#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fs,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use serde_json::{json, Value};

/// A value planted in every mutated artifact so a diagnostic that leaks a
/// document value fails loudly instead of quietly.
const CANARY: &str = "s3cr3t-canary-value";

/// A bounded local JWKS endpoint for exercising the actual CLI process.
///
/// The acceptance bundle is switched to its explicit local-assurance HTTP
/// issuer profile, so this server proves the same fetch path the deployed
/// authenticator uses without depending on a network outside the test.
struct JwksServer {
    origin: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl JwksServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("JWKS server binds");
        listener
            .set_nonblocking(true)
            .expect("JWKS listener becomes nonblocking");
        let address = listener.local_addr().expect("JWKS server has an address");
        let key = registry_platform_crypto::PrivateJwk::parse(VERIFY_PRIVATE_JWK)
            .expect("fixture key parses");
        let body =
            serde_json::to_vec(&json!({"keys": [key.public()]})).expect("JWKS response serializes");
        let response = Arc::new(
            [
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes(),
                body,
            ]
            .concat(),
        );
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut request = Vec::with_capacity(1_024);
                        while request.len() < 8_192
                            && !request.windows(4).any(|window| window == b"\r\n\r\n")
                        {
                            let mut chunk = [0_u8; 512];
                            let Ok(read) = stream.read(&mut chunk) else {
                                break;
                            };
                            if read == 0 {
                                break;
                            }
                            request.extend_from_slice(&chunk[..read]);
                        }
                        let valid_request =
                            request.starts_with(b"GET /.well-known/jwks.json HTTP/1.1\r\n");
                        let rejected = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        let _ = stream.write_all(if valid_request {
                            response.as_ref()
                        } else {
                            rejected
                        });
                        let _ = stream.flush();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            }
        });
        Self {
            origin: format!("http://{address}"),
            stop,
            worker: Some(worker),
        }
    }

    fn origin(&self) -> &str {
        &self.origin
    }
}

impl Drop for JwksServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("JWKS server stops");
        }
    }
}

/// One shipped reference deployment project, staged for the real binary.
///
/// Its fixtures take the reference evaluation path rather than the acceptance
/// path, and they are the fixtures an adopter's own project resembles, so
/// behavior that differs between the two paths is proven on both.
struct ReferenceProject {
    root: tempfile::TempDir,
}

impl ReferenceProject {
    fn stage() -> Self {
        let root = tempfile::tempdir().expect("temporary deployment");
        let project = Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence",
        );
        copy_tree(&project.join("bundle"), &root.path().join("bundle"));
        let bundle_configuration = root.path().join("bundle/evidence.yaml");
        let bundle_document =
            fs::read_to_string(&bundle_configuration).expect("read bundle document");
        fs::write(
            &bundle_configuration,
            bundle_document.replacen(
                "assuranceProfile: evidence-grade",
                "assuranceProfile: local",
                1,
            ),
        )
        .expect("select local assurance for the isolated CLI test");
        let secret_root = root.path().join("secrets");
        fs::create_dir(&secret_root).expect("create private secret root");
        fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
            .expect("set private secret-root mode");

        stage_reference_secrets(&secret_root);

        let runtime =
            fs::read_to_string(project.join("runtime.yaml")).expect("read runtime template");
        let bundle_path = root.path().join("bundle");
        let bundle_directory = bundle_path.to_str().expect("temporary path is UTF-8");
        let audit_path = root.path().join("audit.jsonl");
        let runtime = runtime
            .replacen("/etc/registry-evidence/bundle", bundle_directory, 1)
            .replacen(
                "/run/secrets/registry-evidence",
                secret_root.to_str().expect("temporary path is UTF-8"),
                1,
            )
            .replacen(
                "/var/lib/registry-evidence/audit/evidence.jsonl",
                audit_path.to_str().expect("temporary path is UTF-8"),
                1,
            )
            .replacen(
                "signer:\n  kind: transit\n  unixSocketPath: /run/registry-evidence/transit-proxy.sock\n  mount: transit\n  keyName: evidence-signing\n  keyVersion: 7\n  timeoutMilliseconds: 2000",
                "signer:\n  kind: local-jwk\n  privateKeyRef: secret:file/evidence-signing",
                1,
            );
        fs::write(root.path().join("runtime.yaml"), runtime).expect("stage runtime");
        Self { root }
    }

    /// Rewrite the first occurrence of one passage in a staged project file.
    fn replace(&self, relative: &str, from: &str, to: &str) {
        let path = self.root.path().join(relative);
        let text = fs::read_to_string(&path).expect("read staged project file");
        assert!(text.contains(from), "{relative} does not contain {from:?}");
        fs::write(&path, text.replacen(from, to, 1)).expect("write staged project file");
    }

    /// Run against the project with the immutable modes the runtime demands.
    ///
    /// The modes are restored before the caller asserts anything, so a failed
    /// assertion still leaves a tree the temporary directory can remove.
    fn sealed<T>(&self, run: impl FnOnce(&Path) -> T) -> T {
        let bundle = self.root.path().join("bundle");
        let runtime = self.root.path().join("runtime.yaml");
        set_tree_mode(&bundle, 0o555, 0o444);
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o444))
            .expect("set immutable runtime mode");
        let outcome = run(&runtime);
        set_tree_mode(&bundle, 0o755, 0o644);
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o644))
            .expect("restore runtime mode");
        outcome
    }
}

#[test]
fn actual_binary_checks_and_evaluates_an_immutable_project() {
    let project = ReferenceProject::stage();
    let (check, evaluate) = project.sealed(|runtime| {
        (
            invoke(runtime, &["check"]),
            invoke(
                runtime,
                &["evaluate", "--fixture", "fixtures/adult-status-cases.yaml"],
            ),
        )
    });

    assert_success(
        &check,
        "Evidence deployment ",
        " passed check (3 requirements)\n",
    );
    assert_success(
        &evaluate,
        "Evidence fixture passed (",
        " evaluated cases)\n",
    );
}

#[test]
fn dependency_check_proves_the_real_runtime_boundaries() {
    let key_server = JwksServer::start();
    let deployment = Deployment::stage("all-definitions");
    deployment.stage_acceptance_secrets();
    deployment.point_authentication_to(key_server.origin());

    assert_success(
        &deployment.check_with_runtime_dependencies(),
        "Evidence deployment ",
        " passed check (4 requirements)\n",
    );
}

#[test]
fn dependency_check_fails_closed_when_the_jwks_endpoint_is_unavailable() {
    let unavailable = TcpListener::bind("127.0.0.1:0").expect("ephemeral port binds");
    let origin = format!(
        "http://{}",
        unavailable.local_addr().expect("listener has an address")
    );
    drop(unavailable);

    let deployment = Deployment::stage("all-definitions");
    deployment.stage_acceptance_secrets();
    deployment.point_authentication_to(&origin);
    let output = deployment.check_with_runtime_dependencies();

    assert!(!output.status.success(), "an unavailable JWKS passed check");
    assert!(
        output.stdout.is_empty(),
        "a failed dependency check wrote output"
    );
    assert_eq!(
        std::str::from_utf8(&output.stderr).expect("diagnostic is UTF-8"),
        "evidence: a required runtime dependency is unavailable\n"
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains(&origin));
}

#[tokio::test]
async fn dependency_check_fails_when_an_audit_writer_already_holds_the_sink() {
    use registry_evidence::audit::EvidenceAuditLog;

    let deployment = Deployment::stage("all-definitions");
    deployment.stage_acceptance_secrets();
    let writer = EvidenceAuditLog::initialize(
        deployment.path("audit.jsonl"),
        1_073_741_824,
        b"audit-hash-secret-32-bytes-minimum-value".to_vec(),
        1,
    )
    .await
    .expect("first audit writer initializes");

    let output = deployment.check_with_runtime_dependencies();

    assert!(
        !output.status.success(),
        "a second audit writer passed check"
    );
    assert!(
        output.stdout.is_empty(),
        "a failed dependency check wrote output"
    );
    assert_eq!(
        std::str::from_utf8(&output.stderr).expect("diagnostic is UTF-8"),
        "evidence: runtime audit initialization failed: another writer already holds the audit sink lock\n"
    );
    drop(writer);
}

#[test]
fn check_refuses_an_already_stale_bound_extract_with_only_the_governed_source() {
    let root = tempfile::tempdir().expect("temporary deployment");
    let project = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../products/evidence/reference/request-adapter/deployment-projects/sqlite-extract-evidence",
    );
    let bundle = root.path().join("bundle");
    copy_tree(&project.join("bundle"), &bundle);
    let bundle_configuration = bundle.join("evidence.yaml");
    let bundle_document = fs::read_to_string(&bundle_configuration).expect("read bundle document");
    fs::write(
        &bundle_configuration,
        bundle_document.replacen(
            "assuranceProfile: evidence-grade",
            "assuranceProfile: local",
            1,
        ),
    )
    .expect("select local assurance");

    let secret_root = root.path().join("secrets");
    fs::create_dir(&secret_root).expect("create private secret root");
    fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
        .expect("set private secret-root mode");
    stage_reference_secrets(&secret_root);

    let fixture: serde_json::Value = serde_norway::from_slice(
        &fs::read(bundle.join("fixtures/professional-licence-cases.yaml"))
            .expect("read statement fixture"),
    )
    .expect("parse statement fixture");
    let seed = fixture
        .pointer("/common/extract")
        .and_then(serde_json::Value::as_str)
        .expect("fixture carries extract seed")
        .replacen("2026-08-01T00:00:00Z", "2000-01-01T00:00:00Z", 1);
    let extract_path = root.path().join("licence-register.sqlite");
    rusqlite::Connection::open(&extract_path)
        .expect("create extract")
        .execute_batch(&seed)
        .expect("materialize extract");
    fs::set_permissions(&extract_path, fs::Permissions::from_mode(0o444)).expect("seal extract");

    let runtime = fs::read_to_string(project.join("runtime.yaml")).expect("read runtime template");
    let runtime = runtime
        .replacen(
            "/etc/registry-evidence/bundle",
            bundle.to_str().expect("bundle path is UTF-8"),
            1,
        )
        .replacen(
            "/run/secrets/registry-evidence",
            secret_root.to_str().expect("secret path is UTF-8"),
            1,
        )
        .replacen(
            "/var/lib/registry-evidence/audit/evidence.jsonl",
            root.path()
                .join("audit.jsonl")
                .to_str()
                .expect("audit path is UTF-8"),
            1,
        )
        .replacen(
            "/var/lib/registry-evidence/extracts/licence-register-2026-08-01.sqlite",
            extract_path.to_str().expect("extract path is UTF-8"),
            1,
        )
        .replacen(
            "signer:\n  kind: transit\n  unixSocketPath: /run/registry-evidence/transit-proxy.sock\n  mount: transit\n  keyName: evidence-signing\n  keyVersion: 7\n  timeoutMilliseconds: 2000",
            "signer:\n  kind: local-jwk\n  privateKeyRef: secret:file/evidence-signing",
            1,
        );
    let runtime_path = root.path().join("runtime.yaml");
    fs::write(&runtime_path, runtime).expect("stage runtime");
    set_tree_mode(&bundle, 0o555, 0o444);
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o444)).expect("seal runtime");

    let output = invoke(&runtime_path, &["check"]);

    set_tree_mode(&bundle, 0o755, 0o644);
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o644)).expect("unseal runtime");
    fs::set_permissions(&extract_path, fs::Permissions::from_mode(0o644)).expect("unseal extract");
    assert!(!output.status.success(), "a stale extract passed check");
    assert_eq!(
        std::str::from_utf8(&output.stderr).expect("diagnostic is UTF-8"),
        "evidence: bound extract is stale for source licence-register\n"
    );
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(!diagnostic.contains("2000-01-01"));
    assert!(!diagnostic.contains("2026-08-01-licence-register"));
    assert!(!diagnostic.contains(extract_path.to_string_lossy().as_ref()));
}

/// The reference path has to explain itself as well as the acceptance path does.
///
/// A reference case that records only the form it was written in says a case
/// was read, never how far it got, which is the whole of what the trace is for.
#[test]
fn explaining_a_reference_project_fixture_traces_how_far_each_case_reached() {
    let project = ReferenceProject::stage();
    let output = project.sealed(|runtime| {
        invoke(
            runtime,
            &[
                "evaluate",
                "--fixture",
                "fixtures/adult-status-cases.yaml",
                "--explain",
                "--explain-format",
                "json",
            ],
        )
    });

    assert!(
        output.status.success(),
        "explained evaluation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    let report: Value = serde_json::from_str(stdout).expect("stdout is one JSON document");
    assert_eq!(report["passed"], json!(true));

    let cases = report["cases"].as_array().expect("cases is an array");
    assert!(!cases.is_empty(), "the document carried no case");
    for case in cases {
        let reached = stage_names(case);
        assert!(
            reached.len() > 1,
            "case {} recorded only {reached:?}, so the trace never says how far it got",
            case["id"]
        );
    }

    // The cases that run the pipeline record the pipeline, so a reader is
    // promised no stage the reference path declines to report.
    let resolved = cases
        .iter()
        .find(|case| case["id"] == json!("positive"))
        .expect("the fixture states a resolving case");
    for stage in [
        "prepare", "acquire", "extract", "derive", "validate", "sign",
    ] {
        assert!(
            stage_names(resolved).contains(&stage),
            "a resolving reference case never recorded {stage}: {:?}",
            stage_names(resolved)
        );
    }

    // An unresolved case reports the unresolved outcome on the stage that
    // reached it, exactly as the acceptance path does.
    let unresolved = cases
        .iter()
        .find(|case| case["id"] == json!("no-match"))
        .expect("the fixture states an unresolved case");
    let extract = unresolved["stages"]
        .as_array()
        .expect("stages is an array")
        .iter()
        .find(|stage| stage["stage"] == json!("extract"))
        .expect("an unresolved case records its extraction");
    assert_eq!(extract["status"], json!("no-match"));
}

/// A reference case that fails at its source says so on the acquisition.
///
/// A response the source contract refuses is an acquisition that was reached
/// and failed. Reporting only the preparation before it reads as though the
/// case never got as far as calling its source, which is the opposite of what
/// the reader needs from precisely this failure.
#[test]
fn a_reference_case_whose_response_is_refused_records_a_failed_acquisition() {
    let project = ReferenceProject::stage();
    project.replace(
        "bundle/fixtures/adult-status-cases.yaml",
        "  - id: positive\n    response:\n      total: 1\n",
        "  - id: positive\n    response:\n      errors: [source-refused]\n      total: 1\n",
    );
    let output = project.sealed(|runtime| {
        invoke(
            runtime,
            &[
                "evaluate",
                "--fixture",
                "fixtures/adult-status-cases.yaml",
                "--explain",
                "--explain-format",
                "json",
            ],
        )
    });

    assert!(
        !output.status.success(),
        "the refused response was accepted"
    );
    assert_eq!(
        std::str::from_utf8(&output.stderr).expect("stderr is UTF-8"),
        "evidence: reference fixture source projection failed\n"
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    let report: Value = serde_json::from_str(stdout).expect("stdout is one JSON document");
    let refused = report["cases"]
        .as_array()
        .expect("cases is an array")
        .iter()
        .find(|case| case["id"] == json!("positive"))
        .expect("the refused case is traced");
    let acquire = refused["stages"]
        .as_array()
        .expect("stages is an array")
        .iter()
        .find(|stage| stage["stage"] == json!("acquire"))
        .expect("a case refused at its source records its acquisition");
    assert_eq!(acquire["status"], json!("failed"));
}

/// A chained acquisition is traced stage by stage, not as one acquisition.
///
/// The whole reason this acquisition kind exists is that it makes several calls
/// in a fixed order, each reading only what an earlier one produced. A trace
/// that reported the chain as a single step would drop exactly the fact a
/// reader needs from it: which call the case got to, and which one stopped it.
#[test]
fn explaining_a_chained_acquisition_traces_every_planned_stage() {
    let deployment = Deployment::stage("surviving-spouse-status");
    // The operator half of the acquisition gate. The bundle names the kind it
    // needs; without this the deployment is refused before any case runs.
    deployment.append(
        "runtime.yaml",
        "acquisitionCapabilities: [search-then-fetch-set]\n",
    );
    let output = deployment.evaluate(&["--explain", "--explain-format", "json"]);

    assert!(
        output.status.success(),
        "explained evaluation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    let report: Value = serde_json::from_str(stdout).expect("stdout is one JSON document");
    let cases = report["cases"].as_array().expect("cases is an array");

    // The search and both members, each acquired and each extracted, before the
    // one derivation that sees them together.
    let resolved = cases
        .iter()
        .find(|case| case["id"] == json!("positive"))
        .expect("the fixture states a resolving case");
    assert_eq!(
        stage_names(resolved),
        vec![
            "prepare", "acquire", "extract", "acquire", "extract", "acquire", "extract", "derive",
            "validate", "expect", "sign",
        ],
        "a resolving chained case did not record every planned stage"
    );

    // A member whose response the declared projection refuses stops the chain at
    // its acquisition, so the trace names the call that was refused and never
    // reports the stages after it as reached.
    let refused = cases
        .iter()
        .find(|case| case["id"] == json!("negative-union-register-unresolved"))
        .expect("the fixture states a case whose first member answers nothing");
    assert_eq!(
        stage_outcomes(refused),
        vec![
            ("prepare", "ok"),
            ("acquire", "ok"),
            ("extract", "ok"),
            ("acquire", "failed"),
            ("expect", "ok"),
        ],
        "the chain did not stop on the member whose response was refused"
    );

    // A member that answers, but resolves no unique record for the reference the
    // search produced, stops the chain one stage later: the response is acquired
    // and the extraction is what fails.
    let stopped = cases
        .iter()
        .find(|case| case["id"] == json!("negative-death-register-unresolved"))
        .expect("the fixture states a case whose second member does not resolve");
    assert_eq!(
        stage_outcomes(stopped),
        vec![
            ("prepare", "ok"),
            ("acquire", "ok"),
            ("extract", "ok"),
            ("acquire", "ok"),
            ("extract", "ok"),
            ("acquire", "ok"),
            ("extract", "failed"),
            ("expect", "ok"),
        ],
        "the chain did not stop on the member that resolved nothing"
    );

    // An unresolved search is a settled outcome rather than an inconsistency,
    // and it is reported as one on the stage that reached it.
    let unresolved = cases
        .iter()
        .find(|case| case["id"] == json!("ambiguous"))
        .expect("the fixture states an unresolved search");
    let extract = unresolved["stages"]
        .as_array()
        .expect("stages is an array")
        .iter()
        .find(|stage| stage["stage"] == json!("extract"))
        .expect("an unresolved search records its extraction");
    assert_eq!(extract["status"], json!("ambiguous"));
}

/// The stages one traced case recorded, each with the status it reached.
fn stage_outcomes(case: &Value) -> Vec<(&str, &str)> {
    case["stages"]
        .as_array()
        .expect("stages is an array")
        .iter()
        .map(|stage| {
            (
                stage["stage"].as_str().expect("a stage is named"),
                stage["status"].as_str().expect("a stage has a status"),
            )
        })
        .collect()
}

/// The stages one traced case recorded, in the order it recorded them.
fn stage_names(case: &Value) -> Vec<&str> {
    case["stages"]
        .as_array()
        .expect("stages is an array")
        .iter()
        .map(|stage| stage["stage"].as_str().expect("a stage is named"))
        .collect()
}

/// The exact unexplained success output of the acceptance fixture.
///
/// It is pinned as one literal rather than a prefix and a suffix, because the
/// property under test is that asking for no trace produces this and nothing
/// else. A shape assertion would pass with a trace printed in the middle.
const UNEXPLAINED_SUCCESS: &str = "Evidence fixture passed (13 evaluated cases)\n";

/// The message the mutated acceptance fixture fails with, trace or no trace.
const MUTATED_FIXTURE_FAILURE: &str =
    "evidence: fixture kernel failure did not match its public problem\n";

/// Turn one acceptance case into a case whose stated outcome cannot happen.
///
/// The record is absent, so the lookup can only be unresolved, while the case
/// now claims a unique match. This is the ordinary authoring mistake `--explain`
/// exists for: the fixed message names the contract that broke, and only the
/// trace can say the extraction never found a record to begin with.
fn state_an_impossible_lookup(deployment: &Deployment) {
    deployment.replace(
        "bundle/fixtures/cases.yaml",
        "{id: no-match, source: {total: 0}, expected_lookup: no_match,",
        "{id: no-match, source: {total: 0}, expected_lookup: match,",
    );
}

#[test]
fn an_unexplained_fixture_run_prints_the_summary_line_and_nothing_else() {
    let deployment = Deployment::stage("adult-status");
    let output = deployment.evaluate(&[]);
    assert!(output.status.success(), "fixture evaluation failed");
    assert!(output.stderr.is_empty(), "fixture evaluation wrote stderr");
    assert_eq!(
        std::str::from_utf8(&output.stdout).expect("stdout is UTF-8"),
        UNEXPLAINED_SUCCESS
    );
}

#[test]
fn explaining_a_passing_fixture_keeps_its_exit_code_and_keeps_its_summary_line() {
    let deployment = Deployment::stage("adult-status");
    let output = deployment.evaluate(&["--explain"]);
    assert!(output.status.success(), "explained evaluation failed");
    assert!(
        output.stderr.is_empty(),
        "explained evaluation wrote stderr"
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        stdout.ends_with(UNEXPLAINED_SUCCESS),
        "the summary line changed: {stdout}"
    );
    assert!(stdout.contains("case: positive\n"), "{stdout}");
    assert!(stdout.contains("-> case passed\n"), "{stdout}");
    for stage in [
        "prepare", "acquire", "extract", "derive", "validate", "expect", "sign",
    ] {
        assert!(stdout.contains(stage), "the trace never named {stage}");
    }
}

/// The trace names shapes, never values.
///
/// The acceptance fixture states the selector values its diagnostics may never
/// disclose. They are synthetic, but a trace that reprints them is a trace that
/// would reprint a real one from a bundle authored the same way.
#[test]
fn an_explained_fixture_run_discloses_no_protected_selector_value() {
    let deployment = Deployment::stage("adult-status");
    let passing = deployment.evaluate(&["--explain"]);
    let passing_json = deployment.evaluate(&["--explain", "--explain-format", "json"]);
    state_an_impossible_lookup(&deployment);
    let failing = deployment.evaluate(&["--explain"]);
    let failing_json = deployment.evaluate(&["--explain", "--explain-format", "json"]);
    for output in [&passing, &passing_json, &failing, &failing_json] {
        let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
        for protected in ["Amina", "Diallo", "2000-01-01", "fixture-source-canary"] {
            assert!(
                !stdout.contains(protected),
                "the trace disclosed protected input {protected:?}"
            );
        }
    }
}

#[test]
fn explaining_a_failing_fixture_shows_where_the_case_stopped_and_keeps_its_message() {
    let deployment = Deployment::stage("adult-status");
    state_an_impossible_lookup(&deployment);
    let output = deployment.evaluate(&["--explain"]);

    assert!(!output.status.success(), "the mutated fixture passed");
    assert_eq!(
        std::str::from_utf8(&output.stderr).expect("stderr is UTF-8"),
        MUTATED_FIXTURE_FAILURE
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        !stdout.contains("Evidence fixture passed"),
        "a failed run announced success: {stdout}"
    );
    assert!(stdout.contains("case: no-match\n"), "{stdout}");
    assert!(stdout.contains("extract    no-match"), "{stdout}");
    assert!(
        stdout.contains("response keys available [\"total\"]"),
        "the trace never named the response shape the script saw: {stdout}"
    );
    // The expectation comparison is what rejected this case, so its own stage
    // reports the rejection. A satisfied expectation printed immediately above
    // `case failed` would point a reader away from the stage that failed.
    assert!(
        stdout.contains("expect     failed"),
        "the stage that rejected the case reported success: {stdout}"
    );
    assert!(
        stdout
            .contains("-> case failed: fixture kernel failure did not match its public problem\n"),
        "{stdout}"
    );
    // The cases before the mutated one are reported as reached and passed, so
    // the trace says how far the run got and not only where it stopped.
    assert!(stdout.contains("case: positive\n"), "{stdout}");
}

/// A fixture cannot forge trace lines through its own case identifiers.
///
/// The identifier is interpolated into the rendered text trace, so a control
/// character in one would let a fixture write lines that read as stages the run
/// never reached. It is refused where the identifier is validated rather than
/// escaped where it is rendered: the readable form stays readable, and the
/// forgery has nowhere to start.
#[test]
fn a_case_identifier_carrying_a_control_character_is_refused() {
    let deployment = Deployment::stage("adult-status");
    // Appended rather than substituted: the bundle's category coverage reads
    // the identifiers, so a case renamed outright is refused before evaluation
    // and the identifier check is never reached.
    deployment.replace(
        "bundle/fixtures/cases.yaml",
        "{id: negative-false-is-success,",
        "{id: \"negative-false-is-success\\n  sign       ok         forged\",",
    );
    let output = deployment.evaluate(&["--explain"]);

    assert!(
        !output.status.success(),
        "the forged identifier was accepted"
    );
    assert_eq!(
        std::str::from_utf8(&output.stderr).expect("stderr is UTF-8"),
        "evidence: fixture case identifier is invalid\n"
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        !stdout.contains("forged"),
        "the forged stage line reached the trace: {stdout}"
    );
}

/// A run that fails is checked against its own canaries before it is read.
///
/// The failing run is the one whose trace an operator reads, so it is the one
/// the canaries most need to cover. Checking only a run that settled every case
/// would leave the diagnostic nobody guards being exactly the diagnostic
/// everybody reads.
#[test]
fn a_failing_run_is_refused_when_its_trace_holds_a_declared_canary() {
    let deployment = Deployment::stage("adult-status");
    state_an_impossible_lookup(&deployment);
    // The unresolved lookup names the response members the extraction script
    // saw, and the fixture now declares one of those names protected.
    deployment.replace(
        "bundle/fixtures/cases.yaml",
        "diagnostics_exclude: [Amina, Diallo, '2000-01-01', fixture-source-canary]",
        "diagnostics_exclude: [Amina, Diallo, '2000-01-01', fixture-source-canary, total]",
    );
    let output = deployment.evaluate(&["--explain"]);

    assert!(!output.status.success(), "the leaking run passed");
    assert_eq!(
        std::str::from_utf8(&output.stderr).expect("stderr is UTF-8"),
        "evidence: fixture prohibited diagnostic is present\n"
    );
    // The refusal has to come before the render. A trace reported as prohibited
    // and printed anyway would disclose the value the canary named.
    assert!(
        output.stdout.is_empty(),
        "a prohibited trace was printed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn a_failing_fixture_run_is_unchanged_when_no_trace_is_asked_for() {
    let deployment = Deployment::stage("adult-status");
    state_an_impossible_lookup(&deployment);
    let output = deployment.evaluate(&[]);

    assert!(!output.status.success(), "the mutated fixture passed");
    assert_eq!(
        std::str::from_utf8(&output.stderr).expect("stderr is UTF-8"),
        MUTATED_FIXTURE_FAILURE
    );
    assert!(
        output.stdout.is_empty(),
        "an unexplained failure wrote stdout"
    );
}

/// The trace is an offline fixture diagnostic and reaches nothing else.
///
/// `serve` is the case that matters: a running service must have no way to be
/// asked for a per-case breakdown of an evaluation.
#[test]
fn the_fixture_trace_is_offline_only_and_no_other_subcommand_accepts_it() {
    let deployment = Deployment::stage("adult-status");
    for command in ["serve", "check", "verify-audit"] {
        let output = invoke(&deployment.path("runtime.yaml"), &[command, "--explain"]);
        assert!(
            !output.status.success(),
            "{command} accepted the fixture trace flag"
        );
        let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
        assert!(
            stderr.contains("unexpected argument '--explain'"),
            "{command} did not reject the flag during parsing: {stderr}"
        );
    }
}

/// The JSON form is the whole of standard output, so a reader can pipe it.
///
/// The summary line is what would otherwise trail the document, so its absence
/// is asserted rather than assumed, and the count it carries is asserted in the
/// place it moved to.
#[test]
fn explaining_a_passing_fixture_as_json_prints_one_document_and_no_summary_line() {
    let deployment = Deployment::stage("adult-status");
    let output = deployment.evaluate(&["--explain", "--explain-format", "json"]);
    assert!(output.status.success(), "explained evaluation failed");
    assert!(
        output.stderr.is_empty(),
        "explained evaluation wrote stderr"
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        !stdout.contains("Evidence fixture passed"),
        "the JSON document trails the human summary line: {stdout}"
    );

    let report: Value = serde_json::from_str(stdout).expect("stdout is one JSON document");
    assert_eq!(report["passed"], json!(true));
    assert_eq!(report["evaluatedCases"], json!(13));
    assert_eq!(report["cases"][0]["id"], json!("positive"));
    assert_eq!(report["cases"][0]["stages"][0]["stage"], json!("prepare"));
    assert_eq!(report["cases"][0]["stages"][0]["status"], json!("ok"));
    let cases = report["cases"].as_array().expect("cases is an array");
    assert_eq!(cases.len(), 13, "the document dropped cases");
    assert!(
        cases.iter().all(|case| case.get("failure").is_none()),
        "a passing run reported a failed case"
    );
}

/// The JSON form changes what stdout carries and nothing else.
#[test]
fn explaining_a_failing_fixture_as_json_keeps_its_exit_code_and_keeps_its_message() {
    let deployment = Deployment::stage("adult-status");
    state_an_impossible_lookup(&deployment);
    let output = deployment.evaluate(&["--explain", "--explain-format", "json"]);

    assert!(!output.status.success(), "the mutated fixture passed");
    assert_eq!(
        std::str::from_utf8(&output.stderr).expect("stderr is UTF-8"),
        MUTATED_FIXTURE_FAILURE
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    let report: Value = serde_json::from_str(stdout).expect("stdout is one JSON document");
    assert_eq!(report["passed"], json!(false));
    // `no-match` is the ninth case in the fixture's `cases.yaml`, so the run
    // reaches nine cases before the mutation stops it. A reader counts what the
    // run got through, whether or not it got through all of them.
    assert_eq!(
        report["evaluatedCases"],
        json!(9),
        "a failed run lost its evaluated-case count"
    );

    let cases = report["cases"].as_array().expect("cases is an array");
    assert_eq!(
        report["evaluatedCases"],
        json!(cases.len()),
        "the count and the traced cases disagree"
    );
    let failed = cases
        .iter()
        .find(|case| case.get("failure").is_some())
        .expect("the document names the case that failed");
    assert_eq!(failed["id"], json!("no-match"));
    assert_eq!(
        failed["failure"],
        json!("fixture kernel failure did not match its public problem")
    );
    let extract = failed["stages"]
        .as_array()
        .expect("stages is an array")
        .iter()
        .find(|stage| stage["stage"] == json!("extract"))
        .expect("the document carries the stage the case stopped at");
    assert_eq!(extract["status"], json!("no-match"));
    assert_eq!(
        extract["details"],
        json!(["response keys available [\"total\"]"])
    );
    let expect = failed["stages"]
        .as_array()
        .expect("stages is an array")
        .iter()
        .find(|stage| stage["stage"] == json!("expect"))
        .expect("the document carries the expectation comparison");
    assert_eq!(
        expect["status"],
        json!("failed"),
        "the stage that rejected the case reported success"
    );

    // A case the comparison accepted still reports a satisfied expectation, so
    // the failed status above distinguishes cases rather than marking them all.
    let passed = report["cases"]
        .as_array()
        .expect("cases is an array")
        .iter()
        .find(|case| case["id"] == json!("positive"))
        .expect("the document carries the cases that passed");
    let satisfied = passed["stages"]
        .as_array()
        .expect("stages is an array")
        .iter()
        .find(|stage| stage["stage"] == json!("expect"))
        .expect("a passing case carries its expectation comparison");
    assert_eq!(satisfied["status"], json!("ok"));
}

/// Asking for a format without asking for the trace is a mistake, not a no-op.
#[test]
fn the_json_trace_format_is_rejected_without_the_trace_it_formats() {
    let deployment = Deployment::stage("adult-status");
    let output = deployment.evaluate(&["--explain-format", "json"]);
    assert!(
        !output.status.success(),
        "a format without a trace was accepted"
    );
    assert!(
        output.stdout.is_empty(),
        "a rejected invocation wrote stdout"
    );
    let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
    assert!(
        stderr.contains("--explain"),
        "the rejection never named the flag it needs: {stderr}"
    );
}

#[test]
fn local_relying_procedure_is_bearer_free_closed_and_selector_private() {
    let deployment = Deployment::stage("adult-status");
    deployment.stage_acceptance_secrets();
    deployment.seal();
    let input_path = deployment.path("relying-procedure-input.json");
    let draft = json!({
        "schema": "registry.evidence.local-relying-procedure-input/v1",
        "responseFormat": "signed-jws",
        "requirement": "urn:example:fixture:requirement:adult-status:v1",
        "purpose": "fixture-eligibility",
        "audience": "urn:example:local-client:age-checker",
        "subjects": [{
            "role": "subject",
            "selector": {
                "profile": "person-demographics-v1",
                "values": {
                    "given_name": "Amina",
                    "family_name": "Diallo",
                    "birth_date": "2000-01-01"
                }
            }
        }]
    });
    write_private_json(&input_path, &draft);

    // Non-token stdin is deliberately present. Success proves this seam does
    // not authenticate, parse, or otherwise depend on bearer input.
    let output = invoke_local_relying_procedure(
        &deployment.path("runtime.yaml"),
        &input_path,
        b"this-is-not-a-bearer-token\n",
    );
    assert!(
        output.status.success(),
        "procedure preparation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let procedure: Value =
        serde_json::from_slice(&output.stdout).expect("procedure output is one JSON document");
    assert_eq!(
        procedure["schema"],
        json!("registry.evidence.local-relying-procedure/v1")
    );
    assert_eq!(procedure["responseFormat"], json!("signed-jws"));
    assert_eq!(procedure["expectedAssuranceProfile"], json!("local"));
    assert_eq!(
        procedure["requirement"],
        json!("urn:example:fixture:requirement:adult-status:v1")
    );
    assert_eq!(procedure["purpose"], json!("fixture-eligibility"));
    assert_eq!(
        procedure["audience"],
        json!("urn:example:local-client:age-checker")
    );
    assert!(procedure["configurationRevision"]
        .as_str()
        .is_some_and(|revision| revision.starts_with("sha256:") && revision.len() == 71));
    assert!(procedure["trustedJwks"]["keys"]
        .as_array()
        .is_some_and(|keys| keys.len() == 1));
    assert!(procedure["expectedSubjects"][0]["binding"]
        .as_str()
        .is_some_and(|binding| binding.starts_with("urn:evidence:subject:v1_")));
    assert_eq!(
        procedure["expectedOutputs"],
        json!([{
            "handle": "is_adult",
            "concept": "urn:example:fixture:concept:adult-status",
            "required": true,
            "form": "boolean"
        }])
    );
    assert_eq!(procedure["maximumAssertionLifetimeSeconds"], json!(300));
    assert_eq!(procedure["clockSkewSeconds"], json!(30));
    assert!(procedure.get("requestNonce").is_none());
    let serialized = std::str::from_utf8(&output.stdout).expect("procedure output is UTF-8");
    for protected in [
        "Amina",
        "Diallo",
        "2000-01-01",
        "person-demographics-v1",
        "subject-binding-secret-32-bytes-minimum-value",
        "fixture-agency",
    ] {
        assert!(
            !serialized.contains(protected),
            "procedure output disclosed protected input {protected:?}"
        );
    }
    assert!(
        !deployment.path("audit.jsonl").exists(),
        "procedure preparation never opens audit storage"
    );

    let mut wrong_purpose = draft.clone();
    wrong_purpose["purpose"] = json!("not-configured");
    let mut wrong_profile = draft.clone();
    wrong_profile["subjects"][0]["selector"]["profile"] = json!("not-configured-v1");
    let mut missing_value = draft.clone();
    missing_value["subjects"][0]["selector"]["values"]
        .as_object_mut()
        .expect("selector values are an object")
        .remove("birth_date");
    let mut absent_values = draft.clone();
    absent_values["subjects"][0]["selector"]
        .as_object_mut()
        .expect("selector is an object")
        .remove("values");
    let mut unsupported_format = draft.clone();
    unsupported_format["responseFormat"] = json!("sd-jwt-vc");
    for (label, invalid) in [
        ("purpose", wrong_purpose),
        ("profile", wrong_profile),
        ("missing selector value", missing_value),
        ("absent selector values", absent_values),
        ("response format", unsupported_format),
    ] {
        write_private_json(&input_path, &invalid);
        let refused = invoke_local_relying_procedure(
            &deployment.path("runtime.yaml"),
            &input_path,
            b"ignored-stdin\n",
        );
        assert!(!refused.status.success(), "an invalid {label} was accepted");
        assert!(refused.stdout.is_empty(), "an invalid {label} wrote output");
        assert_eq!(
            std::str::from_utf8(&refused.stderr).expect("diagnostic is UTF-8"),
            "evidence: local relying procedure preparation failed\n"
        );
    }

    write_private_json(&input_path, &draft);
    fs::set_permissions(&input_path, fs::Permissions::from_mode(0o644)).expect("widen draft mode");
    let public_input = invoke_local_relying_procedure(
        &deployment.path("runtime.yaml"),
        &input_path,
        b"ignored-stdin\n",
    );
    assert!(
        !public_input.status.success(),
        "a non-private selector draft was accepted"
    );
    assert_eq!(
        std::str::from_utf8(&public_input.stderr).expect("diagnostic is UTF-8"),
        "evidence: local relying procedure preparation failed\n"
    );

    deployment.unseal();
}

/// Stage the platform secrets the reference project's bundle names, with a
/// signing key matching the bundle's governed active public JWK.
/// Source credentials stay absent: `check` must not resolve them.
fn stage_reference_secrets(secret_root: &Path) {
    let write = |name: &str, value: &str| {
        let path = secret_root.join(name);
        fs::write(&path, value).expect("write reference secret");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set owner-only secret mode");
    };
    write("audit-hmac-key", "audit-hash-secret-32-bytes-minimum-value");
    write(
        "subject-binding-hmac-key",
        "subject-binding-secret-32-bytes-minimum-value",
    );
    write("evidence-signing", VERIFY_PRIVATE_JWK);
}

/// One deployment failure class, with the exact operator text it must produce.
///
/// The expected text is split into a prefix and a suffix so a case that
/// reports a text location can pin the cause and the location shape without
/// pinning a line number that ordinary fixture edits would move. The acceptance
/// bundle is named per case because a failure class can be reachable only from
/// the bundle that declares the configuration it is about.
struct FailureCase {
    label: &'static str,
    bundle: &'static str,
    break_deployment: fn(&Deployment),
    prefix: &'static str,
    suffix: &'static str,
}

#[test]
fn check_names_a_safe_artifact_and_a_value_free_cause_for_every_failure_class() {
    let cases = [
        FailureCase {
            label: "malformed bundle YAML",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.append("bundle/evidence.yaml", &format!("trailing: [{CANARY}\n"));
            },
            prefix: "evidence: deployment configuration is invalid: artifact evidence.yaml: document is not well-formed YAML (line ",
            suffix: ")\n",
        },
        FailureCase {
            label: "unknown bundle field",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.replace(
                    "bundle/evidence.yaml",
                    "  principalClaim: sub\n",
                    &format!("  principalClaim: sub\n  unknownField: {CANARY}\n"),
                );
            },
            prefix: "evidence: deployment configuration is invalid: artifact evidence.yaml: unknown field at authentication (line ",
            suffix: ")\n",
        },
        FailureCase {
            label: "wrong bundle field type",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.replace(
                    "bundle/evidence.yaml",
                    "version: 1\n",
                    &format!("version: \"{CANARY}\"\n"),
                );
            },
            prefix: "evidence: deployment configuration is invalid: artifact evidence.yaml: field has the wrong type at version (line ",
            suffix: ")\n",
        },
        FailureCase {
            label: "unaccepted bundle field variant",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.replace(
                    "bundle/evidence.yaml",
                    "  kind: oidc-access-token\n",
                    &format!("  kind: {CANARY}\n"),
                );
            },
            prefix: "evidence: deployment configuration is invalid: artifact evidence.yaml: field value is not one of the accepted variants at authentication.kind (line ",
            suffix: ")\n",
        },
        FailureCase {
            label: "configuration cross-reference",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.replace(
                    "bundle/evidence.yaml",
                    "      source: source-a\n",
                    &format!("      source: {CANARY}\n"),
                );
            },
            prefix: "evidence: deployment configuration is invalid: artifact evidence.yaml: requirement acquisition references an unknown source\n",
            suffix: "",
        },
        FailureCase {
            label: "artifact closure references a missing file",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.remove("bundle/derivations/adult-status.rhai");
            },
            prefix: "evidence: deployment artifact closure is invalid: artifact derivations/adult-status.rhai: the configuration references an artifact the bundle does not contain\n",
            suffix: "",
        },
        FailureCase {
            label: "artifact closure carries an unreferenced file",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.write("bundle/schemas/orphan.schema.yaml", &format!("x: {CANARY}\n"));
            },
            prefix: "evidence: deployment artifact closure is invalid: artifact schemas/orphan.schema.yaml: the bundle contains an artifact the configuration does not reference\n",
            suffix: "",
        },
        FailureCase {
            label: "unsafe artifact name is never echoed",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.write(
                    &format!("bundle/fixtures/orphan {CANARY}.yaml"),
                    "synthetic_only: true\n",
                );
            },
            prefix: "evidence: deployment artifact closure is invalid: the bundle contains an artifact the configuration does not reference\n",
            suffix: "",
        },
        FailureCase {
            label: "script",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.append(
                    "bundle/derivations/adult-status.rhai",
                    &format!("\nthis is not rhai {CANARY}(((\n"),
                );
            },
            prefix: "evidence: deployment script is invalid: artifact derivations/adult-status.rhai: script does not compile\n",
            suffix: "",
        },
        // The bundle loader compiles a script on a permissive engine that only
        // proves an entrypoint. The kernel is the pass that applies the
        // hardened grammar, so a script using a construct the runtime disables
        // is refused there and has to name its artifact there too.
        FailureCase {
            label: "script the hardened kernel grammar refuses",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.append(
                    "bundle/derivations/adult-status.rhai",
                    &format!("\nfn unreviewed() {{\n    let value = \"{CANARY}\";\n    while false {{ }}\n    value\n}}\n"),
                );
            },
            prefix: "evidence: bundle compilation failed: artifact derivations/adult-status.rhai: script does not compile\n",
            suffix: "",
        },
        FailureCase {
            label: "fact schema",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.write(
                    "bundle/schemas/adult-status-facts.schema.yaml",
                    &format!("type: [{CANARY}]\n"),
                );
            },
            prefix: "evidence: deployment artifact is invalid: artifact schemas/adult-status-facts.schema.yaml: fact schema must close the root object\n",
            suffix: "",
        },
        FailureCase {
            label: "codelist",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.write(
                    "bundle/codelists/residence-region-map.yaml",
                    &format!("id: broken\nversion: \"1\"\nentries: {CANARY}\n"),
                );
            },
            prefix: "evidence: deployment artifact is invalid: artifact codelists/residence-region-map.yaml: codelist YAML is invalid\n",
            suffix: "",
        },
        FailureCase {
            label: "fixture",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.write(
                    "bundle/fixtures/adult-status-cases.yaml",
                    &format!("synthetic_only: true\ncases: {CANARY}\n"),
                );
            },
            prefix: "evidence: deployment artifact is invalid: artifact fixtures/adult-status-cases.yaml: fixture cases are missing\n",
            suffix: "",
        },
        FailureCase {
            label: "unknown runtime field",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.append("runtime.yaml", &format!("unknownField: {CANARY}\n"));
            },
            prefix: "evidence: deployment configuration is invalid: artifact runtime.yaml: unknown field (line ",
            suffix: ")\n",
        },
        FailureCase {
            label: "wrong runtime field type",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.replace(
                    "runtime.yaml",
                    "  port: 8080\n",
                    &format!("  port: \"{CANARY}\"\n"),
                );
            },
            prefix: "evidence: deployment configuration is invalid: artifact runtime.yaml: field has the wrong type at listener.port (line ",
            suffix: ")\n",
        },
        FailureCase {
            label: "runtime operator path",
            bundle: "all-definitions",
            break_deployment: |deployment| {
                deployment.replace_line(
                    "runtime.yaml",
                    "bundleDirectory: ",
                    &format!("bundleDirectory: relative/{CANARY}\n"),
                );
            },
            prefix: "evidence: deployment configuration is invalid: artifact runtime.yaml: absolute operator path is invalid\n",
            suffix: "",
        },
        // Nothing is broken here: an operator runtime file that says nothing
        // about acquisition capabilities enables nothing beyond the frozen
        // Version 1 acquisition forms, so a bundle that requires a gated kind
        // is refused before the deployment serves anything.
        FailureCase {
            label: "gated acquisition kind the operator did not enable",
            bundle: "surviving-spouse-status",
            break_deployment: |_| {},
            prefix: "evidence: deployment artifact is invalid: the runtime configuration does not enable an acquisition capability the bundle requires\n",
            suffix: "",
        },
    ];

    for case in cases {
        let deployment = Deployment::stage(case.bundle);
        (case.break_deployment)(&deployment);
        let output = deployment.check();

        assert!(
            !output.status.success(),
            "{}: check accepted a broken deployment",
            case.label
        );
        let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
        let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
        assert!(stdout.is_empty(), "{}: check wrote output", case.label);
        assert!(
            stderr.starts_with(case.prefix) && stderr.ends_with(case.suffix),
            "{}: unexpected diagnostic {stderr:?}",
            case.label
        );
        assert!(
            !stdout.contains(CANARY) && !stderr.contains(CANARY),
            "{}: diagnostic disclosed a document value",
            case.label
        );
    }
}

/// The operator half of the acquisition gate, from the other side.
///
/// The bundle author declares which acquisition kinds the bundle needs; the
/// operator who deploys it decides, in a file the bundle author does not write,
/// which of them this deployment may serve. The same bundle the failure classes
/// above refuse passes check once the runtime file names the capability, which
/// is what makes the refusal a deployment decision rather than a spelling
/// accident.
#[test]
fn check_accepts_a_gated_acquisition_kind_the_operator_enabled() {
    let deployment = Deployment::stage("surviving-spouse-status");
    deployment.append(
        "runtime.yaml",
        "acquisitionCapabilities: [search-then-fetch-set]\n",
    );
    deployment.write_secret("audit-hash-key", "audit-hash-secret-32-bytes-minimum-value");
    deployment.write_secret(
        "subject-binding-key",
        "subject-binding-secret-32-bytes-minimum-value",
    );
    deployment.write_secret("signing-key", VERIFY_PRIVATE_JWK);
    deployment.write_secret("civil-record-search-token", "synthetic-source-token");
    deployment.write_secret("union-register-token", "synthetic-source-token");
    deployment.write_secret("death-register-token", "synthetic-source-token");

    assert_success(
        &deployment.check(),
        "Evidence deployment ",
        " passed check (1 requirements)\n",
    );
}

/// Secret material the server would refuse at startup must already fail
/// `check`, with the same fixed operator message startup produces. Each case
/// stages the complete acceptance secret set and then breaks exactly one
/// piece of it.
#[test]
fn check_rejects_secret_material_the_server_would_refuse_at_startup() {
    struct SecretFailureCase {
        label: &'static str,
        break_secrets: fn(&Deployment),
        expected: &'static str,
    }
    let cases = [
        SecretFailureCase {
            label: "signing key differs from the governed active public JWK",
            break_secrets: |deployment| deployment.write_mismatched_signing_key(),
            expected: "evidence: runtime signing initialization failed\n",
        },
        SecretFailureCase {
            label: "audit hash key below the minimum length",
            break_secrets: |deployment| deployment.write_secret("audit-hash-key", "short"),
            expected: "evidence: runtime audit initialization failed: the audit hash secret is \
                       unusable\n",
        },
        SecretFailureCase {
            label: "subject binding key missing",
            break_secrets: |deployment| deployment.remove("secrets/subject-binding-key"),
            expected: "evidence: runtime secret initialization failed\n",
        },
    ];

    for case in cases {
        let deployment = Deployment::stage("all-definitions");
        deployment.stage_acceptance_secrets();
        (case.break_secrets)(&deployment);
        let output = deployment.check();

        assert!(
            !output.status.success(),
            "{}: check accepted secret material the server would refuse",
            case.label
        );
        assert!(
            output.stdout.is_empty(),
            "{}: check wrote output for a refused deployment",
            case.label
        );
        let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
        assert_eq!(
            stderr, case.expected,
            "{}: unexpected diagnostic",
            case.label
        );
    }
}

/// One audit initialization failure class, with the exact operator text it
/// must produce and any handle the fault needs held open while `serve` runs.
struct AuditFaultCase {
    label: &'static str,
    break_audit: fn(&Deployment) -> Option<fs::File>,
    expected: &'static str,
}

/// The audit boundary refuses to start for unrelated reasons, and from outside
/// the process they are indistinguishable: a mode an operator fixes with
/// `chmod`, a chain that no longer verifies, and a second writer already
/// holding the sink lock are three different questions with three different
/// answers. Each names itself, and none of them names the audit path, which
/// the operator already has in the runtime file.
#[test]
fn serve_names_why_the_audit_boundary_refused_to_initialize() {
    let cases = [
        AuditFaultCase {
            label: "an audit file readable beyond its owner",
            break_audit: |deployment| {
                deployment.stage_audit_chain("");
                set_mode(&deployment.path("audit.jsonl"), 0o644);
                None
            },
            expected: "evidence: runtime audit initialization failed: the audit file or lock is \
                       not owner-only, or its directory is unavailable or not owner-controlled\n",
        },
        AuditFaultCase {
            label: "an audit chain that does not verify",
            break_audit: |deployment| {
                deployment.stage_audit_chain("{\"not\":\"an audit record\"}\n");
                None
            },
            expected: "evidence: runtime audit initialization failed: the existing audit chain \
                       did not verify\n",
        },
        AuditFaultCase {
            label: "a second writer holding the audit sink lock",
            break_audit: |deployment| {
                let path = deployment.path("audit.jsonl.lock");
                fs::write(&path, "").expect("stage audit sink lock");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    .expect("set owner-only audit lock mode");
                let held = fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .expect("open audit sink lock");
                held.try_lock().expect("hold the audit sink lock");
                Some(held)
            },
            expected: "evidence: runtime audit initialization failed: another writer already \
                       holds the audit sink lock\n",
        },
    ];

    for case in cases {
        let deployment = Deployment::stage_on_port("all-definitions", free_port());
        deployment.stage_acceptance_secrets();
        deployment.seal();
        let _held = (case.break_audit)(&deployment);
        let output = invoke(&deployment.path("runtime.yaml"), &["serve"]);
        deployment.unseal();

        assert!(
            !output.status.success(),
            "{}: serve started on a refused audit boundary",
            case.label
        );
        let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
        assert_eq!(
            stderr, case.expected,
            "{}: unexpected diagnostic",
            case.label
        );
    }
}

/// The documented audit rotation procedure, executed against the real binary.
///
/// The procedure is: stop the service with SIGTERM, archive the audit file by
/// rename, start the service again on the same path, and confirm readiness on
/// the new chain. This proves the stop and start-new-chain steps of the
/// operator procedure and the SIGTERM handling that makes the stop step
/// possible at all.
#[test]
fn serve_stops_on_sigterm_and_restarts_on_an_archived_audit_chain() {
    let port = free_port();
    let deployment = Deployment::stage_on_port("all-definitions", port);
    deployment.stage_acceptance_secrets();
    deployment.seal();

    let mut service = deployment.serve();
    wait_until_ready(port);
    let first = deployment.path("audit.jsonl");
    assert!(first.is_file(), "the service did not open an audit chain");
    stop(&mut service);

    // Archive by rename: the audit file must stay a singly linked owner-only
    // regular file, so a copy-and-truncate rotation is not the procedure.
    let archive = deployment.path("audit-archived.jsonl");
    fs::rename(&first, &archive).expect("archive the audit chain");
    assert!(!first.exists(), "the archived chain was left in place");

    let mut restarted = deployment.serve();
    wait_until_ready(port);
    assert!(first.is_file(), "the restart did not start a new chain");
    stop(&mut restarted);

    assert!(archive.is_file(), "the archived chain was disturbed");

    // Rollback is the same stop, rename, start sequence in reverse: the new
    // chain is set aside and the archived chain resumes at the original path.
    let superseded = deployment.path("audit-superseded.jsonl");
    fs::rename(&first, &superseded).expect("set the new chain aside");
    fs::rename(&archive, &first).expect("restore the archived chain");
    let mut rolled_back = deployment.serve();
    wait_until_ready(port);
    stop(&mut rolled_back);
    assert!(
        superseded.is_file(),
        "the superseded chain was disturbed during rollback"
    );
    deployment.unseal();
}

/// The staged verification key identifier, echoed by the protected header.
const VERIFY_KEY_ID: &str = "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo";

/// A staged P-256 test key. It signs fixture assertions in this test binary
/// only and is not a deployment key.
const VERIFY_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;

/// A different valid P-256 key used to prove exact public-key matching.
const MISMATCHED_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","alg":"ES256","kid":"xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"}"#;

/// A staged request nonce, of the exact 43-character request-nonce shape.
const FIXTURE_NONCE: &str = "r1N1mq48U3PpZ5keuZEgmA5KMC2KDrF1hT6640koy6I";

/// A different nonce of the same shape, carrying the canary so a policy
/// diagnostic that echoed the expected value would fail loudly.
const CANARY_NONCE: &str = "s3cr3t-canary-value000000000000000000000000";

#[test]
fn verify_accepts_an_authentic_and_current_stored_response() {
    let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &fixture_policy());
    let output = stored.verify(Some("2026-08-02T12:00:00Z"));

    assert_eq!(
        output.status.code(),
        Some(0),
        "verify rejected a good response"
    );
    assert!(output.stderr.is_empty(), "verify wrote diagnostics");
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        stdout.starts_with(
            "verified-at: 2026-08-02T12:00:00Z\nauthentic: yes\ncurrently-valid: yes\n"
        ),
        "unexpected verification output {stdout:?}"
    );
    assert!(
        stdout.contains(&format!("\"requestNonce\": \"{FIXTURE_NONCE}\"")),
        "verify did not print the verified Evidence for inspection"
    );
}

#[test]
fn verify_separates_authenticity_from_current_validity() {
    let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &fixture_policy());
    let output = stored.verify(Some("2026-08-05T00:00:00Z"));

    assert_eq!(
        output.status.code(),
        Some(3),
        "an expired response did not report its own exit status"
    );
    assert!(output.stderr.is_empty(), "verify wrote diagnostics");
    assert_eq!(
        std::str::from_utf8(&output.stdout).expect("stdout is UTF-8"),
        "verified-at: 2026-08-05T00:00:00Z\nauthentic: yes\ncurrently-valid: no\n",
        "an expired response must stay authentic without being current"
    );
}

#[test]
fn verify_rejects_a_tampered_payload_without_naming_a_value() {
    let mut tampered = fixture_evidence();
    tampered["supportedValues"][0]["value"] = serde_json::Value::String(CANARY.to_owned());
    let stored = StoredResponse::stage(&fixture_evidence(), &tampered, &fixture_policy());
    let output = stored.verify(Some("2026-08-02T12:00:00Z"));

    assert_verification_failure(
        &output,
        "2026-08-02T12:00:00Z",
        "authentic: no\n",
        "evidence: stored response verification failed (signature)\n",
    );
}

#[test]
fn verify_reports_only_the_generic_policy_class_for_a_wrong_expected_nonce() {
    let policy = fixture_policy().replacen(FIXTURE_NONCE, CANARY_NONCE, 1);
    let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &policy);
    let output = stored.verify(Some("2026-08-02T12:00:00Z"));

    assert_verification_failure(
        &output,
        "2026-08-02T12:00:00Z",
        "authentic: no\n",
        "evidence: stored response verification failed (policy)\n",
    );
}

#[test]
fn verify_rejects_a_policy_document_with_an_unknown_field() {
    let policy = format!("{}unknownField: {CANARY}\n", fixture_policy());
    let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &policy);
    let output = stored.verify(Some("2026-08-02T12:00:00Z"));

    assert_verification_failure(
        &output,
        "2026-08-02T12:00:00Z",
        "",
        "evidence: stored response verification failed (malformed)\n",
    );
}

/// A policy stating a time bound the verification policy contract forbids is an
/// unusable input document, not a verification outcome: honouring it would make
/// the verifier accept assertions a conformant relying party must refuse, and
/// the failure-class vocabulary is frozen, so there is no class to report it
/// under. The command therefore refuses it before verifying anything, exactly as
/// it refuses a policy with an unknown field.
#[test]
fn verify_rejects_a_policy_document_outside_the_contract_time_bounds() {
    for (label, replaced, with) in [
        (
            "a lifetime past the contract ceiling",
            "maximumAssertionLifetimeSeconds: 172800",
            "maximumAssertionLifetimeSeconds: 31536001",
        ),
        (
            "a zero lifetime",
            "maximumAssertionLifetimeSeconds: 172800",
            "maximumAssertionLifetimeSeconds: 0",
        ),
        (
            "a skew past the contract ceiling",
            "clockSkewSeconds: 30",
            "clockSkewSeconds: 301",
        ),
    ] {
        let policy = fixture_policy().replacen(replaced, with, 1);
        assert!(policy.contains(with), "{label} did not reach the policy");
        let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &policy);
        let output = stored.verify(Some("2026-08-02T12:00:00Z"));

        assert_verification_failure(
            &output,
            "2026-08-02T12:00:00Z",
            "",
            "evidence: stored response verification failed (malformed)\n",
        );
    }
}

#[test]
fn verify_rejects_a_policy_document_outside_the_contract_list_bounds() {
    for (label, minimum_items, maximum_items) in [
        ("a zero minimum", 0, 1),
        ("a minimum past the ceiling", 65, 64),
        ("a zero maximum", 1, 0),
        ("a maximum past the ceiling", 1, 65),
    ] {
        let policy = fixture_policy().replacen(
            "form: boolean",
            &format!(
                "form:\n      list:\n        minimumItems: {minimum_items}\n        maximumItems: {maximum_items}"
            ),
            1,
        );
        let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &policy);
        let output = stored.verify(Some("2026-08-02T12:00:00Z"));

        assert_verification_failure(
            &output,
            "2026-08-02T12:00:00Z",
            "",
            "evidence: stored response verification failed (malformed)\n",
        );
        assert_eq!(output.status.code(), Some(1), "{label} was accepted");
    }
}

#[test]
fn verify_rejects_a_verification_instant_that_is_not_strict_utc() {
    let stored = StoredResponse::stage(&fixture_evidence(), &fixture_evidence(), &fixture_policy());

    for at in ["2026-08-02T12:00:00+02:00", "2026-08-02", CANARY] {
        let output = stored.verify(Some(at));
        assert_eq!(output.status.code(), Some(1), "verify accepted {at:?}");
        assert!(
            output.stdout.is_empty(),
            "verify printed an unusable instant"
        );
        let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
        assert_eq!(
            stderr, "evidence: verification instant is not strict RFC 3339 UTC\n",
            "unexpected verification diagnostic"
        );
    }
}

#[test]
fn verify_accepts_an_authentic_and_current_stored_sd_jwt_vc() {
    let stored = StoredCredential::stage(&fixture_policy(), |credential| credential);
    let output = stored.verify(Some("2026-08-02T12:00:00Z"));

    assert_eq!(
        output.status.code(),
        Some(0),
        "verify rejected a good credential"
    );
    assert!(output.stderr.is_empty(), "verify wrote diagnostics");
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        stdout.contains("authentic: yes\n") && stdout.contains("currently-valid: yes\n"),
        "verify did not report the credential as authentic and current"
    );
    assert!(
        stdout.contains("urn:example:concept"),
        "verify did not print the rebuilt Evidence for inspection"
    );
}

#[test]
fn verify_rejects_a_stored_sd_jwt_vc_whose_disclosure_was_replaced() {
    // Substitute a well-formed disclosure of the same claim with the opposite
    // value. Its digest is absent from the signed `_sd`, so the credential
    // fails without the signature itself being touched.
    let stored = StoredCredential::stage(&fixture_policy(), |credential| {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let body = credential
            .strip_suffix('~')
            .expect("the credential ends with the key-binding terminator");
        let (jwt, disclosure) = body.split_once('~').expect("the credential discloses");
        let decoded: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(disclosure)
                .expect("disclosure decodes"),
        )
        .expect("disclosure parses");
        let replaced = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!([decoded[0], decoded[1], true]))
                .expect("disclosure serializes"),
        );
        format!("{jwt}~{replaced}~")
    });
    let output = stored.verify(Some("2026-08-02T12:00:00Z"));

    assert_verification_failure(
        &output,
        "2026-08-02T12:00:00Z",
        "authentic: no\n",
        "evidence: stored response verification failed (disclosure)\n",
    );
}

#[test]
fn verify_requires_exactly_one_stored_response_format() {
    let stored = StoredCredential::stage(&fixture_policy(), |credential| credential);
    for arguments in [
        vec![],
        vec![
            "--jws".to_owned(),
            stored.path("response.sd-jwt").display().to_string(),
            "--sd-jwt-vc".to_owned(),
            stored.path("response.sd-jwt").display().to_string(),
        ],
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_evidence"));
        command
            .arg("verify")
            .args(&arguments)
            .arg("--jwks")
            .arg(stored.path("trusted.jwks.json"))
            .arg("--policy")
            .arg(stored.path("policy.yaml"))
            .env_remove("REGISTRY_EVIDENCE_RUNTIME");
        let output = command.output().expect("evidence binary starts");
        assert_eq!(
            output.status.code(),
            Some(2),
            "verify accepted an ambiguous stored-response selection"
        );
        assert!(
            output.stdout.is_empty(),
            "verify began before selecting a stored response"
        );
    }
}

/// The audience the fixture relying party put in the challenge it issued.
const KEY_BINDING_AUDIENCE: &str = "urn:example:relying-party";

/// The challenge the fixture relying party issued and retained. Comparing it is
/// not consuming it, so every run below may present it again.
const KEY_BINDING_NONCE: &str = "QH-fpo3GJG9ksxAJeee7wQqpaRCkly8q-ltiG5QQmSk";

/// The holder's own key: the second staged test pair, reused here because no
/// deployment ever holds a holder private key and this is a test pair only.
const HOLDER_PRIVATE_JWK: &str = MISMATCHED_PRIVATE_JWK;

/// The public half of [`HOLDER_PRIVATE_JWK`], as a credential's confirmation
/// key. No key identifier is confirmed, so the proof header nominates none.
const HOLDER_PUBLIC_JWK: &str = r#"{"kty":"EC","crv":"P-256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","alg":"ES256"}"#;

/// The instant every holder-bound run below verifies at. The fixture assertion
/// is current at it, and a proof stamped with it is inside the accepted window.
const PRESENTATION_INSTANT: &str = "2026-08-02T12:00:00Z";

#[test]
fn verify_presentation_accepts_an_authentic_and_current_presentation() {
    let stored = StoredPresentation::stage(
        &holder_bound_fixture_policy(),
        valid_key_binding_claims,
        HOLDER_PRIVATE_JWK,
    );
    let output = stored.verify_presentation(Some(PRESENTATION_INSTANT));

    assert_eq!(
        output.status.code(),
        Some(0),
        "verify-presentation rejected a good presentation"
    );
    assert!(
        output.stderr.is_empty(),
        "verify-presentation wrote diagnostics"
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        stdout.starts_with("verified-at: 2026-08-02T12:00:00Z\nauthentic: yes\npossession: "),
        "unexpected verification output {stdout:?}"
    );
    assert!(
        stdout.contains("currently-valid: yes\n"),
        "verify-presentation did not report the presentation as current"
    );
    assert!(
        stdout.contains("\"subjectBinding\": \"holder-bound\""),
        "verify-presentation did not print the rebuilt Evidence for inspection"
    );
    // The command answers what possession was proven and refuses to imply
    // more: the challenge was compared, and comparing it retired nothing.
    assert!(
        stdout.contains(
            "possession: proven when the key-binding JWT was signed; \
             not proof that the presentation is fresh, single-use, or unreplayed\n"
        ),
        "verify-presentation overstated what a verified proof establishes"
    );
}

/// The documented behavior, asserted deliberately rather than left implied: the
/// expected challenge is compared and never consumed, so the same stored bytes
/// verify again under the same policy. Nothing here is a replay defence, and a
/// relying party that needs one owns it in its own challenge lifecycle.
#[test]
fn verify_presentation_accepts_the_same_stored_bytes_every_time() {
    let stored = StoredPresentation::stage(
        &holder_bound_fixture_policy(),
        valid_key_binding_claims,
        HOLDER_PRIVATE_JWK,
    );

    for attempt in 1..=2 {
        let output = stored.verify_presentation(Some(PRESENTATION_INSTANT));
        assert_eq!(
            output.status.code(),
            Some(0),
            "attempt {attempt} over unchanged bytes was refused"
        );
        assert!(
            output.stderr.is_empty(),
            "attempt {attempt} wrote diagnostics"
        );
        let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
        assert!(
            stdout.contains("authentic: yes\n") && stdout.contains("currently-valid: yes\n"),
            "attempt {attempt} did not report the same answer"
        );
    }
}

#[test]
fn verify_presentation_reports_only_the_key_binding_class_for_a_failed_proof() {
    let policy = holder_bound_fixture_policy();
    let cases = [
        (
            "a challenge answered to another relying party",
            StoredPresentation::stage(
                &policy,
                |issued| {
                    let mut claims = valid_key_binding_claims(issued);
                    claims["aud"] = json!("urn:example:other-relying-party");
                    claims
                },
                HOLDER_PRIVATE_JWK,
            ),
        ),
        (
            "a proof bound to bytes other than the presented ones",
            StoredPresentation::stage(
                &policy,
                |issued| {
                    let mut claims = valid_key_binding_claims(issued);
                    claims["sd_hash"] = json!(disclosure_hash(&format!("{issued}~")));
                    claims
                },
                HOLDER_PRIVATE_JWK,
            ),
        ),
        (
            "a signer other than the confirmed holder key",
            // The service signing key: authentic for the credential, and not
            // the key the issuer confirmed for the holder.
            StoredPresentation::stage(&policy, valid_key_binding_claims, VERIFY_PRIVATE_JWK),
        ),
    ];

    for (label, stored) in &cases {
        let output = stored.verify_presentation(Some(PRESENTATION_INSTANT));
        assert_verification_failure(
            &output,
            PRESENTATION_INSTANT,
            "authentic: no\n",
            "evidence: stored response verification failed (key-binding)\n",
        );
        assert_eq!(output.status.code(), Some(1), "{label} was accepted");
    }
}

/// Neither command reads the other's serialization. A presentation carries no
/// trailing tilde, so `verify` refuses it, and it is refused for its shape
/// rather than its policy: the Version 1 policy staged for this run is one that
/// command does accept.
#[test]
fn verify_refuses_a_holder_bound_presentation() {
    let stored = StoredPresentation::stage(
        &holder_bound_fixture_policy(),
        valid_key_binding_claims,
        HOLDER_PRIVATE_JWK,
    );
    let output = stored.verify_as_stored_response(Some(PRESENTATION_INSTANT));

    assert_verification_failure(
        &output,
        PRESENTATION_INSTANT,
        "authentic: no\n",
        "evidence: stored response verification failed (malformed)\n",
    );
}

/// The other direction: an audience-scoped credential ends in the trailing
/// tilde that marks an absent proof, so it is refused for offering no
/// possession rather than verified without one.
#[test]
fn verify_presentation_refuses_an_audience_scoped_credential() {
    let stored = StoredCredential::stage(&holder_bound_fixture_policy(), |credential| credential);
    let output = stored.verify_presentation(Some(PRESENTATION_INSTANT));

    assert_verification_failure(
        &output,
        PRESENTATION_INSTANT,
        "authentic: no\n",
        "evidence: stored response verification failed (key-binding)\n",
    );
}

/// Assert one closed verification failure: exit 1, the chosen instant, the
/// expected remaining stdout, only the closed class on stderr, and no leaked
/// document value on either stream.
fn assert_verification_failure(
    output: &Output,
    instant: &str,
    remaining_stdout: &str,
    stderr: &str,
) {
    assert_eq!(output.status.code(), Some(1), "verify accepted a bad input");
    let printed_out = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    let printed_err = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
    assert_eq!(
        printed_out,
        format!("verified-at: {instant}\n{remaining_stdout}"),
        "unexpected verification output"
    );
    assert_eq!(printed_err, stderr, "unexpected verification diagnostic");
    assert!(
        !printed_out.contains(CANARY) && !printed_err.contains(CANARY),
        "verification disclosed a document value"
    );
}

/// The stored Evidence payload the verify tests sign and re-verify.
fn fixture_evidence() -> serde_json::Value {
    serde_json::json!({
        "schema": "registry.assertion-evidence/v1",
        "assuranceProfile": "evidence-grade",
        "subjectBinding": "audience-scoped",
        "requestNonce": FIXTURE_NONCE,
        "id": "urn:ulid:01K1EXAMPLE0000000000000000",
        "type": "Evidence",
        "supportsRequirement": "urn:example:requirement:v1",
        "isConformantTo": "urn:example:type:v1",
        "issuedBy": "urn:example:issuer",
        "providedBy": "urn:example:provider",
        "issuedAt": "2026-08-02T00:00:00Z",
        "observedAt": "2026-08-02T00:00:00Z",
        "validUntil": "2026-08-03T00:00:00Z",
        "purpose": "casework",
        "audience": "urn:example:audience",
        "configurationRevision": format!("sha256:{}", "0".repeat(64)),
        "subjects": [{"role": "subject", "binding": format!("urn:evidence:subject:v1_{}", "A".repeat(43))}],
        "supportedValues": [{"providesValueFor": "urn:example:concept", "value": false}],
    })
}

/// The relying-procedure policy matching that payload.
///
/// A real relying party builds this from independently retained trusted state.
/// The test simulates that state from the fixture it controls.
fn fixture_policy() -> String {
    format!(
        "expectedAssuranceProfile: evidence-grade
issuedBy: urn:example:issuer
providedBy: urn:example:provider
requirement: urn:example:requirement:v1
evidenceType: urn:example:type:v1
purpose: casework
audience: urn:example:audience
configurationRevision: sha256:{revision}
requestNonce: {FIXTURE_NONCE}
expectedSubjects:
  - role: subject
    binding: urn:evidence:subject:v1_{binding}
expectedOutputs:
  - concept: urn:example:concept
    form: boolean
maximumAssertionLifetimeSeconds: 172800
clockSkewSeconds: 30
revokedKeyIds: []
",
        revision = "0".repeat(64),
        binding = "A".repeat(43),
    )
}

/// The same fixture assertion under the holder-bound mode: no audience and no
/// request nonce, because it names no relying party and correlates to no single
/// request.
fn holder_bound_fixture_evidence() -> serde_json::Value {
    let mut evidence = fixture_evidence();
    evidence["subjectBinding"] = json!("holder-bound");
    let members = evidence.as_object_mut().expect("the fixture is an object");
    members.remove("audience");
    members.remove("requestNonce");
    evidence
}

/// The holder-bound relying-procedure policy matching that payload.
///
/// A real relying party builds this from independently retained trusted state,
/// including the challenge it issued itself. The test simulates that state from
/// the fixture it controls.
fn holder_bound_fixture_policy() -> String {
    format!(
        "subjectBinding: holder-bound
expectedAssuranceProfile: evidence-grade
issuedBy: urn:example:issuer
providedBy: urn:example:provider
requirement: urn:example:requirement:v1
evidenceType: urn:example:type:v1
expectedIssuancePurpose: casework
configurationRevision: sha256:{revision}
expectedSubjects:
  - role: subject
    binding: urn:evidence:subject:v1_{binding}
expectedOutputs:
  - concept: urn:example:concept
    form: boolean
maximumAssertionLifetimeSeconds: 172800
revokedKeyIds: []
keyBindingAudience: {KEY_BINDING_AUDIENCE}
keyBindingNonce: {KEY_BINDING_NONCE}
maximumKeyBindingAgeSeconds: 300
clockSkewSeconds: 30
",
        revision = "0".repeat(64),
        binding = "A".repeat(43),
    )
}

/// The four members RFC 9901 section 4.3 permits, over one presentation prefix.
///
/// `sd_hash_input` is the presentation up to and including its last tilde,
/// which for a complete issued credential is that serialization itself.
fn valid_key_binding_claims(sd_hash_input: &str) -> Value {
    json!({
        "nonce": KEY_BINDING_NONCE,
        "aud": KEY_BINDING_AUDIENCE,
        "iat": presentation_instant(),
        "sd_hash": disclosure_hash(sd_hash_input),
    })
}

/// The verification instant the holder-bound runs share, as a Unix second.
fn presentation_instant() -> i64 {
    chrono::DateTime::parse_from_rfc3339(PRESENTATION_INSTANT)
        .expect("the staged instant parses")
        .timestamp()
}

/// The `sd_hash` a proof carries over one presentation prefix.
fn disclosure_hash(sd_hash_input: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    URL_SAFE_NO_PAD.encode(registry_platform_sdjwt::presentation_disclosure_hash(
        sd_hash_input,
    ))
}

/// Sign one compact JWT over the given header and claims with a staged test
/// key.
fn sign_compact_jwt(header: &Value, claims: &Value, private_jwk: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use registry_platform_crypto::{sign, PrivateJwk};

    let key = PrivateJwk::parse(private_jwk).expect("the staged key parses");
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).expect("header serializes")),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims serialize")),
    );
    let signature =
        URL_SAFE_NO_PAD.encode(sign(signing_input.as_bytes(), &key).expect("the staged key signs"));
    format!("{signing_input}.{signature}")
}

/// The three files an operator holds for offline re-verification: one stored
/// signed response, one pinned trusted key set, and one policy document.
struct StoredResponse {
    root: tempfile::TempDir,
}

impl StoredResponse {
    /// Sign `signed`, store `stored` as the response payload, and stage
    /// `policy`. Passing different payloads produces a tampered response whose
    /// signature no longer covers the stored bytes.
    fn stage(signed: &serde_json::Value, stored: &serde_json::Value, policy: &str) -> Self {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use registry_platform_crypto::{sign, PrivateJwk};

        let root = tempfile::tempdir().expect("temporary verification inputs");
        let key = PrivateJwk::parse(VERIFY_PRIVATE_JWK).expect("fixture key parses");
        let protected = URL_SAFE_NO_PAD.encode(format!(
            r#"{{"alg":"ES256","kid":"{VERIFY_KEY_ID}","typ":"evidence+jws","cty":"application/evidence+json"}}"#
        ));
        let signed_payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(signed).expect("Evidence payload serializes"));
        let signature = URL_SAFE_NO_PAD.encode(
            sign(format!("{protected}.{signed_payload}").as_bytes(), &key)
                .expect("fixture payload signs"),
        );
        let stored_payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(stored).expect("Evidence payload serializes"));

        fs::write(
            root.path().join("response.jws.json"),
            format!(
                r#"{{"protected":"{protected}","payload":"{stored_payload}","signature":"{signature}"}}"#
            ),
        )
        .expect("stage the stored response");
        fs::write(
            root.path().join("trusted.jwks.json"),
            serde_json::to_vec(&serde_json::json!({"keys": [key.public()]}))
                .expect("trusted JWKS serializes"),
        )
        .expect("stage the pinned key set");
        fs::write(root.path().join("policy.yaml"), policy).expect("stage the policy");
        Self { root }
    }

    /// Run `verify` with no runtime file staged, so the command proves it needs
    /// no deployment and opens no socket.
    fn verify(&self, at: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_evidence"));
        command
            .arg("verify")
            .arg("--jws")
            .arg(self.root.path().join("response.jws.json"))
            .arg("--jwks")
            .arg(self.root.path().join("trusted.jwks.json"))
            .arg("--policy")
            .arg(self.root.path().join("policy.yaml"))
            .env_remove("REGISTRY_EVIDENCE_RUNTIME");
        if let Some(at) = at {
            command.arg("--at").arg(at);
        }
        command.output().expect("evidence binary starts")
    }
}

/// The SD-JWT VC counterpart of `StoredResponse`. The same assertion is
/// serialized through the production issuance path, so the command is proven
/// against the bytes an adopter actually receives rather than a hand-built
/// approximation.
struct StoredCredential {
    root: tempfile::TempDir,
}

impl StoredCredential {
    /// Issue the fixture assertion, apply `mutate` to the serialization, and
    /// stage it beside the pinned key set and the policy.
    fn stage(policy: &str, mutate: impl FnOnce(String) -> String) -> Self {
        use registry_evidence::{
            model::Evidence,
            sdjwt_vc::issuance_input,
            signing::{jwks_document, EvidenceSigner},
        };
        use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, SigningProvider};
        use std::sync::Arc;

        let root = tempfile::tempdir().expect("temporary verification inputs");
        let evidence: Evidence =
            serde_json::from_value(fixture_evidence()).expect("the fixture is an Evidence payload");
        let private = PrivateJwk::parse(VERIFY_PRIVATE_JWK).expect("fixture key parses");
        let provider: Arc<dyn SigningProvider> =
            Arc::new(LocalJwkSigner::new(private).expect("fixture signer builds"));

        let (credential, trusted) = tokio::runtime::Runtime::new()
            .expect("issuance runtime starts")
            .block_on(async {
                let signer = EvidenceSigner::initialize(provider, VERIFY_KEY_ID)
                    .await
                    .expect("signer initializes");
                let input =
                    issuance_input(&evidence, None, &BTreeMap::new()).expect("the fixture maps");
                let credential = signer
                    .sign_sd_jwt_vc(input)
                    .await
                    .expect("credential serializes");
                let trusted = jwks_document(signer.public_jwk(), []).expect("JWKS builds");
                (credential, trusted)
            });

        fs::write(root.path().join("response.sd-jwt"), mutate(credential))
            .expect("stage the stored credential");
        fs::write(
            root.path().join("trusted.jwks.json"),
            serde_json::to_vec(&trusted).expect("JWKS serializes"),
        )
        .expect("stage the pinned key set");
        fs::write(root.path().join("policy.yaml"), policy).expect("stage the policy");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn verify(&self, at: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_evidence"));
        command
            .arg("verify")
            .arg("--sd-jwt-vc")
            .arg(self.path("response.sd-jwt"))
            .arg("--jwks")
            .arg(self.path("trusted.jwks.json"))
            .arg("--policy")
            .arg(self.path("policy.yaml"))
            .env_remove("REGISTRY_EVIDENCE_RUNTIME");
        if let Some(at) = at {
            command.arg("--at").arg(at);
        }
        command.output().expect("evidence binary starts")
    }

    /// Offer the issued audience-scoped credential to the holder-bound command,
    /// which must refuse bytes that carry no proof of possession.
    fn verify_presentation(&self, at: Option<&str>) -> Output {
        invoke_verify_presentation(
            &self.path("response.sd-jwt"),
            &self.path("trusted.jwks.json"),
            &self.path("policy.yaml"),
            at,
        )
    }
}

/// The three files an operator holds for offline re-verification of a
/// holder-bound presentation: one stored presentation carrying the holder's
/// key-binding JWT after its last tilde, one pinned trusted key set, and one
/// holder-bound policy document.
struct StoredPresentation {
    root: tempfile::TempDir,
}

impl StoredPresentation {
    /// Issue the holder-bound fixture confirming the test holder key, append a
    /// key-binding JWT carrying `claims` and signed by `key_binding_jwk`, and
    /// stage the result beside the pinned key set and the policy.
    ///
    /// `claims` receives the issued serialization, which is exactly the input
    /// RFC 9901 section 4.3.1 hashes into `sd_hash`, so a case can bind a proof
    /// to bytes other than the ones it travels with.
    fn stage(policy: &str, claims: impl FnOnce(&str) -> Value, key_binding_jwk: &str) -> Self {
        use registry_evidence::{
            model::{Evidence, HolderPublicKey},
            sdjwt_vc::issuance_input,
            signing::{jwks_document, EvidenceSigner},
        };
        use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, SigningProvider};
        use std::sync::Arc;

        let root = tempfile::tempdir().expect("temporary verification inputs");
        let evidence: Evidence = serde_json::from_value(holder_bound_fixture_evidence())
            .expect("the fixture is a holder-bound Evidence payload");
        let holder: HolderPublicKey =
            serde_json::from_str(HOLDER_PUBLIC_JWK).expect("the holder key parses");
        let private = PrivateJwk::parse(VERIFY_PRIVATE_JWK).expect("fixture key parses");
        let provider: Arc<dyn SigningProvider> =
            Arc::new(LocalJwkSigner::new(private).expect("fixture signer builds"));

        let (issued, trusted) = tokio::runtime::Runtime::new()
            .expect("issuance runtime starts")
            .block_on(async {
                let signer = EvidenceSigner::initialize(provider, VERIFY_KEY_ID)
                    .await
                    .expect("signer initializes");
                let input = issuance_input(&evidence, Some(&holder), &BTreeMap::new())
                    .expect("the fixture maps");
                let issued = signer
                    .sign_sd_jwt_vc(input)
                    .await
                    .expect("credential serializes");
                let trusted = jwks_document(signer.public_jwk(), []).expect("JWKS builds");
                (issued, trusted)
            });
        let key_binding = sign_compact_jwt(
            &json!({"alg": "ES256", "typ": "kb+jwt"}),
            &claims(&issued),
            key_binding_jwk,
        );

        fs::write(
            root.path().join("presentation.sd-jwt"),
            format!("{issued}{key_binding}"),
        )
        .expect("stage the stored presentation");
        fs::write(
            root.path().join("trusted.jwks.json"),
            serde_json::to_vec(&trusted).expect("JWKS serializes"),
        )
        .expect("stage the pinned key set");
        fs::write(root.path().join("policy.yaml"), policy).expect("stage the policy");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn verify_presentation(&self, at: Option<&str>) -> Output {
        invoke_verify_presentation(
            &self.path("presentation.sd-jwt"),
            &self.path("trusted.jwks.json"),
            &self.path("policy.yaml"),
            at,
        )
    }

    /// Offer the same presentation bytes to the Version 1 `verify` command,
    /// against a policy document that command does accept, so its refusal is
    /// about the serialization rather than the policy it was handed.
    fn verify_as_stored_response(&self, at: Option<&str>) -> Output {
        let policy = self.path("audience-scoped-policy.yaml");
        fs::write(&policy, fixture_policy()).expect("stage the Version 1 policy");
        let mut command = Command::new(env!("CARGO_BIN_EXE_evidence"));
        command
            .arg("verify")
            .arg("--sd-jwt-vc")
            .arg(self.path("presentation.sd-jwt"))
            .arg("--jwks")
            .arg(self.path("trusted.jwks.json"))
            .arg("--policy")
            .arg(policy)
            .env_remove("REGISTRY_EVIDENCE_RUNTIME");
        if let Some(at) = at {
            command.arg("--at").arg(at);
        }
        command.output().expect("evidence binary starts")
    }
}

/// Run `verify-presentation` with no runtime file staged, so the command proves
/// it needs no deployment and opens no socket.
fn invoke_verify_presentation(
    presentation: &Path,
    jwks: &Path,
    policy: &Path,
    at: Option<&str>,
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_evidence"));
    command
        .arg("verify-presentation")
        .arg("--sd-jwt-vc-presentation")
        .arg(presentation)
        .arg("--jwks")
        .arg(jwks)
        .arg("--policy")
        .arg(policy)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME");
    if let Some(at) = at {
        command.arg("--at").arg(at);
    }
    command.output().expect("evidence binary starts")
}

fn stop(service: &mut Child) {
    let pid = rustix::process::Pid::from_raw(
        i32::try_from(service.id()).expect("child identifier is a pid"),
    )
    .expect("child identifier is a pid");
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).expect("send SIGTERM");
    let status = service.wait().expect("service exits");
    assert!(
        status.success(),
        "SIGTERM did not stop the service cleanly: {status}"
    );
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve a local port")
        .local_addr()
        .expect("reserved port")
        .port()
}

/// Poll `/ready` until the service reports a healthy audit chain.
///
/// Readiness covers the subject-binding key, the signer, the audit chain head,
/// and every source credential, so a ready service proves the whole startup
/// path completed rather than only that a socket is open.
fn wait_until_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = String::new();
    while Instant::now() < deadline {
        if let Some(status) = probe(port, "/ready") {
            if status == "HTTP/1.1 200 OK" {
                return;
            }
            last = status;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the service never became ready (last status {last:?})");
}

fn probe(port: u16, path: &str) -> Option<String> {
    use std::io::{BufRead as _, BufReader, Write as _};

    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut status = String::new();
    BufReader::new(stream).read_line(&mut status).ok()?;
    Some(status.trim_end().to_owned())
}

/// A staged deployment: one acceptance bundle, one operator runtime file, and
/// one private secret root under a single temporary directory.
struct Deployment {
    root: tempfile::TempDir,
    port: u16,
}

impl Deployment {
    fn stage(case: &str) -> Self {
        Self::stage_on_port(case, 8080)
    }

    fn stage_on_port(case: &str, port: u16) -> Self {
        let deployment = Self {
            root: tempfile::tempdir().expect("temporary deployment"),
            port,
        };
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance")
            .join(case);
        copy_tree(&source, &deployment.path("bundle"));
        deployment.replace(
            "bundle/evidence.yaml",
            "assuranceProfile: evidence-grade",
            "assuranceProfile: local",
        );
        let secrets = deployment.path("secrets");
        fs::create_dir(&secrets).expect("create private secret root");
        fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))
            .expect("set private secret-root mode");
        fs::write(
            deployment.path("runtime.yaml"),
            deployment.runtime_document(),
        )
        .expect("stage runtime");
        deployment
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.path().join(relative)
    }

    fn runtime_document(&self) -> String {
        format!(
            "version: 1
bundleDirectory: {bundle}
listener:
  bindHost: 127.0.0.1
  port: {port}
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 5000
secretProviders:
  file:
    root: {secrets}
signer:
  kind: local-jwk
  privateKeyRef: secret:file/signing-key
auditStorage:
  path: {audit}
  maximumFileBytes: 1073741824
outboundTls:
  systemRoots: true
  trustProfiles: {{}}
",
            bundle = self.path("bundle").display(),
            port = self.port,
            secrets = self.path("secrets").display(),
            audit = self.path("audit.jsonl").display(),
        )
    }

    fn write(&self, relative: &str, contents: &str) {
        fs::write(self.path(relative), contents).expect("write staged artifact");
    }

    fn append(&self, relative: &str, contents: &str) {
        let path = self.path(relative);
        let mut text = fs::read_to_string(&path).expect("read staged artifact");
        text.push_str(contents);
        fs::write(path, text).expect("write staged artifact");
    }

    fn remove(&self, relative: &str) {
        fs::remove_file(self.path(relative)).expect("remove staged artifact");
    }

    fn replace(&self, relative: &str, from: &str, to: &str) {
        let path = self.path(relative);
        let text = fs::read_to_string(&path).expect("read staged artifact");
        assert!(text.contains(from), "staged artifact has no {from:?}");
        fs::write(path, text.replacen(from, to, 1)).expect("write staged artifact");
    }

    fn replace_line(&self, relative: &str, prefix: &str, line: &str) {
        let path = self.path(relative);
        let text = fs::read_to_string(&path).expect("read staged artifact");
        let replaced = text
            .lines()
            .map(|current| {
                if current.starts_with(prefix) {
                    line.to_owned()
                } else {
                    format!("{current}\n")
                }
            })
            .collect::<String>();
        assert_ne!(replaced, text, "staged artifact has no {prefix:?} line");
        fs::write(path, replaced).expect("write staged artifact");
    }

    fn write_secret(&self, name: &str, value: &str) {
        let path = self.path("secrets").join(name);
        fs::write(&path, value).expect("write staged secret");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set owner-only secret mode");
    }

    /// Stage every logical secret the acceptance bundle references.
    ///
    /// The signing key matches the governed public fixture key, and the source
    /// credentials are synthetic constants that never reach a network because
    /// the test performs no evidence request.
    fn stage_acceptance_secrets(&self) {
        self.write_secret("audit-hash-key", "audit-hash-secret-32-bytes-minimum-value");
        self.write_secret(
            "subject-binding-key",
            "subject-binding-secret-32-bytes-minimum-value",
        );
        self.write_secret("signing-key", VERIFY_PRIVATE_JWK);
        self.write_secret("source-a-token", "synthetic-source-token");
        self.write_secret("source-b-token", "synthetic-source-token");
        self.write_secret("source-c-username", "synthetic-source-user");
        self.write_secret("source-c-password", "synthetic-source-password");
        self.write_secret("source-d-token", "synthetic-source-token");
    }

    fn point_authentication_to(&self, origin: &str) {
        self.replace(
            "bundle/evidence.yaml",
            "  issuer: https://identity.invalid\n",
            &format!("  issuer: {origin}\n"),
        );
        self.replace(
            "bundle/evidence.yaml",
            "  jwksUri: https://identity.invalid/.well-known/jwks.json\n",
            &format!("  jwksUri: {origin}/.well-known/jwks.json\n"),
        );
    }

    /// Place an audit chain the service will find on start, owner-only as the
    /// sink requires. A case that is about a mode widens it afterwards.
    fn stage_audit_chain(&self, contents: &str) {
        let path = self.path("audit.jsonl");
        fs::write(&path, contents).expect("stage audit chain");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set owner-only audit chain mode");
    }

    /// Overwrite the staged signing key with a different valid P-256 key.
    fn write_mismatched_signing_key(&self) {
        self.write_secret("signing-key", MISMATCHED_PRIVATE_JWK);
    }

    /// Start `serve` against the sealed deployment.
    fn serve(&self) -> Child {
        Command::new(env!("CARGO_BIN_EXE_evidence"))
            .arg("--runtime")
            .arg(self.path("runtime.yaml"))
            .arg("serve")
            .env_remove("REGISTRY_EVIDENCE_RUNTIME")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("evidence service starts")
    }

    /// Run `check` against the sealed deployment, then restore write access so
    /// the temporary directory can be cleaned up.
    fn check(&self) -> Output {
        self.seal();
        let output = invoke(&self.path("runtime.yaml"), &["check"]);
        self.unseal();
        output
    }

    fn check_with_runtime_dependencies(&self) -> Output {
        self.seal();
        let output = invoke(
            &self.path("runtime.yaml"),
            &["check", "--require-runtime-dependencies"],
        );
        self.unseal();
        output
    }

    /// Evaluate the staged bundle's own fixture, with any extra arguments.
    fn evaluate(&self, arguments: &[&str]) -> Output {
        let mut invocation = vec!["evaluate", "--fixture", "fixtures/cases.yaml"];
        invocation.extend_from_slice(arguments);
        self.seal();
        let output = invoke(&self.path("runtime.yaml"), &invocation);
        self.unseal();
        output
    }

    fn seal(&self) {
        set_tree_mode(&self.path("bundle"), 0o555, 0o444);
        fs::set_permissions(self.path("runtime.yaml"), fs::Permissions::from_mode(0o444))
            .expect("seal runtime");
    }

    fn unseal(&self) {
        set_tree_mode(&self.path("bundle"), 0o755, 0o644);
        fs::set_permissions(self.path("runtime.yaml"), fs::Permissions::from_mode(0o644))
            .expect("unseal runtime");
    }
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if self.path("bundle").is_dir() {
            set_tree_mode(&self.path("bundle"), 0o755, 0o644);
        }
    }
}

fn write_private_json(path: &Path, value: &Value) {
    fs::write(
        path,
        serde_json::to_vec(value).expect("local relying procedure draft serializes"),
    )
    .expect("write local relying procedure draft");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("make local relying procedure draft owner-only");
}

fn invoke_local_relying_procedure(runtime: &Path, input: &Path, stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_evidence"))
        .arg("--runtime")
        .arg(runtime)
        .arg("prepare-local-relying-procedure")
        .arg("--input")
        .arg(input)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("evidence binary starts");
    let mut child_stdin = child.stdin.take().expect("command stdin is piped");
    child_stdin
        .write_all(stdin)
        .expect("write deliberately irrelevant stdin");
    drop(child_stdin);
    child.wait_with_output().expect("evidence command exits")
}

fn invoke(runtime: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidence"))
        .arg("--runtime")
        .arg(runtime)
        .args(arguments)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .output()
        .expect("evidence binary starts")
}

fn assert_success(output: &Output, prefix: &str, suffix: &str) {
    assert!(output.status.success(), "evidence command failed");
    assert!(
        output.stderr.is_empty(),
        "evidence command wrote diagnostics"
    );
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert!(
        stdout.starts_with(prefix) && stdout.ends_with(suffix),
        "evidence command output shape changed"
    );
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create staged directory");
    for entry in fs::read_dir(source).expect("read source tree") {
        let entry = entry.expect("source entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("source entry type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy staged artifact");
        }
    }
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set staged mode");
}

fn set_tree_mode(path: &Path, directory_mode: u32, file_mode: u32) {
    let metadata = fs::symlink_metadata(path).expect("staged path metadata");
    if metadata.is_dir() {
        for entry in fs::read_dir(path).expect("read staged tree") {
            set_tree_mode(
                &entry.expect("staged entry").path(),
                directory_mode,
                file_mode,
            );
        }
        fs::set_permissions(path, fs::Permissions::from_mode(directory_mode))
            .expect("set staged directory mode");
    } else {
        fs::set_permissions(path, fs::Permissions::from_mode(file_mode))
            .expect("set staged file mode");
    }
}
