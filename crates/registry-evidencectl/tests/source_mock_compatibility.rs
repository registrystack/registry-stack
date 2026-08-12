//! Native compatibility corpus for the local synthetic source mock.
//!
//! Several ideas were independently re-authored after reviewing Stoplight
//! Prism's test harness at commit
//! `94dd8d83ff1139b0c08abd34f73db23d59148103`: literal-versus-template
//! precedence, repeated local references, additional-properties closure,
//! encoded path segments, and bounded unsupported-route behavior. No Prism
//! code, fixture, runtime, Node dependency, or matching semantics are used.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;

const FIXTURES: &str = "tests/fixtures/source_mock";
static SERVER_TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Classification {
    MustAccept,
    MustRefuse,
    ObserveOnly,
}

fn evidencectl() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_evidencectl"))
}

fn run(directory: &Path, arguments: &[&str]) -> Output {
    Command::new(evidencectl())
        .current_dir(directory)
        .args(arguments)
        .output()
        .expect("run evidencectl")
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURES)
        .join(name)
}

fn copy_fixture_tree(destination: &Path) {
    copy_directory(&fixture("."), destination);
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create fixture destination");
    for entry in fs::read_dir(source).expect("read fixture directory") {
        let entry = entry.expect("fixture entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("fixture type").is_dir() {
            copy_directory(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy fixture file");
        }
    }
}

#[test]
fn every_corpus_case_has_an_explicit_bounded_outcome() {
    let cases = [
        ("oas31-noisy-routes", Classification::MustAccept),
        ("oas30-formats-and-nullable", Classification::MustAccept),
        ("local-reference-dataset", Classification::MustAccept),
        (
            "valid-routes-beside-unsupported-format",
            Classification::MustAccept,
        ),
        (
            "valid-routes-beside-undeclared-dataset",
            Classification::MustAccept,
        ),
        ("ignored-optional-controls", Classification::MustAccept),
        ("schema-valid-manual-body", Classification::MustAccept),
        ("materialized-byte-snapshot", Classification::MustAccept),
        ("explicit-project-origin", Classification::MustAccept),
        ("ambiguous-route-templates", Classification::MustRefuse),
        ("selected-unsupported-format", Classification::MustRefuse),
        ("malformed-openapi", Classification::MustRefuse),
        ("oversized-openapi", Classification::MustRefuse),
        ("selected-undeclared-dataset", Classification::MustRefuse),
        ("required-query-route", Classification::MustRefuse),
        ("required-header-route", Classification::MustRefuse),
        ("required-cookie-route", Classification::MustRefuse),
        ("duplicate-dataset-key", Classification::MustRefuse),
        ("invalid-dataset-row", Classification::MustRefuse),
        ("traversal-dataset-path", Classification::MustRefuse),
        ("schema-invalid-manual-body", Classification::MustRefuse),
        ("oversized-manual-body", Classification::MustRefuse),
        ("typed-path-parameter-drift", Classification::MustRefuse),
        ("structured-suffix-media-route", Classification::ObserveOnly),
        ("duplicate-unused-operation-id", Classification::ObserveOnly),
        ("unexpected-response-controls", Classification::ObserveOnly),
    ];
    let identifiers = cases.iter().map(|(name, _)| *name).collect::<BTreeSet<_>>();
    assert_eq!(
        identifiers.len(),
        cases.len(),
        "corpus identifiers are unique"
    );
    assert_eq!(
        cases
            .iter()
            .filter(|(_, outcome)| *outcome == Classification::MustAccept)
            .count(),
        9
    );
    assert_eq!(
        cases
            .iter()
            .filter(|(_, outcome)| *outcome == Classification::MustRefuse)
            .count(),
        14
    );
    assert_eq!(
        cases
            .iter()
            .filter(|(_, outcome)| *outcome == Classification::ObserveOnly)
            .count(),
        3
    );
}

#[test]
fn awkward_and_dataset_apis_materialize_and_check_offline() {
    for (spec, expected_operations) in [
        ("awkward.openapi.yaml", "operations=3"),
        ("dataset.openapi.yaml", "operations=1"),
        ("formats-openapi30.openapi.yaml", "operations=1"),
    ] {
        let temporary = tempfile::tempdir().expect("tempdir");
        copy_fixture_tree(temporary.path());
        let generated = run(
            temporary.path(),
            &[
                "source",
                "mock",
                "generate",
                "--openapi",
                spec,
                "--output",
                "mocks/source.yaml",
            ],
        );
        assert!(
            generated.status.success(),
            "generate {spec}: {}",
            String::from_utf8_lossy(&generated.stderr)
        );
        let checked = run(
            temporary.path(),
            &["source", "mock", "check", "--config", "mocks/source.yaml"],
        );
        assert!(
            checked.status.success(),
            "check {spec}: {}",
            String::from_utf8_lossy(&checked.stderr)
        );
        assert!(
            String::from_utf8_lossy(&checked.stdout).contains(expected_operations),
            "{}",
            String::from_utf8_lossy(&checked.stdout)
        );
    }
}

#[test]
fn regenerating_missing_bodies_explains_the_actual_inference_choices() {
    let temporary = tempfile::tempdir().expect("tempdir");
    copy_fixture_tree(temporary.path());
    let generated = run(
        temporary.path(),
        &[
            "source",
            "mock",
            "generate",
            "--openapi",
            "awkward.openapi.yaml",
            "--output",
            "mocks/source.yaml",
            "--operation",
            "GET /people/{person_id}",
        ],
    );
    assert!(generated.status.success());
    let body = only_json_body(&temporary.path().join("mocks/cases"));
    fs::remove_file(body).expect("remove generated body");

    let regenerated = run(
        temporary.path(),
        &[
            "source",
            "mock",
            "generate",
            "--config",
            "mocks/source.yaml",
            "--explain",
        ],
    );
    assert!(
        regenerated.status.success(),
        "{}",
        String::from_utf8_lossy(&regenerated.stderr)
    );
    let stdout = String::from_utf8_lossy(&regenerated.stdout);
    assert!(
        stdout.contains("Generator contract=evidencectl-source-mock-v1"),
        "{stdout}"
    );
    assert!(stdout.contains("Inference pointer="), "{stdout}");
    assert!(stdout.contains("rule=field."), "{stdout}");
    assert!(!stdout.contains("Missing bodies used"), "{stdout}");
}

#[test]
fn ambiguous_routes_and_unsupported_formats_refuse_before_publication() {
    for spec in ["ambiguous.openapi.yaml", "unsupported-format.openapi.yaml"] {
        let temporary = tempfile::tempdir().expect("tempdir");
        copy_fixture_tree(temporary.path());
        let output = run(
            temporary.path(),
            &[
                "source",
                "mock",
                "generate",
                "--openapi",
                spec,
                "--output",
                "mocks/source.yaml",
            ],
        );
        assert!(!output.status.success(), "{spec} unexpectedly materialized");
        assert!(!temporary.path().join("mocks").exists());
        assert!(output.stderr.len() < 4096, "diagnostic was not bounded");
    }
}

#[test]
fn malformed_and_oversized_openapi_refuse_before_publication() {
    let cases = [
        b"not: [valid".to_vec(),
        vec![b' '; registry_evidence_authoring::layout::MAX_OPENAPI_BYTES as usize + 1],
    ];
    for bytes in cases {
        let temporary = tempfile::tempdir().expect("tempdir");
        fs::write(temporary.path().join("source.yaml"), bytes).expect("write invalid OpenAPI");
        let output = run(
            temporary.path(),
            &[
                "source",
                "mock",
                "generate",
                "--openapi",
                "source.yaml",
                "--output",
                "mocks/source.yaml",
            ],
        );
        assert!(!output.status.success());
        assert!(!temporary.path().join("mocks").exists());
        assert!(output.stderr.len() < 4096, "diagnostic was not bounded");
    }
}

#[test]
fn invalid_reference_datasets_refuse_before_publication_without_values() {
    for bytes in [
        br#"[{"code":"planted-one","code":"planted-two"}]"#.as_slice(),
        br#"[1]"#,
        br#"[{"other":"planted-secret"}]"#,
        br#"[{"code":7}]"#,
    ] {
        let temporary = tempfile::tempdir().expect("tempdir");
        copy_fixture_tree(temporary.path());
        fs::write(temporary.path().join("data/place-codes.json"), bytes)
            .expect("write invalid dataset");
        let output = run(
            temporary.path(),
            &[
                "source",
                "mock",
                "generate",
                "--openapi",
                "dataset.openapi.yaml",
                "--output",
                "mocks/source.yaml",
            ],
        );
        assert!(!output.status.success());
        assert!(!temporary.path().join("mocks").exists());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("planted-one"), "{stderr}");
        assert!(!stderr.contains("planted-two"), "{stderr}");
        assert!(!stderr.contains("planted-secret"), "{stderr}");
        assert!(stderr.len() < 4096, "diagnostic was not bounded");
    }

    let temporary = tempfile::tempdir().expect("tempdir");
    copy_fixture_tree(temporary.path());
    let spec_path = temporary.path().join("dataset.openapi.yaml");
    let spec = fs::read_to_string(&spec_path).expect("dataset spec");
    fs::write(
        &spec_path,
        spec.replace("data/place-codes.json", "../outside.json"),
    )
    .expect("write traversal dataset path");
    let output = run(
        temporary.path(),
        &[
            "source",
            "mock",
            "generate",
            "--openapi",
            "dataset.openapi.yaml",
            "--output",
            "mocks/source.yaml",
        ],
    );
    assert!(!output.status.success());
    assert!(!temporary.path().join("mocks").exists());
    assert!(output.stderr.len() < 4096, "diagnostic was not bounded");
}

#[test]
fn explicitly_selected_incompatible_routes_refuse_before_publication() {
    for (operation, diagnostic) in [
        ("GET /unsupported-dataset", "undeclared mock dataset"),
        ("GET /required-header", "selected operation is incompatible"),
        ("GET /required-cookie", "selected operation is incompatible"),
    ] {
        let temporary = tempfile::tempdir().expect("tempdir");
        copy_fixture_tree(temporary.path());
        let output = run(
            temporary.path(),
            &[
                "source",
                "mock",
                "generate",
                "--openapi",
                "awkward.openapi.yaml",
                "--output",
                "mocks/source.yaml",
                "--operation",
                operation,
            ],
        );
        assert!(
            !output.status.success(),
            "{operation} unexpectedly succeeded"
        );
        assert!(!temporary.path().join("mocks").exists());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(diagnostic), "{operation}: {stderr}");
        assert!(stderr.len() < 4096, "diagnostic was not bounded");
    }
}

#[test]
fn dataset_drift_blocks_future_generation_but_not_checking_existing_bodies() {
    let temporary = tempfile::tempdir().expect("tempdir");
    copy_fixture_tree(temporary.path());
    let generated = run(
        temporary.path(),
        &[
            "source",
            "mock",
            "generate",
            "--openapi",
            "dataset.openapi.yaml",
            "--output",
            "mocks/source.yaml",
        ],
    );
    assert!(generated.status.success());
    fs::write(
        temporary.path().join("data/place-codes.json"),
        b"[{\"code\":\"C03\"}]\n",
    )
    .expect("edit dataset");

    let checked = run(
        temporary.path(),
        &["source", "mock", "check", "--config", "mocks/source.yaml"],
    );
    assert!(
        checked.status.success(),
        "existing bodies do not read datasets"
    );

    fs::remove_file(only_json_body(&temporary.path().join("mocks/cases")))
        .expect("make one future generation necessary");

    let regenerated = run(
        temporary.path(),
        &[
            "source",
            "mock",
            "generate",
            "--config",
            "mocks/source.yaml",
        ],
    );
    assert!(!regenerated.status.success());
    assert!(String::from_utf8_lossy(&regenerated.stderr).contains("generation.datasets"));
}

#[test]
fn ephemeral_routes_are_dynamic_literal_first_and_ignore_response_controls() {
    let _server_test = SERVER_TEST_LOCK.lock().expect("lock server test");
    let temporary = tempfile::tempdir().expect("tempdir");
    copy_fixture_tree(temporary.path());
    let before = snapshot_tree(temporary.path());
    let address = reserve_loopback();
    let mut server = start_server(
        temporary.path(),
        &[
            "source",
            "mock",
            "serve",
            "--openapi",
            "awkward.openapi.yaml",
            "--http-addr",
            &address.to_string(),
        ],
    );

    let special = request(address, "GET", "/people/special", &[]);
    assert_eq!(special.status, 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&special.body).unwrap()["kind"],
        "special"
    );

    let first = request(address, "GET", "/people/person-123", &[]);
    let repeated = request(
        address,
        "GET",
        "/people/person-123?__dynamic=planted-control",
        &[("Prefer", "planted-control"), ("Cookie", "planted-control")],
    );
    let second = request(address, "GET", "/people/person-456", &[]);
    assert_eq!(first.status, 200);
    assert_eq!(first.body, repeated.body);
    assert_ne!(first.body, second.body);
    assert_eq!(
        serde_json::from_slice::<Value>(&first.body).unwrap()["person_id"],
        "person-123"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&second.body).unwrap()["person_id"],
        "person-456"
    );

    assert_eq!(request(address, "GET", "/people/%2F", &[]).status, 404);
    assert_eq!(
        request(address, "POST", "/people/person-123", &[]).status,
        405
    );
    assert_eq!(request(address, "GET", "/search", &[]).status, 501);
    assert_eq!(request(address, "GET", "/required-header", &[]).status, 501);
    assert_eq!(request(address, "GET", "/required-cookie", &[]).status, 501);
    assert_eq!(
        request(address, "GET", "/unsupported-password", &[]).status,
        501
    );
    assert_eq!(
        request(address, "GET", "/unsupported-dataset", &[]).status,
        501
    );
    stop_server(&mut server);
    assert_eq!(snapshot_tree(temporary.path()), before);
}

#[test]
fn edited_materialized_bytes_are_authoritative_and_snapshotted_once() {
    let _server_test = SERVER_TEST_LOCK.lock().expect("lock server test");
    let temporary = tempfile::tempdir().expect("tempdir");
    copy_fixture_tree(temporary.path());
    let generated = run(
        temporary.path(),
        &[
            "source",
            "mock",
            "generate",
            "--openapi",
            "awkward.openapi.yaml",
            "--output",
            "mocks/source.yaml",
            "--operation",
            "GET /people/{person_id}",
        ],
    );
    assert!(generated.status.success());
    let body_path = only_json_body(&temporary.path().join("mocks/cases"));
    let edited = br#"{
  "dateOfBirth": "1990-01-01",
  "firstName": "Synthetic",
  "home": {"email": "home@example.invalid"},
  "person_id": "person-123",
  "work": {"email": "work@example.invalid"}
}
"#;
    fs::write(&body_path, edited).expect("edit generated body");
    let checked = run(
        temporary.path(),
        &["source", "mock", "check", "--config", "mocks/source.yaml"],
    );
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );

    let address = reserve_loopback();
    let mut server = start_server(
        temporary.path(),
        &[
            "source",
            "mock",
            "serve",
            "--config",
            "mocks/source.yaml",
            "--http-addr",
            &address.to_string(),
        ],
    );
    let first = request(address, "GET", "/people/person-123", &[]);
    assert_eq!(first.status, 200);
    assert_eq!(first.body, edited);

    fs::write(
        &body_path,
        br#"{"dateOfBirth":"2001-01-01","firstName":"Changed","home":{"email":"a@example.invalid"},"person_id":"person-123","work":{"email":"b@example.invalid"}}"#,
    )
    .expect("post-start edit");
    let after_edit = request(address, "GET", "/people/person-123?case=other", &[]);
    assert_eq!(after_edit.body, edited);
    stop_server(&mut server);
}

#[test]
fn invalid_manual_edits_report_no_authored_value() {
    let temporary = tempfile::tempdir().expect("tempdir");
    copy_fixture_tree(temporary.path());
    assert!(run(
        temporary.path(),
        &[
            "source",
            "mock",
            "generate",
            "--openapi",
            "awkward.openapi.yaml",
            "--output",
            "mocks/source.yaml",
            "--operation",
            "GET /people/{person_id}",
        ],
    )
    .status
    .success());
    let body_path = only_json_body(&temporary.path().join("mocks/cases"));
    fs::write(&body_path, br#"{"planted-secret-value":"must-not-leak"}"#).expect("invalid edit");
    let output = run(
        temporary.path(),
        &["source", "mock", "check", "--config", "mocks/source.yaml"],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("planted-secret-value"), "{stderr}");
    assert!(!stderr.contains("must-not-leak"), "{stderr}");
    assert!(stderr.contains("body `cases/"), "{stderr}");
    assert!(
        stderr.contains("instance") && stderr.contains("schema"),
        "{stderr}"
    );
}

#[test]
fn malformed_and_oversized_manual_bodies_are_bounded_refusals() {
    for edited in [b"{\"planted-secret\":".to_vec(), vec![b'x'; 512 * 1024 + 1]] {
        let temporary = tempfile::tempdir().expect("tempdir");
        copy_fixture_tree(temporary.path());
        let generated = run(
            temporary.path(),
            &[
                "source",
                "mock",
                "generate",
                "--openapi",
                "awkward.openapi.yaml",
                "--output",
                "mocks/source.yaml",
                "--operation",
                "GET /people/{person_id}",
            ],
        );
        assert!(generated.status.success());
        let body_path = only_json_body(&temporary.path().join("mocks/cases"));
        fs::write(body_path, edited).expect("edit body");
        let checked = run(
            temporary.path(),
            &["source", "mock", "check", "--config", "mocks/source.yaml"],
        );
        assert!(!checked.status.success());
        let stderr = String::from_utf8_lossy(&checked.stderr);
        assert!(!stderr.contains("planted-secret"), "{stderr}");
        assert!(stderr.len() < 4096, "diagnostic was not bounded");
    }
}

#[test]
fn materialized_path_parameters_keep_the_openapi_json_type() {
    let temporary = tempfile::tempdir().expect("tempdir");
    copy_fixture_tree(temporary.path());
    let generated = run(
        temporary.path(),
        &[
            "source",
            "mock",
            "generate",
            "--openapi",
            "awkward.openapi.yaml",
            "--output",
            "mocks/source.yaml",
            "--operation",
            "GET /people/{person_id}",
        ],
    );
    assert!(generated.status.success());
    let config_path = temporary.path().join("mocks/source.yaml");
    let original = fs::read_to_string(&config_path).expect("generated config");
    let wrong_type = original.replace("person_id: person-123", "person_id: true");
    assert_ne!(wrong_type, original, "fixture witness must be present");
    fs::write(&config_path, wrong_type).expect("edit config type");

    let checked = run(
        temporary.path(),
        &["source", "mock", "check", "--config", "mocks/source.yaml"],
    );
    assert!(!checked.status.success());
    assert!(String::from_utf8_lossy(&checked.stderr).contains("wrong JSON type"));
}

#[test]
fn explicit_source_origin_wires_bare_project_mock_serve_create_only() {
    let _server_test = SERVER_TEST_LOCK.lock().expect("lock server test");
    let temporary = tempfile::tempdir().expect("tempdir");
    copy_fixture_tree(temporary.path());
    fs::copy(
        temporary.path().join("awkward.openapi.yaml"),
        temporary.path().join("source.openapi.yaml"),
    )
    .expect("retain project OpenAPI");
    for directory in ["sources", "adapters", "schemas"] {
        fs::create_dir(temporary.path().join(directory)).expect("authoring directory");
    }
    let address = reserve_loopback();
    let origin = format!("http://{address}");
    let suggested = run(
        temporary.path(),
        &[
            "source",
            "suggest",
            "--project",
            ".",
            "--operation",
            "GET /people/{person_id}",
            "--select",
            "/dateOfBirth",
            "--source-id",
            "people",
            "--base-url",
            &origin,
        ],
    );
    assert!(
        suggested.status.success(),
        "{}",
        String::from_utf8_lossy(&suggested.stderr)
    );
    let source_path = temporary.path().join("sources/people.yaml");
    let source_before = fs::read(&source_path).expect("source draft");
    assert!(String::from_utf8_lossy(&source_before).contains(&format!("baseUrl: {origin}")));

    let repeated = run(
        temporary.path(),
        &[
            "source",
            "suggest",
            "--project",
            ".",
            "--operation",
            "GET /people/{person_id}",
            "--select",
            "/dateOfBirth",
            "--source-id",
            "people",
            "--base-url",
            &origin,
        ],
    );
    assert!(!repeated.status.success());
    assert_eq!(fs::read(&source_path).unwrap(), source_before);

    let mut server = start_server(
        temporary.path(),
        &["source", "mock", "serve", "--project", "."],
    );
    assert_eq!(
        request(address, "GET", "/v1/people/person-123", &[]).status,
        200
    );
    stop_server(&mut server);
}

fn reserve_loopback() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    let address = listener.local_addr().expect("reserved address");
    drop(listener);
    address
}

fn start_server(directory: &Path, arguments: &[&str]) -> Child {
    let mut child = Command::new(evidencectl())
        .current_dir(directory)
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn source mock");
    let stdout = child.stdout.take().expect("server stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let read = reader.read_line(&mut line).expect("read readiness");
    if read == 0 || !line.contains("Source mock ready:") {
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .expect("server stderr")
            .read_to_string(&mut stderr)
            .expect("read server stderr");
        panic!("server did not become ready: {line}{stderr}");
    }
    // The server prints bounded route details after readiness. Keep draining
    // the captured pipe so dropping this reader cannot terminate those writes
    // before Axum begins accepting requests.
    thread::spawn(move || {
        let mut remainder = String::new();
        let _ = reader.read_to_string(&mut remainder);
    });
    child
}

fn stop_server(child: &mut Child) {
    child.kill().expect("stop test server");
    child.wait().expect("wait for test server");
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> HttpResponse {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = loop {
        match TcpStream::connect(address) {
            Ok(stream) => break stream,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("connect to source mock: {error}"),
        }
    };
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n"
    )
    .expect("write request line");
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n").expect("write request header");
    }
    stream.write_all(b"\r\n").expect("finish request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP header terminator");
    let head = std::str::from_utf8(&response[..split]).expect("HTTP response head");
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse().ok())
        .expect("HTTP response status");
    HttpResponse {
        status,
        body: response[split + 4..].to_vec(),
    }
}

fn only_json_body(root: &Path) -> PathBuf {
    fn visit(directory: &Path, found: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(directory).expect("read cases") {
            let entry = entry.expect("case entry");
            if entry.file_type().expect("case type").is_dir() {
                visit(&entry.path(), found);
            } else if entry.path().extension().and_then(|value| value.to_str()) == Some("json") {
                found.push(entry.path());
            }
        }
    }
    let mut found = Vec::new();
    visit(root, &mut found);
    assert_eq!(found.len(), 1);
    found.pop().unwrap()
}

fn snapshot_tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, directory: &Path, snapshot: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(directory).expect("read snapshot directory") {
            let entry = entry.expect("snapshot entry");
            if entry.file_type().expect("snapshot type").is_dir() {
                visit(root, &entry.path(), snapshot);
            } else {
                snapshot.insert(
                    entry.path().strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(entry.path()).expect("snapshot file"),
                );
            }
        }
    }
    let mut snapshot = BTreeMap::new();
    visit(root, root, &mut snapshot);
    snapshot
}
