#![cfg(unix)]
#![allow(
    clippy::disallowed_methods,
    reason = "tests read the published example and the files the code under test wrote; they read no operator configuration"
)]

//! The public certificate check example, packaged and served.
//!
//! The ordinary test keeps the packaged deployment reference beside the
//! Evidence crate equal to what `evidencectl package` produces from the
//! example. The ignored gate starts the real Evidence binary on the packaged
//! example, posts one hit and misses to `/v1/public-check`, and reads the audit
//! history back through the core's minimized view.

use serde_json::Value;
use std::{
    fs,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

const DOCUMENT_NUMBER: &str = "RN-2026-004217";
const CHECK_CODE: &str = "K7QWM4XRT5PZ3NB6VHJYDC2A";
const LEGACY_DOCUMENT_NUMBER: &str = "RN-2019-000042";
// Records the example pack cannot fully use. A caller with the wrong code must
// still get the common miss, because a failure here would show the record exists.
const LOWERCASE_CODE_NUMBER: &str = "RN-2026-100001";
const NO_EXPIRY_NUMBER: &str = "RN-2026-100002";
const UNKNOWN_STATUS_NUMBER: &str = "RN-2026-100003";
const MISMATCHED_NUMBER: &str = "RN-2026-100004";
const OTHER_NUMBER: &str = "RN-2026-100005";

fn example() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/evidence/examples/public-check")
}

fn deployment_reference() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../products/evidence/reference/request-adapter/deployment-projects/public-check-evidence",
    )
}

fn evidencectl() -> Command {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("destination directory");
    for entry in fs::read_dir(source).expect("source directory") {
        let entry = entry.expect("source entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("source entry type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy file");
        }
    }
}

fn set_tree_mode(path: &Path, directory_mode: u32, file_mode: u32) {
    if path.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(directory_mode))
            .expect("directory mode");
        for entry in fs::read_dir(path).expect("directory entries") {
            set_tree_mode(&entry.expect("entry").path(), directory_mode, file_mode);
        }
    } else {
        fs::set_permissions(path, fs::Permissions::from_mode(file_mode)).expect("file mode");
    }
}

fn unused_ports<const N: usize>() -> [u16; N] {
    let listeners: Vec<TcpListener> = (0..N)
        .map(|_| TcpListener::bind("127.0.0.1:0").expect("reserve port"))
        .collect();
    let ports = listeners
        .iter()
        .map(|listener| listener.local_addr().expect("address").port())
        .collect::<Vec<_>>();
    drop(listeners);
    ports.try_into().expect("port count")
}

/// A writable copy of the example with its keys generated and its target
/// pointed at the given loopback ports, packaged into a candidate directory.
struct Packaged {
    _temporary: tempfile::TempDir,
    project: PathBuf,
    candidate: PathBuf,
}

fn package_example(ports: Option<[u16; 3]>) -> Packaged {
    let temporary = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).expect("tempdir mode");
    let project = temporary.path().join("project");
    copy_tree(&example(), &project);
    let target = project.join("public-check-target.yaml");
    if let Some([evidence, issuer, source]) = ports {
        let text = fs::read_to_string(&target)
            .expect("target")
            .replace("127.0.0.1:8090", &format!("127.0.0.1:{evidence}"))
            .replace("127.0.0.1:8082", &format!("127.0.0.1:{issuer}"))
            .replace("127.0.0.1:8081", &format!("127.0.0.1:{source}"));
        fs::write(&target, text).expect("target ports");
    }
    let secrets = project.join(".generated/secrets");
    assert_success(
        &evidencectl()
            .args(["keygen", "signing", "--output-dir"])
            .arg(&secrets)
            .output()
            .expect("signing key"),
        "signing key",
    );
    for name in ["audit-hmac-key", "subject-binding-hmac-key"] {
        assert_success(
            &evidencectl()
                .args(["keygen", "secret", "--output"])
                .arg(secrets.join(name))
                .output()
                .expect("HMAC key"),
            "HMAC key",
        );
    }
    assert_success(
        &evidencectl()
            .args(["keygen", "token", "--output"])
            .arg(secrets.join("synthetic-source-token"))
            .output()
            .expect("source token"),
        "source token",
    );
    let candidate = temporary.path().join("candidate");
    assert_success(
        &evidencectl()
            .args(["package"])
            .arg(&project)
            .arg("--target")
            .arg(&target)
            .arg("--output")
            .arg(&candidate)
            .output()
            .expect("package"),
        "package",
    );
    Packaged {
        _temporary: temporary,
        project,
        candidate,
    }
}

impl Drop for Packaged {
    fn drop(&mut self) {
        set_tree_mode(self._temporary.path(), 0o755, 0o644);
    }
}

fn relative_files(root: &Path) -> Vec<PathBuf> {
    fn walk(root: &Path, directory: &Path, found: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(directory).expect("directory entries") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                walk(root, &path, found);
            } else {
                found.push(path.strip_prefix(root).expect("inside root").to_owned());
            }
        }
    }
    let mut found = Vec::new();
    walk(root, root, &mut found);
    found.sort();
    found
}

/// The packaged deployment reference holds exactly what packaging the example
/// produces, apart from the public signing key and the package envelope, which
/// belong to the deployment that generated them.
#[test]
fn the_packaged_deployment_reference_matches_the_example() {
    let packaged = package_example(None);
    let is_deployment_owned =
        |path: &Path| path.starts_with("public-keys") || path == Path::new("SHA256SUMS");
    let produced = packaged.candidate.join("bundle");
    let committed = deployment_reference().join("bundle");
    let produced_files = relative_files(&produced)
        .into_iter()
        .filter(|path| !is_deployment_owned(path))
        .collect::<Vec<_>>();
    let committed_files = relative_files(&committed)
        .into_iter()
        .filter(|path| !is_deployment_owned(path))
        .collect::<Vec<_>>();
    assert_eq!(
        produced_files, committed_files,
        "regenerate the packaged reference with evidencectl package"
    );
    // The one line naming the signing key file belongs to the deployment.
    let comparable = |root: &Path, path: &Path| {
        let bytes = fs::read(root.join(path)).expect("bundle file");
        if path == Path::new("evidence.yaml") {
            String::from_utf8(bytes)
                .expect("evidence.yaml text")
                .lines()
                .filter(|line| !line.contains("activePublicJwkFile"))
                .collect::<Vec<_>>()
                .join("\n")
                .into_bytes()
        } else {
            bytes
        }
    };
    for path in &produced_files {
        assert_eq!(
            comparable(&produced, path),
            comparable(&committed, path),
            "{} differs from the example; regenerate the packaged reference",
            path.display()
        );
    }
    assert_eq!(
        fs::read(packaged.candidate.join("compiled-authority.yaml")).expect("compiled authority"),
        fs::read(deployment_reference().join("compiled-authority.yaml"))
            .expect("committed compiled authority"),
        "regenerate the packaged reference with evidencectl package"
    );
}

/// A loopback server standing in for both the certificate register and the
/// issuer's key endpoint. Records are keyed by document number; a number with
/// no record answers an empty result, and one issued before check codes
/// existed answers a record without a code. Four more numbers answer a
/// lowercase stored code, a record without `expiresOn`, an unknown status, and
/// a record for a different number than the one requested.
fn serve_synthetic_services(
    issuer: TcpListener,
    source: TcpListener,
    public_jwk: Value,
    source_token: String,
) {
    let jwks = serde_json::json!({"keys": [public_jwk]}).to_string();
    std::thread::spawn(move || {
        for stream in issuer.incoming().flatten() {
            let _ = answer(stream, |_path, _authorization| jwks.clone());
        }
    });
    std::thread::spawn(move || {
        for stream in source.incoming().flatten() {
            let _ = answer(stream, |path, authorization| {
                if !authorization.is_some_and(|value| value.contains(&source_token)) {
                    return serde_json::json!({"total": 0}).to_string();
                }
                match path.strip_prefix("/certificates/") {
                    Some(DOCUMENT_NUMBER) => serde_json::json!({
                        "total": 1,
                        "record": {
                            "record_id": DOCUMENT_NUMBER,
                            "status": "active",
                            "holder_name": "Jordan Sample",
                            "issued_on": "2025-03-01",
                            "expires_on": "2099-12-31",
                            "check_code": CHECK_CODE,
                        },
                    })
                    .to_string(),
                    Some(LEGACY_DOCUMENT_NUMBER) => serde_json::json!({
                        "total": 1,
                        "record": {
                            "record_id": LEGACY_DOCUMENT_NUMBER,
                            "status": "active",
                            "holder_name": "Casey Sample",
                            "issued_on": "2019-03-01",
                            "expires_on": "2099-12-31",
                        },
                    })
                    .to_string(),
                    Some(LOWERCASE_CODE_NUMBER) => serde_json::json!({
                        "total": 1,
                        "record": {
                            "record_id": LOWERCASE_CODE_NUMBER,
                            "status": "active",
                            "holder_name": "Lowercase Holder",
                            "issued_on": "2025-03-01",
                            "expires_on": "2099-12-31",
                            "check_code": CHECK_CODE.to_ascii_lowercase(),
                        },
                    })
                    .to_string(),
                    Some(NO_EXPIRY_NUMBER) => serde_json::json!({
                        "total": 1,
                        "record": {
                            "record_id": NO_EXPIRY_NUMBER,
                            "status": "active",
                            "holder_name": "Noexpiry Holder",
                            "issued_on": "2025-03-01",
                            "check_code": CHECK_CODE,
                        },
                    })
                    .to_string(),
                    Some(UNKNOWN_STATUS_NUMBER) => serde_json::json!({
                        "total": 1,
                        "record": {
                            "record_id": UNKNOWN_STATUS_NUMBER,
                            "status": "pending",
                            "holder_name": "Unknownstatus Holder",
                            "issued_on": "2025-03-01",
                            "expires_on": "2099-12-31",
                            "check_code": CHECK_CODE,
                        },
                    })
                    .to_string(),
                    Some(MISMATCHED_NUMBER) => serde_json::json!({
                        "total": 1,
                        "record": {
                            "record_id": OTHER_NUMBER,
                            "status": "active",
                            "holder_name": "Mismatched Holder",
                            "issued_on": "2025-03-01",
                            "expires_on": "2099-12-31",
                            "check_code": CHECK_CODE,
                        },
                    })
                    .to_string(),
                    _ => serde_json::json!({"total": 0}).to_string(),
                }
            });
        }
    });
}

fn answer(
    mut stream: TcpStream,
    body: impl Fn(&str, Option<String>) -> String,
) -> std::io::Result<()> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        request.extend_from_slice(&buffer[..read]);
    }
    let text = String::from_utf8_lossy(&request).into_owned();
    let path = text
        .lines()
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .unwrap_or("/")
        .to_owned();
    let authorization = text
        .lines()
        .find_map(|line| {
            line.strip_prefix("authorization: ")
                .or_else(|| line.strip_prefix("Authorization: "))
        })
        .map(str::to_owned);
    let payload = body(&path, authorization);
    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
        payload.len()
    )
}

/// One `POST /v1/public-check`, returning the status code and the body.
fn post_check(port: u16, body: &Value) -> (u16, Value) {
    let payload = body.to_string();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to Evidence");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    write!(
        stream,
        "POST /v1/public-check HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
        payload.len()
    )
    .expect("send request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    let (head, body) = response.split_once("\r\n\r\n").expect("response framing");
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status code");
    (status, serde_json::from_str(body).expect("JSON body"))
}

struct Running(Child);

impl Running {
    /// Stops the service the way an operator does and waits for it, so the
    /// audit file is released before it is read.
    fn stop(&mut self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status()
            .expect("kill");
        assert!(status.success(), "signal Evidence");
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.0.try_wait().expect("wait").is_none() {
            assert!(Instant::now() < deadline, "Evidence did not stop");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "exact gate: starts the real Evidence binary"]
fn the_packaged_example_answers_a_hit_and_an_identical_miss_and_audits_neither_subject() {
    let evidence = PathBuf::from(
        std::env::var_os("EVIDENCE_BIN").expect("set EVIDENCE_BIN for the exact public check gate"),
    );
    let [evidence_port, issuer_port, source_port] = unused_ports();
    let packaged = package_example(Some([evidence_port, issuer_port, source_port]));

    let secrets = packaged.project.join(".generated/secrets");
    let public_jwk: Value = serde_json::from_slice(
        &fs::read(secrets.join("signing-p256-public.jwk.json")).expect("public JWK"),
    )
    .expect("public JWK JSON");
    let source_token = fs::read_to_string(secrets.join("synthetic-source-token"))
        .expect("source token")
        .trim()
        .to_owned();
    serve_synthetic_services(
        TcpListener::bind(("127.0.0.1", issuer_port)).expect("issuer port"),
        TcpListener::bind(("127.0.0.1", source_port)).expect("source port"),
        public_jwk,
        source_token,
    );

    // The runtime document names `.generated/package`, `.generated/audit` and
    // `.generated/authority` under the project. The package is read-only, as
    // the service requires.
    let generated = packaged.project.join(".generated");
    copy_tree(
        &packaged.candidate.join("bundle"),
        &generated.join("package"),
    );
    set_tree_mode(&generated.join("package"), 0o555, 0o444);
    for private in ["audit", "authority"] {
        fs::create_dir(generated.join(private)).expect("private directory");
        fs::set_permissions(generated.join(private), fs::Permissions::from_mode(0o700))
            .expect("private directory mode");
    }
    let runtime = packaged.candidate.join("runtime.yaml");
    let activated = Command::new(&evidence)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .args(["authority", "activate", "--runtime-config"])
        .arg(&runtime)
        .arg("--document")
        .arg(packaged.candidate.join("compiled-authority.yaml"))
        .output()
        .expect("activate authority");
    assert_success(&activated, "authority activation");

    let log = fs::File::create(packaged.project.join("evidence.log")).expect("service log");
    let child = Command::new(&evidence)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .args(["serve", "--runtime-config"])
        .arg(&runtime)
        .stdout(log.try_clone().expect("log handle"))
        .stderr(log)
        .stdin(Stdio::null())
        .spawn()
        .expect("start Evidence");
    let mut service = Running(child);
    let deadline = Instant::now() + Duration::from_secs(60);
    while TcpStream::connect(("127.0.0.1", evidence_port)).is_err() {
        assert!(
            service.0.try_wait().expect("service state").is_none(),
            "Evidence exited at startup: {}",
            fs::read_to_string(packaged.project.join("evidence.log")).unwrap_or_default()
        );
        assert!(Instant::now() < deadline, "Evidence did not listen");
        std::thread::sleep(Duration::from_millis(100));
    }

    // Every kind of miss shares one answer: a wrong code, an unknown number, a
    // record issued before check codes existed, and records the pack cannot use
    // (lowercase stored code, no expiry date, unknown status, a body for another
    // number). The last four are asked with a wrong code, so none of them fails
    // before the code comparison.
    let miss_bodies = [
        serde_json::json!({"documentNumber": DOCUMENT_NUMBER, "checkCode": "AAAAAAAAAAAAAAAAAAAAAAAA"}),
        serde_json::json!({"documentNumber": "RN-2026-999999", "checkCode": CHECK_CODE}),
        serde_json::json!({"documentNumber": LEGACY_DOCUMENT_NUMBER, "checkCode": CHECK_CODE}),
        serde_json::json!({"documentNumber": LOWERCASE_CODE_NUMBER, "checkCode": "AAAAAAAAAAAAAAAAAAAAAAAA"}),
        serde_json::json!({"documentNumber": NO_EXPIRY_NUMBER, "checkCode": "AAAAAAAAAAAAAAAAAAAAAAAA"}),
        serde_json::json!({"documentNumber": UNKNOWN_STATUS_NUMBER, "checkCode": "AAAAAAAAAAAAAAAAAAAAAAAA"}),
        serde_json::json!({"documentNumber": MISMATCHED_NUMBER, "checkCode": "AAAAAAAAAAAAAAAAAAAAAAAA"}),
    ];
    let mut misses = Vec::new();
    for body in &miss_bodies {
        let (status, answer) = post_check(evidence_port, body);
        assert_eq!(status, 404, "{answer}");
        misses.push(answer);
    }
    // The trace identifier differs per request; every other member is fixed.
    for miss in &mut misses {
        miss.as_object_mut().expect("problem").remove("traceId");
    }
    assert!(
        misses.windows(2).all(|pair| pair[0] == pair[1]),
        "{misses:?}"
    );
    assert_eq!(misses[0]["code"], "resource.not-found");

    // The server uppercases the code, so the hit is posted in lowercase.
    let (status, hit) = post_check(
        evidence_port,
        &serde_json::json!({
            "documentNumber": DOCUMENT_NUMBER,
            "checkCode": CHECK_CODE.to_ascii_lowercase(),
        }),
    );
    assert_eq!(status, 200, "{hit}");
    assert_eq!(hit["schema"], "registry.evidence.public-check/v1alpha1");
    assert_eq!(hit["status"], "valid");
    assert_eq!(
        hit["fields"],
        serde_json::json!({
            "holderName": "Jordan Sample",
            "issuedOn": "2025-03-01",
            "expiresOn": "2099-12-31",
        })
    );
    assert!(hit["observedAt"].is_string());
    assert!(hit.get("signature").is_none());
    service.stop();

    // Two entries per request (seven misses and one hit), none of them naming
    // the document number or code.
    let audit = fs::read_to_string(generated.join("audit/evidence.jsonl")).expect("audit file");
    assert_eq!(audit.lines().count(), 16, "{audit}");
    let view = Command::new(&evidence)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .arg("local-audit-last-operation")
        .arg("--runtime-config")
        .arg(&runtime)
        .output()
        .expect("audit view");
    assert_success(&view, "audit view");
    let view_text = String::from_utf8(view.stdout).expect("audit view text");
    let view: Value = serde_json::from_str(&view_text).expect("audit view JSON");
    let events = view["events"].as_array().expect("events");
    assert_eq!(events.len(), 2, "{view_text}");
    assert_eq!(events[0]["phase"], "access-attempt");
    assert_eq!(events[0]["decision"], "authorized");
    assert_eq!(events[1]["phase"], "disclosure-release");
    assert_eq!(events[1]["decision"], "released");
    let service_log = fs::read_to_string(packaged.project.join("evidence.log")).expect("log");
    for (name, text) in [
        ("audit file", &audit),
        ("audit view", &view_text),
        ("service log", &service_log),
    ] {
        for canary in [
            DOCUMENT_NUMBER,
            LEGACY_DOCUMENT_NUMBER,
            "RN-2026-999999",
            CHECK_CODE,
            &CHECK_CODE.to_ascii_lowercase(),
            "AAAAAAAAAAAAAAAAAAAAAAAA",
            LOWERCASE_CODE_NUMBER,
            NO_EXPIRY_NUMBER,
            UNKNOWN_STATUS_NUMBER,
            MISMATCHED_NUMBER,
            OTHER_NUMBER,
            "Jordan Sample",
            "Lowercase Holder",
            "Noexpiry Holder",
            "Unknownstatus Holder",
            "Mismatched Holder",
        ] {
            assert!(!text.contains(canary), "{name} leaks {canary}");
        }
    }
}
