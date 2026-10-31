// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `adapterctl verify --live`: the command dials
//! the loopback double with one constant-determined send per binding and
//! judges the answer against the send's declared range
//! (`products/adapter/CONCEPT.md` section 13.3).
//!
//! The double is a real TCP server on `127.0.0.1:0` speaking HTTP/1.1
//! with `Connection: close`, one request per connection, in the shape of
//! the engine's own test double (`crates/registry-adapter/tests/support/
//! upstream`). Its accept thread idles when a test ends; the process
//! exit reaps it.

use base64::Engine as _;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread;

/// The committed verify-live workspace (profile, pack, project pinned by
/// real digests). The runtime is written per test: its base URL carries
/// the double's port.
fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/verify-live")
        .to_path_buf()
}

/// Run one invocation in JSON mode and return its exit code, its report
/// (null when stdout carried no report), and its stderr.
fn run_json(arguments: &[&str]) -> (ExitCode, Value, Vec<u8>) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut all = vec![
        OsString::from("adapterctl"),
        OsString::from("--format=json"),
    ];
    all.extend(arguments.iter().map(OsString::from));
    let exit = registry_adapterctl::main_entry_from(all, &mut stdout, &mut stderr);
    let report = serde_json::from_slice(&stdout).unwrap_or(Value::Null);
    assert_envelope(&stdout, &report, exit);
    (exit, report, stderr)
}

/// Every JSON report opens with `ok`, `command`, and `status` in that
/// order, then names its format; `ok` is true exactly when the process
/// exits zero, and a report that is not ok carries at least one
/// diagnostic naming the next step.
fn assert_envelope(stdout: &[u8], report: &Value, exit: ExitCode) {
    let text = String::from_utf8_lossy(stdout);
    let head = text
        .lines()
        .filter_map(|line| line.strip_prefix("  \""))
        .filter_map(|line| line.split_once('"').map(|(key, _)| key))
        .take(5)
        .collect::<Vec<_>>();
    assert_eq!(
        head,
        ["ok", "command", "status", "apiVersion", "kind"],
        "{text}"
    );
    assert_eq!(
        report["apiVersion"],
        "id.registrystack.org/formats/adapter/ctl-report/v1alpha1"
    );
    assert_eq!(report["kind"], "AdapterCtlReport");
    assert!(report["command"].as_str().is_some_and(|c| !c.is_empty()));
    assert!(report["status"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(report["ok"], json!(exit == ExitCode::SUCCESS), "{text}");
    if exit != ExitCode::SUCCESS {
        let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
        assert!(!diagnostics.is_empty(), "{text}");
        for diagnostic in diagnostics {
            assert!(
                diagnostic["suggestedAction"]
                    .as_str()
                    .is_some_and(|action| !action.is_empty()),
                "{text}"
            );
        }
    }
}

/// Recursively copy a fixture tree (a handful of small files).
fn copy_fs(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_fs(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// Copy the committed workspace, write a runtime configuration whose
/// binding points at `base_url` with a basic credential drawn from the
/// two named environment variables, and set those variables. Returns the
/// directory guard with the project path inside it.
fn workspace(base_url: &str, user_var: &str, pass_var: &str) -> (tempfile::TempDir, String) {
    let (user, pass) = (
        format!("VERIFY_LIVE_USER_{user_var}"),
        format!("VERIFY_LIVE_PASS_{pass_var}"),
    );
    std::env::set_var(&user, "probe-user");
    std::env::set_var(&pass, "probe-pass");
    let root = tempfile::tempdir().unwrap();
    let copy = root.path().join("project");
    copy_fs(&fixture_dir(), &copy);
    let runtime = format!(
        "# The runtime the test writes: the binding's base URL is the\n\
         # double's loopback address, the credential the environment holds.\n\
         apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1\n\
         kind: AdapterRuntimeConfig\n\
         id: verify-demo\n\
         endpoints:\n  \
           - endpoint: verify-source\n    \
             baseUrl: {base_url}\n    \
             credential:\n      \
               type: basic\n      \
               usernameRef: secret:env/{user}\n      \
               passwordRef: secret:env/{pass}\n\
         allowedClients:\n  \
           - verify-client\n\
         allowedPrivateCidrs:\n  \
           - 10.0.0.0/8\n\
         listener:\n  \
           bind: 127.0.0.1:8080\n\
         database:\n  \
           runtimeUrlRef: secret:env/VERIFY_LIVE_DB_RUNTIME\n  \
           migrationUrlRef: secret:env/VERIFY_LIVE_DB_MIGRATION\n\
         oidc:\n  \
           issuer: https://issuer.example.invalid\n  \
           audience: verify-demo\n\
         audit:\n  \
           retentionDays: 90\n"
    );
    std::fs::write(copy.join("runtime.yaml"), runtime).unwrap();
    let project = copy.join("project.yaml").to_str().unwrap().to_owned();
    (root, project)
}

/// One scripted response of the double.
#[derive(Clone)]
struct Response {
    status: u16,
    body: &'static str,
    headers: Vec<(&'static str, String)>,
}

impl Response {
    fn json(status: u16, body: &'static str) -> Self {
        Self {
            status,
            body,
            headers: Vec::new(),
        }
    }

    #[cfg(feature = "tls-test")]
    fn redirect(location: String) -> Self {
        Self {
            status: 302,
            body: "",
            headers: vec![("Location", location)],
        }
    }
}

/// One request the double recorded, with its header names lowercased.
#[derive(Clone, Debug)]
struct RecordedRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    #[allow(dead_code)]
    body: Vec<u8>,
}

impl RecordedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// A loopback HTTP/1.1 double: real TCP, one request per connection,
/// `Connection: close`, the scripted answers in order, every request
/// recorded.
struct Double {
    port: u16,
    recorded: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl Double {
    fn start(answers: VecDeque<Response>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::clone(&recorded);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    break;
                };
                let shared = Arc::clone(&shared);
                let mut answers = answers.clone();
                thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
                    serve(&mut stream, &shared, &mut answers);
                });
            }
        });
        Self { port, recorded }
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.recorded.lock().unwrap().clone()
    }
}

/// A real loopback TLS server under a throwaway private CA. It uses the
/// synchronous rustls stream so the CLI can run its own Tokio transport on
/// the test thread without sharing an executor.
#[cfg(feature = "tls-test")]
struct TlsDouble {
    port: u16,
    ca_pem: String,
    recorded: Arc<Mutex<Vec<RecordedRequest>>>,
}

#[cfg(feature = "tls-test")]
impl TlsDouble {
    fn start(answers: VecDeque<Response>) -> Self {
        use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let mut authority =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("private CA parameters");
        authority.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let authority_key = rcgen::KeyPair::generate().expect("private CA key");
        let authority_certificate = authority
            .self_signed(&authority_key)
            .expect("private CA certificate");
        let server_key = rcgen::KeyPair::generate().expect("server key");
        let server = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()])
            .expect("server parameters")
            .signed_by(
                &server_key,
                &rcgen::Issuer::from_params(&authority, &authority_key),
            )
            .expect("the private CA signs the server certificate");
        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![server.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .expect("TLS server configuration");
        let listener = TcpListener::bind("127.0.0.1:0").expect("the TLS double binds");
        let port = listener.local_addr().expect("the TLS address").port();
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::clone(&recorded);
        let config = Arc::new(config);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else {
                    break;
                };
                let shared = Arc::clone(&shared);
                let config = Arc::clone(&config);
                let mut answers = answers.clone();
                thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
                    let Ok(connection) = tokio_rustls::rustls::ServerConnection::new(config) else {
                        return;
                    };
                    let mut stream = tokio_rustls::rustls::StreamOwned::new(connection, stream);
                    serve(&mut stream, &shared, &mut answers);
                });
            }
        });
        Self {
            port,
            ca_pem: pem_certificate(authority_certificate.der().as_ref()),
            recorded,
        }
    }

    fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.recorded.lock().unwrap().clone()
    }
}

#[cfg(feature = "tls-test")]
fn pem_certificate(der: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is text"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

#[cfg(feature = "tls-test")]
fn tls_workspace(
    double: &TlsDouble,
    trusted_ca: &str,
    suffix: &str,
) -> (tempfile::TempDir, String) {
    let (root, project) = workspace(&double.url(), suffix, suffix);
    let directory = Path::new(&project).parent().expect("project directory");
    let ca_path = directory.join("verify-ca.pem");
    std::fs::write(&ca_path, trusted_ca).expect("the CA bundle is written");
    let runtime_path = directory.join("runtime.yaml");
    let runtime = std::fs::read_to_string(&runtime_path).expect("the runtime is readable");
    let runtime = runtime.replacen(
        "    credential:\n",
        "    tlsTrustProfile: verify-ca\n    credential:\n",
        1,
    );
    let runtime = runtime.replacen(
        "allowedClients:\n",
        &format!(
            "outboundTls:\n  trustProfiles:\n    verify-ca:\n      caBundleFile: {}\nallowedClients:\n",
            ca_path.display()
        ),
        1,
    );
    std::fs::write(runtime_path, runtime).expect("the TLS runtime is written");
    (root, project)
}

/// Turn the pinned TLS workspace into an explicitly approved anonymous
/// HTTPS source, updating the project's byte pin exactly as an adopter must.
#[cfg(feature = "tls-test")]
fn anonymous_tls_workspace(
    double: &TlsDouble,
    trusted_ca: &str,
    suffix: &str,
) -> (tempfile::TempDir, String) {
    let (root, project) = tls_workspace(double, trusted_ca, suffix);
    let directory = Path::new(&project).parent().expect("project directory");
    let pack_path = directory.join("pack.yaml");
    let pack = std::fs::read_to_string(&pack_path)
        .expect("pack text")
        .replacen("      type: basic\n", "      type: none\n", 1);
    std::fs::write(&pack_path, &pack).expect("anonymous pack");
    let digest = registry_platform_config::sha256_uri(pack.as_bytes());
    let project_path = directory.join("project.yaml");
    let project_text = std::fs::read_to_string(&project_path).expect("project text");
    let project_text = project_text.replacen(
        "  digest: sha256:d4b1ed6a097dd6d452503abbf3c549de9b0d0f1ace05151c6112ccab14172c85\n",
        &format!("  digest: {digest}\n"),
        1,
    );
    std::fs::write(project_path, project_text).expect("anonymous project pin");

    let runtime_path = directory.join("runtime.yaml");
    let runtime = std::fs::read_to_string(&runtime_path).expect("runtime text");
    let runtime = runtime.replacen(
        &format!(
            "    credential:\n      type: basic\n      usernameRef: secret:env/VERIFY_LIVE_USER_{suffix}\n      passwordRef: secret:env/VERIFY_LIVE_PASS_{suffix}\n"
        ),
        "    anonymousHttps: operator-approved\n    credential:\n      type: none\n",
        1,
    );
    std::fs::write(runtime_path, runtime).expect("anonymous runtime");
    (root, project)
}

/// Read one request, answer it with the next scripted response (a 500
/// when the script is exhausted, a 400 when the request will not read),
/// and record what arrived.
fn serve<S: Read + Write>(
    stream: &mut S,
    recorded: &Mutex<Vec<RecordedRequest>>,
    answers: &mut VecDeque<Response>,
) {
    let request = match read_request(stream) {
        Some(request) => request,
        None => {
            write_response(stream, &Response::json(400, "unparseable request"));
            return;
        }
    };
    let answer = answers
        .pop_front()
        .unwrap_or_else(|| Response::json(500, "the script is exhausted"));
    write_response(stream, &answer);
    recorded.lock().unwrap().push(request);
}

/// Read one HTTP/1.1 request head (bounded) plus its content-length body.
fn read_request(stream: &mut impl Read) -> Option<RecordedRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if buffer.len() > 64 * 1024 {
            return None;
        }
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(head_end) = find_subsequence(&buffer, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
            let mut lines = head.split("\r\n");
            let request_line = lines.next()?.to_owned();
            let mut method = String::new();
            let mut target = String::new();
            for (index, part) in request_line.split(' ').enumerate() {
                match index {
                    0 => method = part.to_owned(),
                    1 => target = part.to_owned(),
                    _ => break,
                }
            }
            let mut headers = Vec::new();
            let mut content_length = 0usize;
            for line in lines {
                if let Some((name, value)) = line.split_once(':') {
                    let name = name.trim().to_ascii_lowercase();
                    let value = value.trim().to_owned();
                    if name == "content-length" {
                        content_length = value.parse().ok()?;
                    }
                    headers.push((name, value));
                }
            }
            let mut body = buffer[head_end + 4..].to_vec();
            while body.len() < content_length {
                let read = stream.read(&mut chunk).ok()?;
                if read == 0 {
                    return None;
                }
                body.extend_from_slice(&chunk[..read]);
            }
            body.truncate(content_length);
            return Some(RecordedRequest {
                method,
                target,
                headers,
                body,
            });
        }
    }
}

fn write_response(stream: &mut impl Write, response: &Response) {
    let reason = match response.status {
        200 => "OK",
        302 => "Found",
        400 => "Bad Request",
        418 => "I'm a teapot",
        500 => "Internal Server Error",
        _ => "Status",
    };
    let mut head = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        response.body.len()
    );
    for (name, value) in &response.headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(response.body.as_bytes());
    let _ = stream.flush();
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// A loopback port with no listener behind it: bind, read the port, drop.
fn refused_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// A constant send drives the double with the credential the runtime
/// names, the placeholders filled from constants and the instantiation,
/// and the answer inside the send's declared range passes.
#[test]
fn a_constant_send_drives_the_double_and_passes() {
    let mut answers = VecDeque::new();
    answers.push_back(Response::json(200, r#"{"instances":[]}"#));
    let double = Double::start(answers);
    let (_root, project) = workspace(&format!("http://127.0.0.1:{}", double.port), "H", "H");
    let runtime = Path::new(&project).parent().unwrap().join("runtime.yaml");

    let (exit, report, _stderr) = run_json(&[
        "verify",
        "--live",
        &project,
        "--runtime",
        runtime.to_str().unwrap(),
    ]);

    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["command"], "verify");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["drove"], json!(1));
    assert_eq!(report["waited"], json!(0));
    assert_eq!(report["waits"], json!([]));
    assert_eq!(report["filesChecked"], json!(4));

    let requests = double.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let request = &requests[0];
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.target,
        "/api/cases/case?includeClosed=false&pageSize=1"
    );
    let expected = base64::engine::general_purpose::STANDARD.encode("probe-user:probe-pass");
    assert_eq!(
        request.header("authorization"),
        Some(format!("Basic {expected}").as_str())
    );
    assert_eq!(
        request.header("host"),
        Some(format!("127.0.0.1:{}", double.port).as_str())
    );
}

/// An answer outside the send's declared range refuses with the range
/// named, and no credential value reaches the report.
#[test]
fn an_answer_outside_the_declared_range_refuses() {
    let mut answers = VecDeque::new();
    answers.push_back(Response::json(418, r#"{"detail":"teapot"}"#));
    let double = Double::start(answers);
    let (_root, project) = workspace(&format!("http://127.0.0.1:{}", double.port), "R", "R");
    let runtime = Path::new(&project).parent().unwrap().join("runtime.yaml");

    let (exit, report, stderr) = run_json(&[
        "verify",
        "--live",
        &project,
        "--runtime",
        runtime.to_str().unwrap(),
    ]);

    assert_eq!(exit, ExitCode::from(1));
    assert_eq!(report["ok"], json!(false));
    let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
    let finding = diagnostics
        .iter()
        .find(|finding| finding["code"] == json!("adapterctl.verify.status-outside-range"))
        .expect("the range finding");
    assert_eq!(finding["path"], json!("/bindings/0"));
    let message = finding["message"].as_str().expect("message");
    assert!(message.contains("418"), "{message}");
    assert!(message.contains("200-299"), "{message}");

    let expected = base64::engine::general_purpose::STANDARD.encode("probe-user:probe-pass");
    let stdout = report.to_string();
    assert!(!stdout.contains(&expected), "{stdout}");
    assert!(!stdout.contains("probe-pass"), "{stdout}");
    let stderr = String::from_utf8_lossy(&stderr);
    assert!(!stderr.contains(&expected), "{stderr}");
    assert!(!stderr.contains("probe-pass"), "{stderr}");
}

/// A dial no one answers is an operational failure naming the endpoint,
/// never the destination or a credential value.
#[test]
fn a_transport_failure_is_an_operational_failure() {
    let port = refused_port();
    let (_root, project) = workspace(&format!("http://127.0.0.1:{port}"), "T", "T");
    let runtime = Path::new(&project).parent().unwrap().join("runtime.yaml");

    let (exit, report, _stderr) = run_json(&[
        "verify",
        "--live",
        &project,
        "--runtime",
        runtime.to_str().unwrap(),
    ]);

    assert_eq!(exit, ExitCode::from(3));
    let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
    let finding = diagnostics
        .iter()
        .find(|finding| finding["code"] == json!("adapterctl.verify.transport"))
        .expect("the transport finding");
    let message = finding["message"].as_str().expect("message");
    assert!(message.contains("verify-source"), "{message}");
    assert!(!message.contains("127.0.0.1"), "{message}");
    assert!(!message.contains(&port.to_string()), "{message}");
}

/// A default build applies production HTTPS policy, which refuses a
/// loopback origin before any connection attempt.
#[cfg(not(feature = "tls-test"))]
#[test]
fn production_https_refuses_a_loopback_origin() {
    let port = refused_port();
    let (_root, project) = workspace(&format!("https://127.0.0.1:{port}"), "S", "S");
    let runtime = Path::new(&project).parent().unwrap().join("runtime.yaml");

    let (exit, report, _stderr) = run_json(&[
        "verify",
        "--live",
        &project,
        "--runtime",
        runtime.to_str().unwrap(),
    ]);

    assert_eq!(exit, ExitCode::from(1), "{report}");
    let finding = report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .find(|finding| finding["code"] == "adapterctl.verify.insecure-origin")
        .expect("the destination policy refusal");
    let message = finding["message"].as_str().expect("message");
    assert!(!message.contains("127.0.0.1"), "{message}");
    assert!(!message.contains(&port.to_string()), "{message}");
}

#[cfg(feature = "tls-test")]
#[test]
fn configured_private_ca_drives_a_real_https_probe() {
    let mut answers = VecDeque::new();
    answers.push_back(Response::json(200, r#"{"instances":[]}"#));
    let double = TlsDouble::start(answers);
    let (_root, project) = tls_workspace(&double, &double.ca_pem, "TLS_TRUSTED");
    let runtime = Path::new(&project).parent().unwrap().join("runtime.yaml");

    let (exit, report, _stderr) = run_json(&[
        "verify",
        "--live",
        &project,
        "--runtime",
        runtime.to_str().unwrap(),
    ]);

    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["drove"], json!(1), "{report}");
    assert_eq!(report["waited"], json!(0), "{report}");
    for _ in 0..50 {
        if !double.requests().is_empty() {
            break;
        }
        thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(double.requests().len(), 1);
}

/// The named acknowledgement admits exactly the pinned HTTPS source. The
/// real TLS probe verifies the private CA and sends no source credential or
/// caller-token header.
#[cfg(feature = "tls-test")]
#[test]
fn approved_anonymous_https_verifies_tls_without_authentication_headers() {
    let mut answers = VecDeque::new();
    answers.push_back(Response::json(200, r#"{"instances":[]}"#));
    let double = TlsDouble::start(answers);
    let (_root, project) = anonymous_tls_workspace(&double, &double.ca_pem, "TLS_ANONYMOUS");
    let runtime = Path::new(&project).parent().unwrap().join("runtime.yaml");

    let (exit, report, _stderr) = run_json(&[
        "verify",
        "--live",
        &project,
        "--runtime",
        runtime.to_str().unwrap(),
    ]);

    assert_eq!(exit, ExitCode::SUCCESS, "{report}");
    assert_eq!(report["drove"], json!(1), "{report}");
    for _ in 0..50 {
        if !double.requests().is_empty() {
            break;
        }
        thread::sleep(std::time::Duration::from_millis(10));
    }
    let requests = double.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(requests[0].header("authorization"), None);
    assert_eq!(requests[0].header("proxy-authorization"), None);
    assert_eq!(requests[0].header("cookie"), None);
}

/// The acknowledgement never weakens certificate verification. Trusting an
/// unrelated synthetic CA completes no HTTP request.
#[cfg(feature = "tls-test")]
#[test]
fn approved_anonymous_https_refuses_an_untrusted_certificate() {
    let mut answers = VecDeque::new();
    answers.push_back(Response::json(200, r#"{"instances":[]}"#));
    let destination = TlsDouble::start(answers);
    let unrelated = TlsDouble::start(VecDeque::new());
    let (_root, project) =
        anonymous_tls_workspace(&destination, &unrelated.ca_pem, "TLS_ANON_UNTRUSTED");
    let runtime = Path::new(&project).parent().unwrap().join("runtime.yaml");

    let (exit, report, _stderr) = run_json(&[
        "verify",
        "--live",
        &project,
        "--runtime",
        runtime.to_str().unwrap(),
    ]);

    assert_eq!(exit, ExitCode::from(3), "{report}");
    assert!(report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .any(|finding| finding["code"] == "adapterctl.verify.transport"));
    assert!(destination.requests().is_empty());
}

#[cfg(feature = "tls-test")]
#[test]
fn an_untrusted_private_ca_is_rejected_before_an_http_request() {
    let mut answers = VecDeque::new();
    answers.push_back(Response::json(200, r#"{"instances":[]}"#));
    let destination = TlsDouble::start(answers);
    let unrelated = TlsDouble::start(VecDeque::new());
    let (_root, project) = tls_workspace(&destination, &unrelated.ca_pem, "TLS_UNTRUSTED");
    let runtime = Path::new(&project).parent().unwrap().join("runtime.yaml");

    let (exit, report, _stderr) = run_json(&[
        "verify",
        "--live",
        &project,
        "--runtime",
        runtime.to_str().unwrap(),
    ]);

    assert_eq!(exit, ExitCode::from(3), "{report}");
    assert!(report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .any(|finding| finding["code"] == "adapterctl.verify.transport"));
    assert!(destination.requests().is_empty());
    let text = report.to_string();
    assert!(!text.contains(&destination.port.to_string()), "{text}");
    assert!(!text.contains("BEGIN CERTIFICATE"), "{text}");
}

#[cfg(feature = "tls-test")]
#[test]
fn an_https_redirect_is_returned_without_fallthrough() {
    let redirect_target = Double::start(VecDeque::new());
    let location = format!("http://127.0.0.1:{}/redirected", redirect_target.port);
    let mut answers = VecDeque::new();
    answers.push_back(Response::redirect(location));
    let destination = TlsDouble::start(answers);
    let (_root, project) = tls_workspace(&destination, &destination.ca_pem, "TLS_REDIRECT");
    let runtime = Path::new(&project).parent().unwrap().join("runtime.yaml");

    let (exit, report, _stderr) = run_json(&[
        "verify",
        "--live",
        &project,
        "--runtime",
        runtime.to_str().unwrap(),
    ]);

    assert_eq!(exit, ExitCode::from(1), "{report}");
    assert!(report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .any(|finding| finding["code"] == "adapterctl.verify.status-outside-range"));
    assert!(redirect_target.requests().is_empty());
}

/// The command refuses its own misuse through the usage exit.
#[test]
fn verify_requires_the_live_flag_and_a_runtime() {
    let (_root_a, project_a) = workspace("http://127.0.0.1:9", "U1", "U1");
    let runtime_a = Path::new(&project_a).parent().unwrap().join("runtime.yaml");

    let (exit, report, _stderr) = run_json(&[
        "verify",
        &project_a,
        "--runtime",
        runtime_a.to_str().unwrap(),
    ]);
    assert_eq!(exit, ExitCode::from(2));
    assert_eq!(report["command"], "usage");

    let (exit, report, _stderr) = run_json(&["verify", "--live", &project_a]);
    assert_eq!(exit, ExitCode::from(2));
    assert_eq!(report["command"], "usage");
}
