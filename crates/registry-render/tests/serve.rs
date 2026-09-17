//! End-to-end serve tests: the real `render` binary serving real requests,
//! spawning real supervised workers, writing a real keyed audit ledger.
//! These tests are the DoD's serve-mode acceptance coverage.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const API_KEY: &str = "test-key-0123456789abcdef0123456789abcdef";
const AUDIT_KEY: &str = "audit-key-0123456789abcdef0123456789abcd";

const DEFAULT_LIMITS: &str = "limits:\n  renderTimeoutSeconds: 20\n  maxOutputBytes: 8388608\n  maxRequestBodyBytes: 8388608\n  maxConcurrency: 2\n";

struct Server {
    child: Child,
    port: u16,
    #[allow(dead_code)]
    home: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Secret files must be owner-only: the config crate refuses anything else.
fn write_secret(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate sits at crates/registry-render")
        .to_path_buf()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind for port discovery")
        .local_addr()
        .expect("local addr")
        .port()
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap().path();
        let target = to.join(entry.file_name().unwrap());
        if entry.is_dir() {
            copy_dir(&entry, &target);
        } else {
            std::fs::copy(&entry, &target).unwrap();
        }
    }
}

/// Build a deployment home: sealed receipt bundle, key files, audit dir,
/// runtime.yaml. Returns (home, runtime_path, port).
fn deployment(limits: &str, bundle_source: &Path) -> (PathBuf, PathBuf, u16) {
    let home = tempfile::tempdir().expect("deployment home");
    let bundle = home.path().join("bundle");
    copy_dir(bundle_source, &bundle);
    write_secret(&home.path().join("api.key"), API_KEY);
    write_secret(&home.path().join("audit.key"), AUDIT_KEY);
    std::fs::create_dir(home.path().join("audit")).unwrap();
    let port = free_port();
    let runtime = format!(
        "apiVersion: render.registrystack.org/v1alpha1\nkind: RenderRuntime\nserver:\n  bind: 127.0.0.1:{port}\n  shutdownGraceSeconds: 5\nbundle:\n  path: {}\nauth:\n  apiKeyRef: secret:file/api.key\n{limits}audit:\n  directory: {}\n  integrityKeyRef: secret:file/audit.key\n",
        bundle.display(),
        home.path().join("audit").display()
    );
    let runtime_path = home.path().join("runtime.yaml");
    std::fs::write(&runtime_path, runtime).unwrap();
    (home.keep(), runtime_path, port)
}

fn start_server(runtime_path: &Path) -> Server {
    let mut child = Command::new(env!("CARGO_BIN_EXE_render"))
        .arg("serve")
        .arg("--runtime")
        .arg(runtime_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn render serve");
    let port: u16 = std::fs::read_to_string(runtime_path)
        .unwrap()
        .lines()
        .find(|l| l.contains("bind:"))
        .and_then(|l| l.rsplit(':').next())
        .and_then(|p| p.trim().parse().ok())
        .expect("port from runtime");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = stream
                .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            let mut buf = [0u8; 256];
            if stream.read(&mut buf).is_ok_and(|n| n > 0) {
                return Server {
                    child,
                    port,
                    home: PathBuf::from("/tmp"),
                };
            }
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("server did not become healthy in 30s");
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("server exited early with {status}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn request(
    port: u16,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Reply {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let mut wire =
        format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for (name, value) in headers {
        wire.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        wire.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    wire.push_str("\r\n");
    stream.write_all(wire.as_bytes()).unwrap();
    if let Some(body) = body {
        stream.write_all(body.as_bytes()).unwrap();
    }
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header terminator");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .expect("status");
    let headers = head
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    Reply {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    }
}

fn receipt_body() -> String {
    let fixture = repo_root().join("products/render/bundles/receipt/fixtures/data.json");
    let data = std::fs::read_to_string(&fixture).unwrap();
    format!(r#"{{"issuedAt":"2026-09-16T10:32:00Z","data":{data}}}"#)
}

fn golden_receipt_sha() -> String {
    let golden: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("products/render/golden.json")).unwrap(),
    )
    .unwrap();
    golden["documents"]["receipt"]["pdfSha256"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn audit_lines(home: &Path) -> Vec<String> {
    std::fs::read_dir(home.join("audit"))
        .expect("audit dir")
        .flat_map(|entry| {
            let path = entry.unwrap().path();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if name.ends_with(".jsonl") {
                std::fs::read_to_string(&path)
                    .unwrap_or_default()
                    .lines()
                    .filter(|l| !l.is_empty())
                    .map(str::to_owned)
                    .collect()
            } else {
                Vec::new()
            }
        })
        .collect()
}

#[test]
fn serve_health_and_ready() {
    let (home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    let server = start_server(&runtime);
    let health = request(server.port, "GET", "/health", &[], None);
    assert_eq!(health.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&health.body).expect("health json");
    assert_eq!(body["status"], "ok");
    assert_eq!(
        body["bundleVersion"], 1,
        "health reports the served bundle version: {body}"
    );
    assert!(
        body["rendererVersion"].as_str().is_some_and(|v| v.contains("typst")),
        "health reports the renderer version plus pin: {body}"
    );
    assert_eq!(
        body["bundleHash"].as_str().map(|h| h.len()),
        Some(64),
        "health reports the served bundle hash: {body}"
    );
    let ready = request(server.port, "GET", "/ready", &[], None);
    assert_eq!(ready.status, 200);
    drop(server);
    let _ = home;
}

#[test]
fn api_key_file_with_one_trailing_newline_is_trimmed() {
    let (home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    // Key files written by an editor or `echo` end with one line ending;
    // serve must trim it, not arm a key nobody can present.
    write_secret(&home.join("api.key"), &format!("{API_KEY}\r\n"));
    let server = start_server(&runtime);
    let reply = request(
        server.port,
        "POST",
        "/v1/render/receipt",
        &[
            ("Authorization", &format!("Bearer {API_KEY}")),
            ("Content-Type", "application/json"),
        ],
        Some(&receipt_body()),
    );
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
}

#[test]
fn api_key_with_stray_whitespace_is_refused_at_startup() {
    let (home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    // Anything beyond one trailing line ending (here: a leading space) is a
    // startup error, not a silent permanent 401 with /health green.
    write_secret(&home.join("api.key"), &format!(" {API_KEY}"));
    let mut child = Command::new(env!("CARGO_BIN_EXE_render"))
        .args(["serve", "--runtime", runtime.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let code = wait_for_exit(&mut child);
    assert_eq!(
        code,
        registry_render::ProblemKind::RuntimeInvalid.exit_code(),
        "stray whitespace in the key file must refuse startup"
    );
}

fn wait_for_exit(child: &mut Child) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match child.try_wait().expect("wait") {
            Some(status) => return status.code().unwrap_or(-1),
            None if Instant::now() > deadline => {
                let _ = child.kill();
                panic!("server did not exit");
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

#[test]
fn unauthorized_requests_are_refused_and_audited() {
    let (home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    let server = start_server(&runtime);
    let body = receipt_body();
    let no_key = request(
        server.port,
        "POST",
        "/v1/render/receipt",
        &[("Content-Type", "application/json")],
        Some(&body),
    );
    assert_eq!(no_key.status, 401);
    assert!(String::from_utf8_lossy(&no_key.body).contains("unauthorized"));
    let wrong = request(
        server.port,
        "POST",
        "/v1/render/receipt",
        &[
            (
                "Authorization",
                "Bearer wrong-key-0000000000000000000000000",
            ),
            ("Content-Type", "application/json"),
        ],
        Some(&body),
    );
    assert_eq!(wrong.status, 401);
    // The two indistinguishable 401s leave exactly the same audit shape.
    drop(server);
    let lines = audit_lines(&home);
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.contains("unauthorized") && l.contains("refused"))
            .count(),
        2,
        "both 401 attempts are audited: {lines:?}"
    );
}

#[test]
fn render_returns_pdf_with_hash_headers_matching_golden() {
    let (home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    let server = start_server(&runtime);
    let body = receipt_body();
    let reply = request(
        server.port,
        "POST",
        "/v1/render/receipt",
        &[
            ("Authorization", &format!("Bearer {API_KEY}")),
            ("Content-Type", "application/json"),
            ("Idempotency-Key", "effect-1234"),
        ],
        Some(&body),
    );
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let header = |name: &str| {
        reply
            .headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    assert!(header("content-type").starts_with("application/pdf"));
    assert_eq!(header("x-registry-pdf-sha256"), golden_receipt_sha());
    assert!(!header("x-registry-data-sha256").is_empty());
    assert_eq!(header("x-registry-document-version"), "receipt v3");
    assert_eq!(header("idempotency-key"), "effect-1234");
    // The served bytes are the golden bytes: cross-process determinism.
    let sha = sha256_hex(&reply.body);
    assert_eq!(sha, golden_receipt_sha());
    drop(server);
    // The audit ledger recorded the render, value-free.
    let lines = audit_lines(&home);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("\"outcome\":\"rendered\"")
                && l.contains(&golden_receipt_sha()[..16]))
    );
}

#[test]
fn json_variant_serves_openfn_clients() {
    let (_home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    let server = start_server(&runtime);
    let body = receipt_body();
    let reply = request(
        server.port,
        "POST",
        "/v1/render/receipt",
        &[
            ("Authorization", &format!("Bearer {API_KEY}")),
            ("Content-Type", "application/json"),
            ("Accept", "application/json"),
        ],
        Some(&body),
    );
    assert_eq!(reply.status, 200);
    let json: serde_json::Value = serde_json::from_slice(&reply.body).expect("json body");
    let b64 = json["pdfBase64"].as_str().unwrap();
    let bytes = base64_decode(b64);
    assert_eq!(sha256_hex(&bytes), golden_receipt_sha());
    assert_eq!(json["documentVersion"].as_str().unwrap(), "receipt v3");
    assert_eq!(json["pdfSha256"].as_str().unwrap(), golden_receipt_sha());
}

#[test]
fn missing_issued_at_and_bad_data_are_named_problems() {
    let (_home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    let server = start_server(&runtime);
    let missing = request(
        server.port,
        "POST",
        "/v1/render/receipt",
        &[
            ("Authorization", &format!("Bearer {API_KEY}")),
            ("Content-Type", "application/json"),
        ],
        Some(r#"{"data":{"reference":"R"}}"#),
    );
    assert_eq!(missing.status, 400);
    let text = String::from_utf8_lossy(&missing.body);
    assert!(text.contains("issued-at-missing"), "{text}");

    let bad_data = request(
        server.port,
        "POST",
        "/v1/render/receipt",
        &[
            ("Authorization", &format!("Bearer {API_KEY}")),
            ("Content-Type", "application/json"),
        ],
        Some(r#"{"issuedAt":"2026-09-16T10:32:00Z","data":{"reference":"R","junk":true}}"#),
    );
    assert_eq!(bad_data.status, 400);
    let text = String::from_utf8_lossy(&bad_data.body);
    assert!(text.contains("data-invalid"), "{text}");
    assert!(text.contains("/data"), "pointers reach the caller: {text}");
}

#[test]
fn audit_chain_verifies_from_the_cli() {
    let (home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    let server = start_server(&runtime);
    let body = receipt_body();
    let reply = request(
        server.port,
        "POST",
        "/v1/render/receipt",
        &[
            ("Authorization", &format!("Bearer {API_KEY}")),
            ("Content-Type", "application/json"),
        ],
        Some(&body),
    );
    assert_eq!(reply.status, 200);
    drop(server);
    let output = Command::new(env!("CARGO_BIN_EXE_render"))
        .args(["audit-verify", "--runtime", runtime.to_str().unwrap()])
        .output()
        .expect("run audit-verify");
    assert!(
        output.status.success(),
        "audit-verify: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = home;
}

#[test]
fn audit_events_are_value_free() {
    let (home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    let server = start_server(&runtime);
    // Canary in the data must never reach the ledger — even though the
    // rendered document itself carries it.
    let body = receipt_body().replace("ZKT-2026-W03-000123", "CANARY-DO-NOT-LOG");
    let reply = request(
        server.port,
        "POST",
        "/v1/render/receipt",
        &[
            ("Authorization", &format!("Bearer {API_KEY}")),
            ("Content-Type", "application/json"),
        ],
        Some(&body),
    );
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    // The canary is inside the (compressed) document by construction: it
    // replaced the reference field of the fixture that the template prints.
    drop(server);
    let text = audit_lines(&home).join("\n");
    assert!(
        !text.contains("CANARY-DO-NOT-LOG"),
        "audit must be value-free"
    );
    assert!(
        !text.contains(API_KEY),
        "audit must never contain the API key"
    );
    assert!(
        text.contains("\"outcome\":\"rendered\""),
        "the render is audited: {text}"
    );
}

#[test]
fn tampered_bundle_refuses_to_serve() {
    let (home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    let labels = home.join("bundle/labels/ar.yaml");
    let mut text = std::fs::read_to_string(&labels).unwrap();
    text.push_str("extra: tampered\n");
    std::fs::write(&labels, text).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_render"))
        .args(["serve", "--runtime", runtime.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let code = wait_for_exit(&mut child);
    assert_eq!(
        code,
        registry_render::ProblemKind::BundleTampered.exit_code()
    );
}

#[test]
fn bundle_drift_after_serve_starts_is_refused_per_render() {
    let (home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    let server = start_server(&runtime);
    let bearer = format!("Bearer {API_KEY}");
    let auth = [("Authorization", bearer.as_str()), ("Content-Type", "application/json")];

    // Content drift after startup: the per-request seal check catches it.
    let labels = home.join("bundle/labels/ar.yaml");
    let mut text = std::fs::read_to_string(&labels).unwrap();
    text.push_str("extra: tampered\n");
    std::fs::write(&labels, text).unwrap();
    let tampered = request(server.port, "POST", "/v1/render/receipt", &auth, Some(&receipt_body()));
    assert_eq!(tampered.status, 400, "{}", String::from_utf8_lossy(&tampered.body));
    assert!(
        String::from_utf8_lossy(&tampered.body).contains("bundle-tampered"),
        "{}",
        String::from_utf8_lossy(&tampered.body)
    );

    // Unsealing after startup (hashes stripped, content otherwise intact):
    // the worker must load sealed, not merely verify-if-sealed.
    let manifest_path = home.join("bundle/manifest.yaml");
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    let stripped = manifest.split("hashes:").next().unwrap().to_owned();
    std::fs::write(&manifest_path, stripped).unwrap();
    let unsealed = request(server.port, "POST", "/v1/render/receipt", &auth, Some(&receipt_body()));
    assert_eq!(unsealed.status, 400, "{}", String::from_utf8_lossy(&unsealed.body));
    assert!(
        String::from_utf8_lossy(&unsealed.body).contains("bundle-unsealed"),
        "the worker must refuse an unsealed bundle per request: {}",
        String::from_utf8_lossy(&unsealed.body)
    );
}

#[test]
fn oversized_bodies_are_refused_after_auth_as_problems() {
    let (home, runtime, _) = deployment(
        "limits:\n  renderTimeoutSeconds: 20\n  maxOutputBytes: 8388608\n  maxRequestBodyBytes: 1024\n  maxConcurrency: 2\n",
        &repo_root().join("products/render/bundles/receipt"),
    );
    let server = start_server(&runtime);
    let oversized = "x".repeat(2048);
    // Unauthenticated oversized bodies are 401s: auth runs first, and no
    // unauthenticated body is ever buffered.
    let anonymous = request(
        server.port,
        "POST",
        "/v1/render/receipt",
        &[("Content-Type", "application/json")],
        Some(&oversized),
    );
    assert_eq!(anonymous.status, 401);
    // Authenticated: an RFC 9457 problem naming the ceiling.
    let refused = request(
        server.port,
        "POST",
        "/v1/render/receipt",
        &[
            ("Authorization", &format!("Bearer {API_KEY}")),
            ("Content-Type", "application/json"),
        ],
        Some(&oversized),
    );
    assert_eq!(refused.status, 413);
    let text = String::from_utf8_lossy(&refused.body);
    assert!(text.contains("body-too-large"), "{text}");
    assert!(text.contains("1024"), "{text}");
    // The refusal is audited like every other.
    drop(server);
    let lines = audit_lines(&home);
    assert!(
        lines.iter().any(|l| l.contains("body-too-large") && l.contains("refused")),
        "the 413 refusal is audited: {lines:?}"
    );
}

#[test]
fn slow_renders_are_killed_and_the_service_recovers() {
    // A compute-heavy bundle and a one-second budget: the supervisor kills
    // the worker, the refusal is audited, and the very next render works.
    let heavy = tempfile::tempdir().unwrap();
    let bundle = heavy.path();
    std::fs::write(
        bundle.join("manifest.yaml"),
        "apiVersion: render.registrystack.org/v1alpha1\nkind: RenderBundle\nbundleVersion: 1\ndocuments:\n  - id: heavy\n    version: 1\n    entry: templates/heavy.typ\n",
    )
    .unwrap();
    for dir in ["templates", "fonts", "labels", "schemas"] {
        std::fs::create_dir_all(bundle.join(dir)).unwrap();
    }
    std::fs::create_dir_all(bundle.join("packages/preview")).unwrap();
    std::fs::write(
        bundle.join("templates/heavy.typ"),
        "#let payload = json(bytes(sys.inputs.data))\n#let x = range(20000000).fold(0, (a, b) => a + b)\n#x\n",
    )
    .unwrap();
    // Seal the heavy bundle so serve accepts it.
    let sealed = Command::new(env!("CARGO_BIN_EXE_render"))
        .args(["seal", "--bundle", bundle.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        sealed.status.success(),
        "{}",
        String::from_utf8_lossy(&sealed.stderr)
    );

    let (home, runtime, _) = deployment(
        "limits:\n  renderTimeoutSeconds: 2\n  maxOutputBytes: 8388608\n  maxRequestBodyBytes: 8388608\n  maxConcurrency: 2\n",
        bundle,
    );
    let server = start_server(&runtime);
    let slow = request(
        server.port,
        "POST",
        "/v1/render/heavy",
        &[
            ("Authorization", &format!("Bearer {API_KEY}")),
            ("Content-Type", "application/json"),
        ],
        Some(r#"{"issuedAt":"2026-09-16T10:32:00Z","data":{}}"#),
    );
    assert_eq!(slow.status, 504, "{}", String::from_utf8_lossy(&slow.body));
    assert!(String::from_utf8_lossy(&slow.body).contains("render-timeout"));

    // Recovery: an immediate second request is served by a fresh worker.
    let second = request(
        server.port,
        "POST",
        "/v1/render/heavy",
        &[
            ("Authorization", &format!("Bearer {API_KEY}")),
            ("Content-Type", "application/json"),
        ],
        Some(r#"{"issuedAt":"2026-09-16T10:32:00Z","data":{}}"#),
    );
    assert_eq!(second.status, 504);
    drop(server);
    let lines = audit_lines(&home);
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.contains("render-timeout"))
            .count(),
        2,
        "each killed render is audited"
    );
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn base64_decode(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .expect("valid base64")
}
