//! End-to-end serve tests: the real `registry-render` binary serving real
//! requests, spawning real supervised workers, writing a real audit file
//! through the platform audit writer. These tests are the DoD's serve-mode
//! acceptance coverage.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

const API_KEY: &str = "test-key-0123456789abcdef0123456789abcdef";

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

fn physical_tempdir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().canonicalize().expect("physical tempdir path");
    (dir, path)
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

/// Build a deployment home: sealed receipt bundle, key file, audit dir,
/// runtime.yaml. Returns (home, runtime_path, port).
fn deployment(limits: &str, bundle_source: &Path) -> (PathBuf, PathBuf, u16) {
    let (home_guard, home) = physical_tempdir();
    let bundle = home.join("bundle");
    copy_dir(bundle_source, &bundle);
    write_secret(&home.join("api.key"), API_KEY);
    std::fs::create_dir(home.join("audit")).unwrap();
    let port = free_port();
    let runtime = format!(
        "apiVersion: render.registrystack.org/v1alpha1\nkind: RenderRuntime\nserver:\n  bind: 127.0.0.1:{port}\n  shutdownGraceSeconds: 5\nbundle:\n  path: {}\nauth:\n  apiKeyRef: secret:file/api.key\n{limits}audit:\n  path: {}\n",
        bundle.display(),
        audit_file(&home).display()
    );
    let runtime_path = home.join("runtime.yaml");
    std::fs::write(&runtime_path, runtime).unwrap();
    let _ = home_guard.keep();
    (home, runtime_path, port)
}

fn audit_file(home: &Path) -> PathBuf {
    home.join("audit").join("render.jsonl")
}

/// Point a deployment's audit at standard output instead of its file.
fn audit_to_stdout(home: &Path, runtime_path: &Path) {
    let text = std::fs::read_to_string(runtime_path).unwrap();
    let text = text.replace(
        &format!("  path: {}\n", audit_file(home).display()),
        "  destination: stdout\n",
    );
    assert!(text.contains("destination: stdout"), "{text}");
    std::fs::write(runtime_path, text).unwrap();
}

fn start_server(runtime_path: &Path) -> Server {
    start_server_at(runtime_path, None)
}

fn start_server_at(runtime_path: &Path, current_dir: Option<&Path>) -> Server {
    spawn_server(runtime_path, current_dir, Stdio::null())
}

/// Start a server whose standard output the test reads: the audit stream
/// of a `stdout` destination.
fn start_server_with_stdout(runtime_path: &Path) -> (Server, ChildStdout) {
    let mut server = spawn_server(runtime_path, None, Stdio::piped());
    let stdout = server.child.stdout.take().expect("piped stdout");
    (server, stdout)
}

fn spawn_server(runtime_path: &Path, current_dir: Option<&Path>, stdout: Stdio) -> Server {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-render"));
    command
        .arg("serve")
        .arg("--runtime")
        .arg(runtime_path)
        .stdout(stdout)
        .stderr(Stdio::null());
    if let Some(dir) = current_dir {
        command.current_dir(dir);
    }
    let mut child = command.spawn().expect("spawn registry-render serve");
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
        body["rendererVersion"]
            .as_str()
            .is_some_and(|v| v.contains("typst")),
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
fn relative_runtime_paths_anchor_to_the_runtime_files_directory() {
    // The natural deployment layout: runtime file and key files together in
    // deploy/, bundle and audit as siblings one level up. Every path in the
    // runtime file is relative to it, so the file works from any working
    // directory — before anchoring, a relative audit directory killed serve
    // at startup and a relative bundle path silently depended on the CWD.
    let (_home_guard, home) = physical_tempdir();
    let bundle = home.join("bundle");
    copy_dir(
        &repo_root().join("products/render/bundles/receipt"),
        &bundle,
    );
    let deploy = home.join("deploy");
    std::fs::create_dir_all(&deploy).unwrap();
    write_secret(&deploy.join("api.key"), API_KEY);
    std::fs::create_dir(home.join("audit")).unwrap();
    let port = free_port();
    std::fs::write(
        deploy.join("runtime.yaml"),
        format!(
            "apiVersion: render.registrystack.org/v1alpha1\nkind: RenderRuntime\nserver:\n  bind: 127.0.0.1:{port}\nbundle:\n  path: ../bundle\nauth:\n  apiKeyRef: secret:file/api.key\naudit:\n  path: ../audit/render.jsonl\n"
        ),
    )
    .unwrap();
    let elsewhere = tempfile::tempdir().expect("unrelated working directory");
    let server = start_server_at(&deploy.join("runtime.yaml"), Some(elsewhere.path()));
    let health = request(server.port, "GET", "/health", &[], None);
    assert_eq!(health.status, 200);
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
    drop(server);
    let lines = audit_lines(&home);
    assert!(
        lines.iter().any(|l| l.contains("\"outcome\":\"rendered\"")),
        "the render was audited into the anchored audit file: {lines:?}"
    );
}

#[test]
fn api_key_file_with_one_trailing_newline_is_trimmed() {
    let (home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    // Key files written by an editor or `echo` end with one line ending;
    // serve must trim it, not arm a key nobody can present. Both endings
    // count: bare LF is what a Linux deployment writes.
    for ending in ["\n", "\r\n"] {
        write_secret(&home.join("api.key"), &format!("{API_KEY}{ending}"));
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
            "key file ending in {ending:?}: {}",
            String::from_utf8_lossy(&reply.body)
        );
    }
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
    let mut child = Command::new(env!("CARGO_BIN_EXE_registry-render"))
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

#[test]
fn problem_details_are_bounded() {
    let (_home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    let server = start_server(&runtime);
    // Some refusals name the offending request field: an undeclared locale,
    // a badly named asset. The caller controls the length of those values,
    // so the detail must be capped rather than echoed in full.
    let locale = "x".repeat(50_000);
    let data = std::fs::read_to_string(
        repo_root().join("products/render/bundles/receipt/fixtures/data.json"),
    )
    .unwrap();
    let reply = request(
        server.port,
        "POST",
        "/v1/render/receipt",
        &[
            ("Authorization", &format!("Bearer {API_KEY}")),
            ("Content-Type", "application/json"),
        ],
        Some(&format!(
            r#"{{"locale":"{locale}","issuedAt":"2026-09-16T10:32:00Z","data":{data}}}"#
        )),
    );
    let body = String::from_utf8_lossy(&reply.body).into_owned();
    assert_eq!(reply.status, 400, "{body}");
    let problem: serde_json::Value = serde_json::from_str(&body).expect("problem json");
    let detail = problem["detail"].as_str().expect("detail");
    assert!(
        detail.chars().count() <= 2_048,
        "the detail is capped, found {} characters",
        detail.chars().count()
    );
    assert!(
        detail.ends_with("[truncated]"),
        "a capped detail says so: {detail}"
    );
}

#[test]
fn a_refused_bind_is_caught_before_startup_touches_the_filesystem() {
    let (home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    // A public bind is refused. The refusal must land before the startup
    // steps with side effects, so a misconfigured deployment leaves no
    // half-made state behind: here, a created audit directory.
    let audit = home.join("audit-elsewhere");
    let text = std::fs::read_to_string(&runtime).unwrap();
    let text = text.replace("bind: 127.0.0.1:", "bind: 0.0.0.0:").replace(
        &format!("path: {}", audit_file(&home).display()),
        &format!("path: {}", audit.join("render.jsonl").display()),
    );
    std::fs::write(&runtime, text).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_registry-render"))
        .args(["serve", "--runtime", runtime.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let code = wait_for_exit(&mut child);
    assert_eq!(
        code,
        registry_render::ProblemKind::RuntimeInvalid.exit_code(),
        "a public bind must refuse startup"
    );
    assert!(
        !audit.exists(),
        "startup must not create the audit directory before the bind is accepted"
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
    // The audit file recorded the render, value-free.
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
fn a_render_writes_a_request_entry_then_a_response_entry_sharing_correlation() {
    let (home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    let server = start_server(&runtime);
    let body = receipt_body();
    for key in [Some("effect-1234"), None] {
        let bearer = format!("Bearer {API_KEY}");
        let mut headers = vec![
            ("Authorization", bearer.as_str()),
            ("Content-Type", "application/json"),
        ];
        if let Some(key) = key {
            headers.push(("Idempotency-Key", key));
        }
        let reply = request(
            server.port,
            "POST",
            "/v1/render/receipt",
            &headers,
            Some(&body),
        );
        assert_eq!(
            reply.status,
            200,
            "{}",
            String::from_utf8_lossy(&reply.body)
        );
    }
    drop(server);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(audit_file(&home))
            .expect("audit file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the audit file is owner-only");
    }
    let entries: Vec<serde_json::Value> = audit_lines(&home)
        .iter()
        .map(|line| serde_json::from_str(line).expect("one JSON entry per line"))
        .collect();
    assert_eq!(entries.len(), 4, "{entries:?}");
    for pair in entries.chunks(2) {
        let (request, response) = (&pair[0], &pair[1]);
        for entry in pair {
            assert_eq!(entry["schema"], "render.registrystack.org/audit/v1");
            let fields: Vec<&str> = entry
                .as_object()
                .expect("envelope object")
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(
                fields,
                [
                    "correlation",
                    "eventId",
                    "phase",
                    "record",
                    "schema",
                    "time"
                ],
                "the shared envelope and nothing else: {entry}"
            );
        }
        assert_eq!(request["phase"], "request");
        assert!(
            request["record"].get("outcome").is_none(),
            "the request entry is written before any outcome exists: {request}"
        );
        assert_eq!(response["phase"], "response");
        assert_eq!(response["record"]["outcome"], "rendered");
        assert_eq!(response["record"]["pdfSha256"], golden_receipt_sha());
        assert_eq!(
            request["correlation"], response["correlation"],
            "the response carries its request's correlation"
        );
        for field in [
            "documentId",
            "documentVersion",
            "bundleVersion",
            "bundleHash",
            "caller",
        ] {
            assert_eq!(
                request["record"][field], response["record"][field],
                "{field}"
            );
        }
    }
    assert_eq!(entries[0]["correlation"], "effect-1234");
    assert_eq!(entries[0]["record"]["correlationId"], "effect-1234");
    let drawn = entries[2]["correlation"].as_str().expect("correlation");
    assert_eq!(drawn.len(), 36, "a drawn random id: {drawn}");
    assert!(
        entries[2]["record"].get("correlationId").is_none(),
        "a drawn correlation stays in the envelope: {}",
        entries[2]
    );
}

/// Read one audit line from a `stdout` destination.
fn next_audit_entry(reader: &mut BufReader<ChildStdout>) -> serde_json::Value {
    let mut line = String::new();
    reader.read_line(&mut line).expect("audit line");
    serde_json::from_str(&line).unwrap_or_else(|err| panic!("audit entry {line:?}: {err}"))
}

#[test]
fn a_refused_response_entry_withholds_the_pdf() {
    let (home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    audit_to_stdout(&home, &runtime);
    let (server, stdout) = start_server_with_stdout(&runtime);
    let port = server.port;
    let body = receipt_body();
    let render = std::thread::spawn(move || {
        request(
            port,
            "POST",
            "/v1/render/receipt",
            &[
                ("Authorization", &format!("Bearer {API_KEY}")),
                ("Content-Type", "application/json"),
            ],
            Some(&body),
        )
    });
    // The request entry arrives before the render; closing the stream then
    // makes the response entry the write that fails.
    let mut reader = BufReader::new(stdout);
    let entry = next_audit_entry(&mut reader);
    assert_eq!(entry["phase"], "request", "{entry}");
    drop(reader);
    let reply = render.join().expect("render thread");
    let text = String::from_utf8_lossy(&reply.body);
    assert_eq!(reply.status, 503, "{text}");
    assert!(text.contains("audit-failed"), "{text}");
    assert!(
        !reply.body.windows(5).any(|w| w == b"%PDF-"),
        "no document leaves without an accepted response entry"
    );
    assert!(
        !reply
            .headers
            .iter()
            .any(|(name, _)| name == "x-registry-pdf-sha256"),
        "no document metadata leaves either"
    );
    let ready = request(port, "GET", "/ready", &[], None);
    assert_eq!(ready.status, 503, "a stopped audit stream is not ready");
}

#[test]
fn a_refused_request_entry_prevents_the_render() {
    let (home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    audit_to_stdout(&home, &runtime);
    let (server, stdout) = start_server_with_stdout(&runtime);
    let ready = request(server.port, "GET", "/ready", &[], None);
    assert_eq!(ready.status, 200);
    // Nobody reads the audit stream any more: the request entry fails.
    drop(stdout);
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
    let text = String::from_utf8_lossy(&reply.body);
    assert_eq!(reply.status, 503, "{text}");
    assert!(text.contains("audit-failed"), "{text}");
    assert!(!reply.body.windows(5).any(|w| w == b"%PDF-"));
}

#[test]
fn audit_events_are_value_free() {
    let (home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    let server = start_server(&runtime);
    // Canary in the data must never reach the audit, even though the
    // rendered document itself carries it.
    let body = receipt_body().replace("RCP-2026-W03-000123", "CANARY-DO-NOT-LOG");
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
    let mut child = Command::new(env!("CARGO_BIN_EXE_registry-render"))
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
    let auth = [
        ("Authorization", bearer.as_str()),
        ("Content-Type", "application/json"),
    ];

    // Content drift after startup: the per-request seal check catches it.
    let labels = home.join("bundle/labels/ar.yaml");
    let mut text = std::fs::read_to_string(&labels).unwrap();
    text.push_str("extra: tampered\n");
    std::fs::write(&labels, text).unwrap();
    let tampered = request(
        server.port,
        "POST",
        "/v1/render/receipt",
        &auth,
        Some(&receipt_body()),
    );
    assert_eq!(
        tampered.status,
        400,
        "{}",
        String::from_utf8_lossy(&tampered.body)
    );
    assert!(
        String::from_utf8_lossy(&tampered.body).contains("bundle-tampered"),
        "{}",
        String::from_utf8_lossy(&tampered.body)
    );

    // A bundle-load failure that formats a host path (here: a symlink the
    // seal walk refuses) reaches the caller as a problem, so the bundle
    // root must be redacted the way render diagnostics already are.
    #[cfg(unix)]
    {
        let escape = home.join("bundle/escape");
        std::os::unix::fs::symlink(home.join("api.key"), &escape).unwrap();
        let symlinked = request(
            server.port,
            "POST",
            "/v1/render/receipt",
            &auth,
            Some(&receipt_body()),
        );
        std::fs::remove_file(&escape).unwrap();
        let body = String::from_utf8_lossy(&symlinked.body).into_owned();
        assert_eq!(symlinked.status, 400, "{body}");
        assert!(body.contains("manifest-invalid"), "{body}");
        assert!(
            body.contains("<bundle>/escape"),
            "the detail names the offending file under the redaction marker: {body}"
        );
        for root in [
            home.to_string_lossy().into_owned(),
            std::fs::canonicalize(&home)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        ] {
            assert!(
                !body.contains(&root),
                "host paths must not reach the caller: {body}"
            );
        }
    }

    // Unsealing after startup (hashes stripped, content otherwise intact):
    // the worker must load sealed, not merely verify-if-sealed.
    let manifest_path = home.join("bundle/manifest.yaml");
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    let stripped = manifest.split("hashes:").next().unwrap().to_owned();
    std::fs::write(&manifest_path, stripped).unwrap();
    let unsealed = request(
        server.port,
        "POST",
        "/v1/render/receipt",
        &auth,
        Some(&receipt_body()),
    );
    assert_eq!(
        unsealed.status,
        400,
        "{}",
        String::from_utf8_lossy(&unsealed.body)
    );
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
        lines
            .iter()
            .any(|l| l.contains("body-too-large") && l.contains("refused")),
        "the 413 refusal is audited: {lines:?}"
    );
}

#[test]
fn chunked_bodies_are_refused_upfront_as_problems() {
    let (home, runtime, _) = deployment(
        "limits:\n  renderTimeoutSeconds: 20\n  maxOutputBytes: 8388608\n  maxRequestBodyBytes: 1024\n  maxConcurrency: 2\n",
        &repo_root().join("products/render/bundles/receipt"),
    );
    let server = start_server(&runtime);
    // Chunked framing, oversized payload: once a chunked stream trips the
    // limit mid-body the connection is broken and NO response can be
    // delivered, so chunked must be refused up front — as an audited
    // problem document on a healthy connection.
    let body = "x".repeat(2048);
    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let head = format!(
        "POST /v1/render/receipt HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {API_KEY}\r\nTransfer-Encoding: chunked\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).unwrap();
    stream
        .write_all(format!("{:x}\r\n", body.len()).as_bytes())
        .unwrap();
    stream.write_all(body.as_bytes()).unwrap();
    stream.write_all(b"\r\n0\r\n\r\n").unwrap();
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw);
    assert!(
        text.starts_with("HTTP/1.1 400"),
        "chunked must be refused with a problem, not a plain or missing response: {text}"
    );
    assert!(
        text.contains("invalid-argument") && text.contains("Content-Length"),
        "chunked refusal names the fix: {text}"
    );
    drop(server);
    let lines = audit_lines(&home);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("invalid-argument") && l.contains("refused")),
        "the chunked refusal is audited: {lines:?}"
    );
}

#[test]
fn wrong_method_on_render_is_a_problem_and_audited() {
    let (home, runtime, _) = deployment(
        DEFAULT_LIMITS,
        &repo_root().join("products/render/bundles/receipt"),
    );
    let server = start_server(&runtime);
    let reply = request(
        server.port,
        "GET",
        "/v1/render/receipt",
        &[("Authorization", &format!("Bearer {API_KEY}"))],
        None,
    );
    assert_eq!(
        reply.status,
        400,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let text = String::from_utf8_lossy(&reply.body);
    assert!(text.contains("use POST"), "{text}");
    drop(server);
    let lines = audit_lines(&home);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("invalid-argument") && l.contains("refused")),
        "the method refusal is audited: {lines:?}"
    );
}

#[test]
fn pathological_renders_are_bounded_and_the_service_recovers() {
    // A compute- and memory-heavy bundle exercises the worker resource walls.
    // Depending on binary and platform layout, either the address-space cap or
    // the timeout can win. Both must kill only that worker, be audited, and
    // leave the service ready to spawn a fresh worker for the next request.
    let (_heavy, bundle) = physical_tempdir();
    std::fs::write(
        bundle.join("manifest.yaml"),
        "apiVersion: render.registrystack.org/v1alpha1\nkind: RenderBundle\nbundleVersion: 1\ndocuments:\n  - id: heavy\n    version: 1\n    entry: templates/heavy.typ\n  - id: healthy\n    version: 1\n    entry: templates/healthy.typ\n",
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
    std::fs::write(
        bundle.join("templates/healthy.typ"),
        "#let payload = json(bytes(sys.inputs.data))\n= Worker recovered\n",
    )
    .unwrap();
    // Seal the heavy bundle so serve accepts it.
    let sealed = Command::new(env!("CARGO_BIN_EXE_registry-render"))
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
        &bundle,
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
    assert_worker_hit_resource_wall(&slow);

    // Recovery: an immediate second request is served by a fresh worker.
    let second = request(
        server.port,
        "POST",
        "/v1/render/healthy",
        &[
            ("Authorization", &format!("Bearer {API_KEY}")),
            ("Content-Type", "application/json"),
        ],
        Some(r#"{"issuedAt":"2026-09-16T10:32:00Z","data":{}}"#),
    );
    assert_eq!(
        second.status,
        200,
        "a fresh worker serves a healthy render: {}",
        String::from_utf8_lossy(&second.body)
    );
    assert!(second.body.starts_with(b"%PDF-"));
    drop(server);
    let lines = audit_lines(&home);
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.contains("render-timeout") || l.contains("render-panicked"))
            .count(),
        1,
        "the bounded render is audited once"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("\"outcome\":\"rendered\"")),
        "the recovery render is audited: {lines:?}"
    );
}

fn assert_worker_hit_resource_wall(reply: &Reply) {
    let body = String::from_utf8_lossy(&reply.body);
    assert!(
        (reply.status == 504 && body.contains("render-timeout"))
            || (reply.status == 500 && body.contains("render-panicked")),
        "expected the timeout or memory wall to stop the worker: {body}"
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

#[test]
#[cfg(unix)]
fn shutdown_is_bounded_by_grace_even_with_renders_in_flight() {
    // A render far beyond the grace (and a huge render timeout so nothing
    // else reaps it): SIGTERM must still exit the process within the
    // bounded window — the drain holds the door for grace, connection
    // teardown gets grace, then stragglers are abandoned and their workers
    // killed. Waiting for the render itself would take tens of seconds.
    let (_heavy, bundle) = physical_tempdir();
    std::fs::write(
        bundle.join("manifest.yaml"),
        "apiVersion: render.registrystack.org/v1alpha1\nkind: RenderBundle\nbundleVersion: 1\ndocuments:\n  - id: heavy\n    version: 1\n    entry: templates/heavy.typ\n",
    )
    .unwrap();
    for dir in [
        "templates",
        "fonts",
        "labels",
        "schemas",
        "packages/preview",
    ] {
        std::fs::create_dir_all(bundle.join(dir)).unwrap();
    }
    std::fs::write(
        bundle.join("templates/heavy.typ"),
        "#let x = range(200000000).fold(0, (a, b) => a + b)\n#x\n",
    )
    .unwrap();
    let sealed = Command::new(env!("CARGO_BIN_EXE_registry-render"))
        .args(["seal", "--bundle", bundle.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(sealed.status.success());

    let (home, runtime, port) = deployment(
        "limits:\n  renderTimeoutSeconds: 120\n  maxOutputBytes: 8388608\n  maxRequestBodyBytes: 8388608\n  maxConcurrency: 2\n",
        &bundle,
    );
    // Tighten the grace: the deployment default is 5s.
    let text = std::fs::read_to_string(&runtime).unwrap();
    std::fs::write(
        &runtime,
        text.replace("shutdownGraceSeconds: 5", "shutdownGraceSeconds: 1"),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_registry-render"))
        .args(["serve", "--runtime", runtime.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            let _ =
                stream.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            let mut buf = [0u8; 128];
            if stream.read(&mut buf).is_ok_and(|n| n > 0) {
                break;
            }
        }
        assert!(Instant::now() < deadline, "server did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
    // A render in flight, from a detached thread (its socket closes when
    // the process exits).
    let body = r#"{"issuedAt":"2026-09-16T10:32:00Z","data":{}}"#.to_owned();
    std::thread::spawn(move || {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = stream.write_all(
                format!(
                    "POST /v1/render/heavy HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {API_KEY}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = stream.write_all(body.as_bytes());
            let mut sink = Vec::new();
            use std::io::Read as _;
            let _ = stream.read_to_end(&mut sink);
        }
    });
    std::thread::sleep(Duration::from_millis(700));
    let started = Instant::now();
    Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .output()
        .expect("send SIGTERM");
    let code = wait_for_exit(&mut child);
    let elapsed = started.elapsed();
    assert_eq!(code, 0, "graceful exit code");
    assert!(
        elapsed < Duration::from_secs(10),
        "SIGTERM exit took {elapsed:?}; the shutdown window is bounded (grace 1s here)"
    );
    let _ = home;
}
