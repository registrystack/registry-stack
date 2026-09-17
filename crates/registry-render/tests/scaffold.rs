//! Scaffold and CLI regression tests: the first-hour path, exercised as a
//! user drives it — `render init`, first compile, validate without a
//! clock, the unsealed notice, edit-after-seal recovery, and verify-then-
//! seal ordering.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn render_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_render"))
}

fn tempdir() -> PathBuf {
    tempfile::tempdir().expect("tempdir").keep()
}

fn run(args: &[&str]) -> Output {
    render_bin().args(args).output().expect("spawn render")
}

fn compile(bundle: &Path) -> Output {
    run(&[
        "compile",
        "--bundle",
        bundle.to_str().unwrap(),
        "--type",
        "letter",
        "--data",
        bundle.join("fixtures/data.json").to_str().unwrap(),
        "--issued-at",
        "2026-01-01T00:00:00Z",
        "--out",
        bundle.join("letter.pdf").to_str().unwrap(),
    ])
}

#[test]
fn default_scaffold_compiles_offline_with_zero_edits_and_no_warnings() {
    let dir = tempdir();
    let init = run(&["init", dir.to_str().unwrap()]);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let compiled = compile(&dir);
    assert!(
        compiled.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&compiled.stdout),
        String::from_utf8_lossy(&compiled.stderr)
    );
    assert!(
        dir.join("letter.pdf").is_file(),
        "the PDF was written next to the scaffold"
    );
    assert!(
        !String::from_utf8_lossy(&compiled.stderr).contains("warning"),
        "the scaffold renders warning-free: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    // The scaffold vendors the QR package offline.
    assert!(dir
        .join("packages/preview/zebra/0.1.0/typst.toml")
        .is_file());
    assert!(dir.join("fixtures/data.json").is_file());
}

#[test]
fn non_latin_scaffold_compiles_zero_edits() {
    let dir = tempdir();
    let init = run(&["init", dir.to_str().unwrap(), "--labels", "ar"]);
    assert!(init.status.success());
    // Label files are seeded with the full key set (in English), so the
    // first render is warning-free even before localization + fonts.
    let compiled = compile(&dir);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&compiled.stderr).contains("warning"),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let labels = std::fs::read_to_string(dir.join("labels/ar.yaml")).unwrap();
    for key in [
        "title:",
        "reference:",
        "generated:",
        "issued-at:",
        "version-note:",
    ] {
        assert!(labels.contains(key), "seeded label file misses {key}");
    }
}

#[test]
fn validate_is_a_dry_run_and_needs_no_clock() {
    let dir = tempdir();
    run(&["init", dir.to_str().unwrap()]);
    let data = dir.join("fixtures/data.json").to_str().unwrap().to_owned();
    let good = run(&[
        "validate",
        "--bundle",
        dir.to_str().unwrap(),
        "--type",
        "letter",
        "--data",
        &data,
    ]);
    assert_eq!(good.status.code(), Some(0), "no --issued-at required");

    let bad_path = dir.join("bad.json");
    std::fs::write(&bad_path, r#"{"reference": "X"}"#).unwrap();
    let bad = run(&[
        "validate",
        "--bundle",
        dir.to_str().unwrap(),
        "--type",
        "letter",
        "--data",
        bad_path.to_str().unwrap(),
    ]);
    assert_eq!(
        bad.status.code(),
        Some(registry_render::ProblemKind::DataInvalid.exit_code())
    );
    let text = String::from_utf8_lossy(&bad.stderr);
    assert!(text.contains("body"), "the missing field is named: {text}");
}

#[test]
fn compile_prints_the_unsealed_notice() {
    let dir = tempdir();
    run(&["init", dir.to_str().unwrap()]);
    let compiled = compile(&dir);
    let stderr = String::from_utf8_lossy(&compiled.stderr);
    assert!(
        stderr.contains("unsealed"),
        "compile must say when a bundle is unsealed: {stderr}"
    );
}

#[test]
fn edit_after_seal_names_the_recovery_path() {
    let dir = tempdir();
    run(&["init", dir.to_str().unwrap()]);
    let sealed = run(&["seal", "--bundle", dir.to_str().unwrap()]);
    assert!(sealed.status.success());
    // An intentional edit after sealing…
    let template = dir.join("templates/letter.typ");
    let mut text = std::fs::read_to_string(&template).unwrap();
    text.push_str("// edited\n");
    std::fs::write(&template, text).unwrap();
    let compiled = compile(&dir);
    assert_eq!(
        compiled.status.code(),
        Some(registry_render::ProblemKind::BundleTampered.exit_code())
    );
    let stderr = String::from_utf8_lossy(&compiled.stderr);
    assert!(
        stderr.contains("render seal"),
        "the drift message must point at recovery: {stderr}"
    );
    // …and recovery actually works.
    let resealed = run(&["seal", "--bundle", dir.to_str().unwrap()]);
    assert!(resealed.status.success());
    assert!(compile(&dir).status.success());
}

#[test]
fn compile_is_bounded_by_a_timeout() {
    let dir = tempdir();
    run(&["init", dir.to_str().unwrap()]);
    // A compute-heavy template with a one-second budget: compile must be
    // killed at the bound (the same supervised-worker wall serve uses),
    // not run unbounded.
    std::fs::write(
        dir.join("templates/letter.typ"),
        "#let x = range(20000000).fold(0, (a, b) => a + b)\n#x\n",
    )
    .unwrap();
    let out = run(&[
        "compile",
        "--bundle",
        dir.to_str().unwrap(),
        "--type",
        "letter",
        "--data",
        dir.join("fixtures/data.json").to_str().unwrap(),
        "--issued-at",
        "2026-01-01T00:00:00Z",
        "--out",
        dir.join("letter.pdf").to_str().unwrap(),
        "--timeout",
        "1",
    ]);
    assert_eq!(
        out.status.code(),
        Some(registry_render::ProblemKind::RenderTimeout.exit_code()),
        "compile must be bounded: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("timeout"), "{stderr}");
}

#[test]
fn check_seal_refuses_to_seal_a_broken_bundle() {
    let dir = tempdir();
    run(&["init", dir.to_str().unwrap()]);
    // Break script coverage: a label value in a script no font covers,
    // without adding any font to the bundle.
    std::fs::write(dir.join("labels/en.yaml"), "title: 你好\n").unwrap();
    let out = run(&["check", "--bundle", dir.to_str().unwrap(), "--seal"]);
    assert_eq!(
        out.status.code(),
        Some(registry_render::ProblemKind::FontInvalid.exit_code()),
        "verify must run before sealing"
    );
    let manifest = std::fs::read_to_string(dir.join("manifest.yaml")).unwrap();
    assert!(
        !manifest.contains("hashes:"),
        "a failed check must not leave a seal behind"
    );
}

#[test]
fn bundle_with_symlink_cannot_be_sealed() {
    let dir = tempdir();
    run(&["init", dir.to_str().unwrap()]);
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("x.txt"), "x").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path().join("x.txt"), dir.join("templates/link.typ"))
        .unwrap();
    let out = run(&["seal", "--bundle", dir.to_str().unwrap()]);
    #[cfg(unix)]
    assert_eq!(
        out.status.code(),
        Some(registry_render::ProblemKind::ManifestInvalid.exit_code())
    );
    #[cfg(not(unix))]
    let _ = out;
}

#[test]
fn openapi_document_has_no_drift() {
    let (_home, runtime, _) = serve_deployment();
    let server = start_server(&runtime);
    let reply = request(server.port, "GET", "/openapi.json", &[], None);
    assert_eq!(reply.status, 200);
    let doc = String::from_utf8_lossy(&reply.body);
    assert!(doc.contains("bearerAuth"), "auth is declared and enforced");
    assert!(doc.contains("413"), "the body-limit outcome is documented");
    assert!(
        !doc.contains("\"429\""),
        "the semaphore queues rather than rejecting; 429 is not a real outcome"
    );
    assert!(doc.contains("/v1/render/{type}"));
    assert!(doc.contains("/v1/documents"));
}

#[test]
fn tampered_ledger_fails_audit_verify() {
    let (home, runtime, _) = serve_deployment();
    let server = start_server(&runtime);
    // One honest render to have a chain worth tampering with.
    let data = std::fs::read_to_string(fixtures_receipt()).unwrap();
    let body = format!(r#"{{"issuedAt":"2026-09-16T10:32:00Z","data":{data}}}"#);
    let reply = request(
        server.port,
        "POST",
        "/v1/render/receipt",
        &[
            ("Authorization", &format!("Bearer {}", API_KEY)),
            ("Content-Type", "application/json"),
        ],
        Some(&body),
    );
    assert_eq!(reply.status, 200);
    drop(server);
    // Flip one byte inside a sealed ledger line.
    let ledger = home.join("audit").join("ledger.jsonl");
    let mut bytes = std::fs::read(&ledger).unwrap();
    if let Some(position) = bytes.iter().position(|b| *b == b'"') {
        bytes[position] = b'X';
    }
    std::fs::write(&ledger, bytes).unwrap();
    let out = run(&["audit-verify", "--runtime", runtime.to_str().unwrap()]);
    assert_ne!(
        out.status.code(),
        Some(0),
        "a tampered chain must not verify"
    );
}

// ---------- tiny serve helpers shared with the serve suite ----------

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

const API_KEY: &str = "test-key-0123456789abcdef0123456789abcdef";
const AUDIT_KEY: &str = "audit-key-0123456789abcdef0123456789abcd";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate path")
        .to_path_buf()
}

fn fixtures_receipt() -> PathBuf {
    repo_root().join("products/render/bundles/receipt/fixtures/data.json")
}

fn write_secret(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn serve_deployment() -> (PathBuf, PathBuf, u16) {
    let home = tempfile::tempdir().unwrap().keep();
    let bundle = home.join("bundle");
    copy_dir(
        &repo_root().join("products/render/bundles/receipt"),
        &bundle,
    );
    write_secret(&home.join("api.key"), API_KEY);
    write_secret(&home.join("audit.key"), AUDIT_KEY);
    std::fs::create_dir(home.join("audit")).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let runtime = format!(
        "apiVersion: render.registrystack.org/v1alpha1\nkind: RenderRuntime\nserver:\n  bind: 127.0.0.1:{port}\nbundle:\n  path: {}\nauth:\n  apiKeyRef: secret:file/api.key\nlimits:\n  renderTimeoutSeconds: 20\naudit:\n  directory: {}\n  integrityKeyRef: secret:file/audit.key\n",
        bundle.display(),
        home.join("audit").display()
    );
    let runtime_path = home.join("runtime.yaml");
    std::fs::write(&runtime_path, runtime).unwrap();
    (home, runtime_path, port)
}

struct Server {
    child: Child,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_server(runtime_path: &Path) -> Server {
    let mut child = render_bin()
        .args(["serve", "--runtime", runtime_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn serve");
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
            let _ =
                stream.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            let mut buf = [0u8; 128];
            if stream.read(&mut buf).is_ok_and(|n| n > 0) {
                return Server { child, port };
            }
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("server not healthy in 30s");
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("server exited early: {status}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

struct Reply {
    status: u16,
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
    let mut wire = format!("{method} {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
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
        .expect("terminator");
    let status: u16 = String::from_utf8_lossy(&raw[..split])
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .expect("status");
    Reply {
        status,
        body: raw[split + 4..].to_vec(),
    }
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
