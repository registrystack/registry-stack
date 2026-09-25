//! Scaffold and CLI regression tests: the first-hour path, exercised as a
//! user drives it — `registry-render init`, first compile, validate without a
//! clock, the unsealed notice, edit-after-seal recovery, and verify-then-
//! seal ordering.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn render_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_registry-render"))
}

fn tempdir() -> PathBuf {
    tempfile::tempdir()
        .expect("tempdir")
        .keep()
        .canonicalize()
        .expect("physical tempdir path")
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
    // The scaffold vendors no third-party package. What it has to teach
    // is where packages live and that nothing is fetched at render time;
    // the example bundles carry a worked one.
    assert!(
        !dir.join("packages").exists(),
        "the scaffold writes no vendored package tree"
    );
    assert!(dir.join("fixtures/data.json").is_file());
    // Starter fonts ship with their license, ready to replace.
    assert!(
        dir.join("fonts/NotoSans-Regular.ttf").is_file(),
        "starter fonts must be real font files"
    );
    assert!(
        dir.join("fonts/NotoNaskhArabic-Regular.ttf").is_file(),
        "an Arabic-capable starter font ships for non-Latin scaffolds"
    );
    assert!(
        dir.join("fonts/OFL.txt").is_file(),
        "the fonts' license travels with them"
    );
}

#[test]
fn a_locale_listed_twice_is_refused_before_anything_is_written() {
    let dir = tempdir();
    // A repeated locale would scaffold the same label file twice and write
    // a manifest listing it twice. Refuse the argument instead, before the
    // directory is touched.
    let init = run(&["init", dir.to_str().unwrap(), "--labels", "en,en"]);
    assert_eq!(
        init.status.code(),
        Some(registry_render::ProblemKind::InvalidArgument.exit_code()),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
    assert!(
        !dir.join("manifest.yaml").exists(),
        "a refused argument leaves no half-made bundle"
    );
}

#[test]
fn watch_and_emit_envelope_are_refused_together() {
    let dir = tempdir();
    run(&["init", dir.to_str().unwrap()]);
    // Watch never returns, so it would ignore the envelope request
    // forever. Clap refuses the pair as a usage error.
    let envelope = dir.join("envelope.json");
    let compiled = run(&[
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
        "--watch",
        "--emit-envelope",
        envelope.to_str().unwrap(),
    ]);
    assert_eq!(
        compiled.status.code(),
        Some(2),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&compiled.stdout),
        String::from_utf8_lossy(&compiled.stderr)
    );
    assert!(!envelope.exists(), "no envelope is written");
}

#[test]
fn comma_separated_labels_flag_is_accepted() {
    let dir = tempdir();
    // `--labels en,fr` reads as two locales to a new operator; a comma is
    // never valid inside one, so the flag accepts the comma-separated form
    // instead of failing kebab-case validation on "en,fr".
    let init = run(&["init", dir.to_str().unwrap(), "--labels", "en,fr"]);
    assert!(
        init.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
    assert!(dir.join("labels/en.yaml").is_file(), "en label file");
    assert!(dir.join("labels/fr.yaml").is_file(), "fr label file");
    let manifest = std::fs::read_to_string(dir.join("manifest.yaml")).unwrap();
    assert!(manifest.contains("labels: [\"en\", \"fr\"]"), "{manifest}");
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
        stderr.contains("registry-render seal"),
        "the drift message must point at recovery: {stderr}"
    );
    // …and recovery actually works.
    let resealed = run(&["seal", "--bundle", dir.to_str().unwrap()]);
    assert!(resealed.status.success());
    assert!(compile(&dir).status.success());
}

#[test]
fn compile_is_bounded_by_a_worker_resource_wall() {
    let dir = tempdir();
    run(&["init", dir.to_str().unwrap()]);
    // A pathological template must be bounded by either the worker's memory
    // cap or its timeout. Which wall wins depends on binary and platform
    // layout, but the compile must never run unbounded.
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
    let code = out.status.code();
    assert!(
        code == Some(registry_render::ProblemKind::RenderTimeout.exit_code())
            || code == Some(registry_render::ProblemKind::RenderPanicked.exit_code()),
        "compile must be bounded: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("render-timeout") || stderr.contains("render-panicked"),
        "{stderr}"
    );
}

#[test]
fn now_is_loud_about_the_resolved_issued_at() {
    let dir = tempdir();
    run(&["init", dir.to_str().unwrap()]);
    let out = run(&[
        "compile",
        "--bundle",
        dir.to_str().unwrap(),
        "--type",
        "letter",
        "--data",
        dir.join("fixtures/data.json").to_str().unwrap(),
        "--now",
        "--out",
        dir.join("letter.pdf").to_str().unwrap(),
    ]);
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--now")
            && stderr.contains("issuedAt")
            && stderr.contains("NOT byte-stable"),
        "--now must announce the nondeterministic instant it chose: {stderr}"
    );
}

#[test]
fn json_failures_are_problem_documents() {
    let dir = tempdir();
    run(&["init", dir.to_str().unwrap()]);
    let bad = dir.join("bad.json");
    std::fs::write(&bad, r#"{"reference": "X"}"#).unwrap();
    let out = run(&[
        "compile",
        "--bundle",
        dir.to_str().unwrap(),
        "--type",
        "letter",
        "--data",
        bad.to_str().unwrap(),
        "--issued-at",
        "2026-01-01T00:00:00Z",
        "--out",
        dir.join("letter.pdf").to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(
        out.status.code(),
        Some(registry_render::ProblemKind::DataInvalid.exit_code())
    );
    let problem: serde_json::Value =
        serde_json::from_slice(&out.stderr).expect("stderr is one JSON problem document");
    assert_eq!(problem["title"], "data-invalid", "{problem}");
    assert_eq!(
        problem["type"], "https://render.registrystack.org/problems/data-invalid",
        "{problem}"
    );
    assert!(
        problem["pointers"]
            .as_array()
            .is_some_and(|p| !p.is_empty()),
        "schema pointers survive into the JSON failure: {problem}"
    );
}

#[test]
fn validate_supports_json() {
    let dir = tempdir();
    run(&["init", dir.to_str().unwrap()]);
    let good = run(&[
        "validate",
        "--bundle",
        dir.to_str().unwrap(),
        "--type",
        "letter",
        "--data",
        dir.join("fixtures/data.json").to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(good.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&good.stdout).expect("json stdout");
    assert_eq!(value["valid"], true, "{value}");

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
        "--json",
    ]);
    assert_eq!(
        bad.status.code(),
        Some(registry_render::ProblemKind::DataInvalid.exit_code())
    );
    let problem: serde_json::Value =
        serde_json::from_slice(&bad.stderr).expect("json problem on stderr");
    assert_eq!(problem["title"], "data-invalid", "{problem}");
}

#[test]
fn check_names_a_locale_missing_a_label_key() {
    let dir = tempdir();
    run(&[
        "init",
        dir.to_str().unwrap(),
        "--labels",
        "en",
        "--labels",
        "fr",
    ]);
    // fr loses a key the template (and en) rely on: only the fr render
    // would fail at runtime — check must name it up front.
    let fr = dir.join("labels/fr.yaml");
    let text = std::fs::read_to_string(&fr).unwrap();
    let broken = text.replace("reference: \"Reference\"\n", "");
    std::fs::write(&fr, broken).unwrap();
    let out = run(&["check", "--bundle", dir.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(registry_render::ProblemKind::LabelsInvalid.exit_code()),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("reference") && stderr.contains("fr"),
        "the missing key and locale are named: {stderr}"
    );
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
    let doc: serde_json::Value = serde_json::from_slice(&reply.body).expect("openapi json");
    // Structural, not substring: the served document declares exactly the
    // implemented surface.
    let paths = doc["paths"].as_object().expect("paths object");
    let expected_paths = ["/health", "/ready", "/v1/documents", "/v1/render/{type}"];
    assert_eq!(paths.len(), expected_paths.len(), "{paths:?}");
    for path in expected_paths {
        assert!(paths.contains_key(path), "missing {path}: {paths:?}");
    }
    let render = &paths["/v1/render/{type}"]["post"];
    assert!(
        render["security"][0]["bearerAuth"].is_array(),
        "auth is declared and enforced"
    );
    let responses = render["responses"].as_object().expect("responses");
    for status in ["200", "400", "401", "413", "422", "500", "503", "504"] {
        assert!(
            responses.contains_key(status),
            "render must document {status}: {responses:?}"
        );
    }
    assert!(
        !responses.contains_key("429"),
        "the semaphore queues rather than rejecting; 429 is not a real outcome"
    );
    assert!(
        paths["/v1/documents"]["get"]["security"][0]["bearerAuth"].is_array(),
        "documents is authenticated too"
    );
}

fn check_audit_under(runtime: &Path, bundle: &Path, root: &Path) -> Output {
    run(&[
        "check",
        "--bundle",
        bundle.to_str().unwrap(),
        "--runtime",
        runtime.to_str().unwrap(),
        "--require-audit-under",
        root.to_str().unwrap(),
    ])
}

#[test]
fn check_proves_the_audit_file_resolves_under_the_root() {
    let (home, runtime, _) = serve_deployment();
    let out = check_audit_under(&runtime, &home.join("bundle"), &home);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains(&format!(
            "audit file {} resolves under {}",
            home.join("audit/render.jsonl").display(),
            home.display()
        )),
        "{stdout}"
    );
    let elsewhere = tempdir();
    let out = check_audit_under(&runtime, &home.join("bundle"), &elsewhere);
    assert_ne!(
        out.status.code(),
        Some(0),
        "an audit file outside the root fails the proof"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("audit file fails the containment proof"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn check_refuses_to_prove_a_stdout_audit_destination() {
    let (home, runtime, _) = serve_deployment();
    let text = std::fs::read_to_string(&runtime).unwrap();
    let text = text.replace(
        &format!("  path: {}\n", home.join("audit/render.jsonl").display()),
        "  destination: stdout\n",
    );
    assert!(text.contains("destination: stdout"), "{text}");
    std::fs::write(&runtime, text).unwrap();
    let out = check_audit_under(&runtime, &home.join("bundle"), &home);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("audit.destination is stdout, which has no path to prove"),
        "{stderr}"
    );
}

// ---------- tiny serve helpers shared with the serve suite ----------

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

const API_KEY: &str = "test-key-0123456789abcdef0123456789abcdef";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate path")
        .to_path_buf()
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
    let home = tempfile::tempdir()
        .unwrap()
        .keep()
        .canonicalize()
        .expect("physical deployment path");
    let bundle = home.join("bundle");
    copy_dir(
        &repo_root().join("products/render/bundles/receipt"),
        &bundle,
    );
    write_secret(&home.join("api.key"), API_KEY);
    std::fs::create_dir(home.join("audit")).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let runtime = format!(
        "apiVersion: render.registrystack.org/v1alpha1\nkind: RenderRuntime\nserver:\n  bind: 127.0.0.1:{port}\nbundle:\n  path: {}\nauth:\n  apiKeyRef: secret:file/api.key\nlimits:\n  renderTimeoutSeconds: 20\naudit:\n  path: {}\n",
        bundle.display(),
        home.join("audit/render.jsonl").display()
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
