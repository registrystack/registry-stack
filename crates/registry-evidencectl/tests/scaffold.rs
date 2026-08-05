//! Acceptance tests for the minimal `evidencectl new --openapi` path.

#![cfg(unix)]

use std::{
    fs,
    io::{Read as _, Write as _},
    net::TcpListener,
    os::unix::fs::{symlink, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::TempDir;

const OPENAPI: &str = "# retained comment\r\nopenapi: 3.1.0\r\ninfo:\r\n  title: Records\r\n  version: 1.0.0\r\npaths: {}\r\n";

#[test]
fn bare_new_points_to_openapi_and_writes_nothing() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    let output = evidencectl(&["new", path(&project)]);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("--openapi <path-or-https-url>"));
    assert!(!project.exists());
}

#[test]
fn openapi_requires_the_explicit_local_profile_before_writing() {
    let workspace = TempDir::new().expect("temporary directory");
    let spec = write_spec(workspace.path(), OPENAPI.as_bytes());
    let project = workspace.path().join("project");
    let output = evidencectl(&["new", path(&project), "--openapi", path(&spec)]);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("--profile local"));
    assert!(!project.exists());

    let wrong = workspace.path().join("wrong");
    let output = evidencectl(&[
        "new",
        path(&wrong),
        "--openapi",
        path(&spec),
        "--profile",
        "production",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("invalid value 'production'"));
    assert!(!wrong.exists());
}

#[test]
fn local_openapi_is_retained_byte_for_byte_without_premature_artifacts() {
    let workspace = TempDir::new().expect("temporary directory");
    let spec = write_spec(workspace.path(), OPENAPI.as_bytes());
    let project = workspace.path().join("project");
    let output = openapi_new(&project, path(&spec), &[]);
    assert!(output.status.success(), "{}", stderr(&output));

    assert_eq!(
        fs::read(project.join("source.openapi.yaml")).expect("retained OpenAPI"),
        OPENAPI.as_bytes()
    );
    assert_minimal_project(&project, false);
    assert!(stdout(&output).contains("retained exactly"));
    assert!(stdout(&output).contains("No question, fixture case, runtime"));
    assert!(stdout(&output).contains("evidencectl source suggest --project"));
}

#[test]
fn remote_openapi_is_retained_byte_for_byte() {
    let workspace = TempDir::new().expect("temporary directory");
    let mut remote = OPENAPI.as_bytes().to_vec();
    remote.extend_from_slice(b"# remote trailing bytes\n");
    let url = serve_once(200, remote.clone());
    let project = workspace.path().join("remote-project");

    let output = openapi_new(&project, &url, &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        fs::read(project.join("source.openapi.yaml")).expect("retained remote OpenAPI"),
        remote
    );
    assert_minimal_project(&project, false);
}

#[test]
fn invalid_local_or_remote_openapi_writes_nothing_and_cleans_staging() {
    let workspace = TempDir::new().expect("temporary directory");
    let invalid = write_spec(workspace.path(), b"not: openapi\n");
    let invalid_project = workspace.path().join("invalid-project");
    let output = openapi_new(&invalid_project, path(&invalid), &["--generate-keys"]);
    assert!(!output.status.success());
    assert!(!invalid_project.exists());

    let failed_url = serve_once(500, b"failure\n".to_vec());
    let failed_project = workspace.path().join("failed-project");
    let output = openapi_new(&failed_project, &failed_url, &[]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("HTTP 500"));
    assert!(!failed_project.exists());
    assert_no_staging_directories(workspace.path());
}

#[test]
fn unsafe_remote_urls_are_value_free_and_fail_before_network_or_writes() {
    let workspace = TempDir::new().expect("temporary directory");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind connection probe");
    listener
        .set_nonblocking(true)
        .expect("nonblocking connection probe");
    let address = listener.local_addr().expect("probe address");

    for (name, url, sensitive, expected) in [
        (
            "userinfo",
            format!("http://reader:userinfo-secret@{address}/openapi.yaml"),
            "userinfo-secret",
            "credentials",
        ),
        (
            "query",
            format!("http://{address}/openapi.yaml?access_token=query-secret"),
            "query-secret",
            "query or fragment",
        ),
        (
            "fragment",
            format!("http://{address}/openapi.yaml#private-fragment"),
            "private-fragment",
            "query or fragment",
        ),
    ] {
        let project = workspace.path().join(name);
        let output = openapi_new(&project, &url, &["--generate-keys"]);
        assert!(!output.status.success());
        let logged = format!("{}{}", stdout(&output), stderr(&output));
        assert!(logged.contains(expected), "unexpected refusal: {logged}");
        assert!(
            !logged.contains(sensitive) && !logged.contains(&url),
            "refusal leaked an unsafe URL value: {logged}"
        );
        assert!(!project.exists(), "unsafe URL wrote project {name}");
    }

    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "an unsafe URL reached the network"
    );
    assert_no_staging_directories(workspace.path());
}

#[test]
fn generate_keys_is_transactional_unbound_owner_only_and_prints_no_secret() {
    let workspace = TempDir::new().expect("temporary directory");
    let spec = write_spec(workspace.path(), OPENAPI.as_bytes());
    let project = workspace.path().join("project");
    let output = openapi_new(&project, path(&spec), &["--generate-keys"]);
    assert!(output.status.success(), "{}", stderr(&output));

    assert_minimal_project(&project, true);
    assert_eq!(
        fs::metadata(project.join("secrets"))
            .expect("secret directory")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    for (name, mode) in [
        ("signing-ed25519-private-jwk", 0o600),
        ("signing-ed25519-public.jwk.json", 0o644),
        ("audit-hmac-key", 0o600),
        ("subject-binding-hmac-key", 0o600),
    ] {
        assert_eq!(
            fs::metadata(project.join("secrets").join(name))
                .unwrap_or_else(|error| panic!("reading {name}: {error}"))
                .permissions()
                .mode()
                & 0o777,
            mode
        );
    }

    let private = fs::read_to_string(project.join("secrets/signing-ed25519-private-jwk"))
        .expect("private JWK");
    let private: serde_json::Value = serde_json::from_str(&private).expect("private JWK JSON");
    let secret = private["d"].as_str().expect("private key member");
    assert!(!stdout(&output).contains(secret));
    assert!(!stderr(&output).contains(secret));
    assert_no_staging_directories(workspace.path());
}

#[test]
fn existing_paths_and_force_are_refused_without_changes() {
    let workspace = TempDir::new().expect("temporary directory");
    let spec = write_spec(workspace.path(), OPENAPI.as_bytes());

    let directory = workspace.path().join("existing");
    fs::create_dir(&directory).expect("existing directory");
    fs::write(directory.join("sentinel"), b"unchanged").expect("sentinel");
    let output = openapi_new(&directory, path(&spec), &[]);
    assert!(!output.status.success());
    assert_eq!(
        fs::read(directory.join("sentinel")).expect("sentinel"),
        b"unchanged"
    );

    let external = workspace.path().join("external");
    fs::create_dir(&external).expect("external directory");
    fs::write(external.join("sentinel"), b"external").expect("external sentinel");
    let symlinked = workspace.path().join("symlinked");
    symlink(&external, &symlinked).expect("project symlink");
    let output = openapi_new(&symlinked, path(&spec), &["--generate-keys"]);
    assert!(!output.status.success());
    assert_eq!(
        fs::read(external.join("sentinel")).expect("external sentinel"),
        b"external"
    );
    assert_eq!(entries(&external), ["sentinel"]);

    let forced = workspace.path().join("forced");
    let output = openapi_new(&forced, path(&spec), &["--force"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unexpected argument '--force'"));
    assert!(!forced.exists());
    assert_no_staging_directories(workspace.path());
}

fn assert_minimal_project(project: &Path, with_keys: bool) {
    let expected = if with_keys {
        vec![
            ".gitignore",
            "adapters",
            "derivations",
            "fixtures",
            "questions",
            "schemas",
            "secrets",
            "selectors",
            "source.openapi.yaml",
            "sources",
        ]
    } else {
        vec![
            ".gitignore",
            "adapters",
            "derivations",
            "fixtures",
            "questions",
            "schemas",
            "selectors",
            "source.openapi.yaml",
            "sources",
        ]
    };
    assert_eq!(entries(project), expected);
    assert!(entries(&project.join("questions")).is_empty());
    assert!(entries(&project.join("derivations")).is_empty());
    assert!(entries(&project.join("selectors")).is_empty());
    assert!(entries(&project.join("sources")).is_empty());
    assert!(entries(&project.join("adapters")).is_empty());
    assert!(entries(&project.join("schemas")).is_empty());
    assert!(entries(&project.join("fixtures")).is_empty());
    assert_eq!(
        fs::read_to_string(project.join(".gitignore")).expect("gitignore"),
        "secrets/\n.evidence/\n"
    );
    for absent in ["bundle", "runtime.yaml", "evidence.yaml", "README.md"] {
        assert!(
            !project.join(absent).exists(),
            "unexpected generated {absent}"
        );
    }
}

fn openapi_new(project: &Path, openapi: &str, extra: &[&str]) -> Output {
    let mut arguments = vec![
        "new",
        path(project),
        "--openapi",
        openapi,
        "--profile",
        "local",
    ];
    arguments.extend_from_slice(extra);
    evidencectl(&arguments)
}

fn evidencectl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(arguments)
        .output()
        .expect("running evidencectl")
}

fn write_spec(root: &Path, contents: &[u8]) -> PathBuf {
    let path = root.join("records.openapi.yaml");
    fs::write(&path, contents).expect("OpenAPI fixture");
    path
}

fn serve_once(status: u16, body: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback server");
    let address = listener.local_addr().expect("server address");
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request);
        let reason = if status == 200 {
            "OK"
        } else {
            "Internal Server Error"
        };
        write!(
            stream,
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("response headers");
        stream.write_all(&body).expect("response body");
    });
    format!("http://{address}/openapi.yaml")
}

fn entries(root: &Path) -> Vec<String> {
    let mut names = fs::read_dir(root)
        .unwrap_or_else(|error| panic!("reading {}: {error}", root.display()))
        .map(|entry| {
            entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn assert_no_staging_directories(root: &Path) {
    assert!(
        entries(root)
            .into_iter()
            .all(|name| !name.starts_with(".evidencectl-new-")),
        "failed scaffold left a staging directory"
    );
}

fn path(path: &Path) -> &str {
    path.to_str().expect("UTF-8 test path")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
