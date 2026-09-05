//! Acceptance tests for the minimal `evidencectl new` authoring paths.

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
fn bare_new_names_both_authoring_inputs_and_writes_nothing() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    let output = evidencectl(&["new", path(&project)]);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("required arguments"));
    assert!(stderr(&output).contains("--openapi <OPENAPI>"));
    assert!(stderr(&output).contains("--transport <TRANSPORT>"));
    assert!(stderr(&output).contains("--profile <PROFILE>"));
    assert!(!project.exists());
}

#[test]
fn sqlite_extract_requires_the_explicit_local_profile_before_writing() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    let output = evidencectl(&["new", path(&project), "--transport", "sqlite-extract"]);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("required arguments"));
    assert!(stderr(&output).contains("--profile <PROFILE>"));
    assert!(!project.exists());
}

#[test]
fn local_sqlite_extract_creates_a_runnable_synthetic_starter() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    let output = sqlite_new(&project, &[]);
    assert!(output.status.success(), "{}", stderr(&output));

    assert_sqlite_project(&project);
    let printed = stdout(&output);
    assert!(printed.contains("editable SQLite-extract authoring project"));
    assert!(printed.contains("queries"));
    assert!(printed.contains("evidencectl fixtures run --project"));
    assert!(printed.contains("synthetic source, question, and fixture"));
    assert!(!printed.contains("source suggest"));
}

#[test]
fn openapi_and_sqlite_extract_are_mutually_exclusive_before_writing() {
    let workspace = TempDir::new().expect("temporary directory");
    let spec = write_spec(workspace.path(), OPENAPI.as_bytes());
    let project = workspace.path().join("project");
    let output = evidencectl(&[
        "new",
        path(&project),
        "--openapi",
        path(&spec),
        "--transport",
        "sqlite-extract",
        "--profile",
        "local",
    ]);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("cannot be used with"));
    assert!(!project.exists());
}

#[test]
fn openapi_requires_the_explicit_local_profile_before_writing() {
    let workspace = TempDir::new().expect("temporary directory");
    let spec = write_spec(workspace.path(), OPENAPI.as_bytes());
    let project = workspace.path().join("project");
    let output = evidencectl(&["new", path(&project), "--openapi", path(&spec)]);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("required arguments"));
    assert!(stderr(&output).contains("--profile <PROFILE>"));
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
fn local_openapi_is_retained_byte_for_byte_with_automatic_disposable_keys() {
    let workspace = TempDir::new().expect("temporary directory");
    let spec = write_spec(workspace.path(), OPENAPI.as_bytes());
    let project = workspace.path().join("project");
    let output = openapi_new(&project, path(&spec), &[]);
    assert!(output.status.success(), "{}", stderr(&output));

    assert_eq!(
        fs::read(project.join("source.openapi.yaml")).expect("retained OpenAPI"),
        OPENAPI.as_bytes()
    );
    assert_minimal_project(&project, true);
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
    assert_minimal_project(&project, true);
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
fn automatic_keys_are_transactional_unbound_owner_only_and_print_no_secret() {
    let workspace = TempDir::new().expect("temporary directory");
    let spec = write_spec(workspace.path(), OPENAPI.as_bytes());
    let project = workspace.path().join("project");
    let output = openapi_new(&project, path(&spec), &[]);
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
        ("signing-p256-private-jwk", 0o600),
        ("signing-p256-public.jwk.json", 0o644),
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

    let private =
        fs::read_to_string(project.join("secrets/signing-p256-private-jwk")).expect("private JWK");
    let private: serde_json::Value = serde_json::from_str(&private).expect("private JWK JSON");
    let secret = private["d"].as_str().expect("private key member");
    assert!(!stdout(&output).contains(secret));
    assert!(!stderr(&output).contains(secret));
    assert_no_staging_directories(workspace.path());
}

#[test]
fn new_writes_the_project_marker_byte_for_byte() {
    let workspace = TempDir::new().expect("temporary directory");
    let spec = write_spec(workspace.path(), OPENAPI.as_bytes());
    let project = workspace.path().join("project");
    let output = openapi_new(&project, path(&spec), &[]);
    assert!(output.status.success(), "{}", stderr(&output));

    assert_eq!(
        fs::read(project.join("evidence-project.yaml")).expect("project marker"),
        registry_evidence_authoring::default_project_marker_document().as_bytes()
    );
    assert_eq!(
        fs::metadata(project.join("evidence-project.yaml"))
            .expect("project marker metadata")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
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

#[test]
fn sqlite_extract_refuses_existing_and_symlink_destinations_without_changes() {
    let workspace = TempDir::new().expect("temporary directory");

    let directory = workspace.path().join("existing");
    fs::create_dir(&directory).expect("existing directory");
    fs::write(directory.join("sentinel"), b"unchanged").expect("sentinel");
    let output = sqlite_new(&directory, &[]);
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
    let output = sqlite_new(&symlinked, &[]);
    assert!(!output.status.success());
    assert_eq!(
        fs::read(external.join("sentinel")).expect("external sentinel"),
        b"external"
    );
    assert_eq!(entries(&external), ["sentinel"]);
    assert_no_staging_directories(workspace.path());
}

#[test]
fn the_starter_ships_a_readme_that_names_every_file_it_wrote() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    assert!(sqlite_new(&project, &[]).status.success());

    let readme = fs::read_to_string(project.join("README.md")).expect("starter README reads");
    for named in [
        "evidence-project.yaml",
        "selectors/record-reference-v1.yaml",
        "sources/record-status.yaml",
        "queries/record-status.sql",
        "adapters/record-status-extract.rhai",
        "schemas/record-status-response.schema.yaml",
        "schemas/record-status-facts.schema.yaml",
        "questions/record-status.yaml",
        "derivations/record-status.rhai",
        "fixtures/record-status.yaml",
        "secrets/",
    ] {
        assert!(readme.contains(named), "the README names {named}");
    }
    assert!(
        readme.contains("evidencectl fixtures run --project ."),
        "the README names the next command: {readme}"
    );
}

#[test]
fn the_retained_openapi_project_ships_a_readme_that_says_what_is_empty() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    let specification = write_spec(workspace.path(), OPENAPI.as_bytes());
    assert!(openapi_new(&project, path(&specification), &[])
        .status
        .success());

    let readme = fs::read_to_string(project.join("README.md")).expect("retained README reads");
    for named in [
        "evidence-project.yaml",
        "source.openapi.yaml",
        "selectors/",
        "sources/",
        "questions/",
        "fixtures/",
        "secrets/",
    ] {
        assert!(readme.contains(named), "the README names {named}");
    }
    assert!(
        readme.contains("evidencectl source suggest --project ."),
        "the README names the next command: {readme}"
    );
}

#[test]
fn every_generated_starter_file_says_what_its_blocks_do() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    assert!(sqlite_new(&project, &[]).status.success());

    // One comment per block of the generated question, source, and fixture is
    // what separates a starter a reader can edit from one they can only run.
    for (relative, blocks) in [
        ("selectors/record-reference-v1.yaml", 2),
        ("sources/record-status.yaml", 8),
        ("queries/record-status.sql", 1),
        ("adapters/record-status-extract.rhai", 2),
        ("schemas/record-status-response.schema.yaml", 1),
        ("schemas/record-status-facts.schema.yaml", 1),
        ("questions/record-status.yaml", 7),
        ("derivations/record-status.rhai", 2),
        ("fixtures/record-status.yaml", 5),
    ] {
        let content = fs::read_to_string(project.join(relative))
            .unwrap_or_else(|error| panic!("{relative} reads: {error}"));
        let marker = if relative.ends_with(".rhai") {
            "//"
        } else if relative.ends_with(".sql") {
            "--"
        } else {
            "#"
        };
        let counted = content
            .lines()
            .filter(|line| line.trim_start().starts_with(marker))
            .count();
        assert!(
            counted >= blocks,
            "{relative} explains {counted} of its {blocks} blocks"
        );
    }
}

#[test]
fn the_starter_links_only_documentation_pages_that_ship() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    assert!(sqlite_new(&project, &[]).status.success());
    let retained = workspace.path().join("retained");
    let specification = write_spec(workspace.path(), OPENAPI.as_bytes());
    assert!(openapi_new(&retained, path(&specification), &[])
        .status
        .success());

    let documentation =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/site/src/content/docs");
    let mut checked = 0usize;
    for root in [&project, &retained] {
        for relative in generated_files(root) {
            let Ok(content) = fs::read_to_string(root.join(&relative)) else {
                continue;
            };
            for link in documentation_links(&content) {
                checked += 1;
                let (route, anchor) = match link.split_once('#') {
                    Some((route, anchor)) => (route, Some(anchor)),
                    None => (link.as_str(), None),
                };
                let route = route.trim_matches('/');
                let page = [
                    documentation.join(format!("{route}.mdx")),
                    documentation.join(format!("{route}.md")),
                    documentation.join(route).join("index.mdx"),
                ]
                .into_iter()
                .find(|candidate| candidate.is_file())
                .unwrap_or_else(|| panic!("{relative} links {link}, which has no page"));
                let source = fs::read_to_string(&page).expect("documentation page reads");
                let frontmatter = source
                    .split("---")
                    .nth(1)
                    .expect("documentation page has frontmatter");
                assert!(
                    !frontmatter.contains("draft: true"),
                    "{relative} links {link}, whose page is not published"
                );
                if let Some(anchor) = anchor {
                    assert!(
                        source
                            .lines()
                            .filter(|line| line.starts_with('#'))
                            .any(|line| heading_slug(line) == anchor),
                        "{relative} links {link}, whose page has no such heading"
                    );
                }
            }
        }
    }
    assert!(checked > 0, "the starter links the documentation");
}

/// Every ordinary file a scaffolded project holds, relative to its root.
fn generated_files(root: &Path) -> Vec<String> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).expect("scaffolded directory reads") {
            let entry = entry.expect("scaffolded entry reads");
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(
                    path.strip_prefix(root)
                        .expect("scaffolded path is inside the project")
                        .display()
                        .to_string(),
                );
            }
        }
    }
    files.sort();
    files
}

/// Collects every published documentation URL a generated file carries.
fn documentation_links(content: &str) -> Vec<String> {
    const PREFIX: &str = "https://docs.registrystack.org/";
    let mut links = Vec::new();
    let mut rest = content;
    while let Some(start) = rest.find(PREFIX) {
        rest = &rest[start + PREFIX.len()..];
        let end = rest
            .find(|character: char| character.is_whitespace() || ">)\"'".contains(character))
            .unwrap_or(rest.len());
        links.push(rest[..end].to_owned());
        rest = &rest[end..];
    }
    links
}

/// Renders a Markdown heading the way the documentation site anchors it.
fn heading_slug(heading: &str) -> String {
    let mut slug = String::new();
    for character in heading.trim_start_matches('#').trim().chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    slug.trim_matches('-').to_owned()
}

fn assert_minimal_project(project: &Path, with_keys: bool) {
    let expected = if with_keys {
        vec![
            ".evidence-editor",
            ".gitignore",
            ".vscode",
            ".zed",
            "README.md",
            "adapters",
            "derivations",
            "evidence-project.yaml",
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
            ".evidence-editor",
            ".gitignore",
            ".vscode",
            ".zed",
            "README.md",
            "adapters",
            "derivations",
            "evidence-project.yaml",
            "fixtures",
            "questions",
            "schemas",
            "selectors",
            "source.openapi.yaml",
            "sources",
        ]
    };
    assert_eq!(entries(project), expected);
    assert_editor_schema_mappings(project);
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
    for absent in ["bundle", "runtime.yaml", "evidence.yaml", "queries"] {
        assert!(
            !project.join(absent).exists(),
            "unexpected generated {absent}"
        );
    }
}

/// A scaffolded project is editable before it is buildable, so the schema
/// mappings a YAML-aware editor reads ship with it rather than after it.
fn assert_editor_schema_mappings(project: &Path) {
    assert_eq!(
        entries(&project.join(".evidence-editor")),
        vec!["manifest.json", "schemas"]
    );
    assert_eq!(
        entries(&project.join(".evidence-editor/schemas")),
        vec!["project-marker.schema.json", "question.schema.json"]
    );
    assert_eq!(
        entries(&project.join(".vscode")),
        vec!["extensions.json", "settings.json"]
    );
    assert_eq!(entries(&project.join(".zed")), vec!["settings.json"]);

    // The schemas an editor reads must be the committed generated artifact,
    // byte for byte, or the drift gate is guarding nothing an adopter sees.
    for (relative, committed) in [
        (
            ".evidence-editor/schemas/question.schema.json",
            include_str!("../schemas/authoring/question.schema.json"),
        ),
        (
            ".evidence-editor/schemas/project-marker.schema.json",
            include_str!("../schemas/authoring/project-marker.schema.json"),
        ),
    ] {
        assert_eq!(
            fs::read_to_string(project.join(relative)).expect("installed editor schema"),
            committed,
            "{relative} is not the committed generated schema"
        );
    }

    let settings: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(project.join(".vscode/settings.json")).expect("VS Code settings"),
    )
    .expect("VS Code settings are JSON");
    assert_eq!(
        settings["yaml.schemas"]["./.evidence-editor/schemas/question.schema.json"],
        serde_json::Value::String("questions/*.yaml".to_string())
    );
}

fn assert_sqlite_project(project: &Path) {
    assert_eq!(
        entries(project),
        [
            ".evidence-editor",
            ".gitignore",
            ".vscode",
            ".zed",
            "README.md",
            "adapters",
            "derivations",
            "evidence-project.yaml",
            "fixtures",
            "queries",
            "questions",
            "schemas",
            "secrets",
            "selectors",
            "sources",
        ]
    );
    for file in [
        "selectors/record-reference-v1.yaml",
        "sources/record-status.yaml",
        "queries/record-status.sql",
        "adapters/record-status-extract.rhai",
        "schemas/record-status-response.schema.yaml",
        "schemas/record-status-facts.schema.yaml",
        "questions/record-status.yaml",
        "derivations/record-status.rhai",
        "fixtures/record-status.yaml",
    ] {
        assert!(project.join(file).is_file(), "missing starter file {file}");
    }
    assert!(!project.join("source.openapi.yaml").exists());
    assert_eq!(
        fs::read_to_string(project.join(".gitignore")).expect("gitignore"),
        "secrets/\n.evidence/\n"
    );
    assert_eq!(
        fs::metadata(project.join("secrets"))
            .expect("secret directory")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_editor_schema_mappings(project);
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

fn sqlite_new(project: &Path, extra: &[&str]) -> Output {
    let mut arguments = vec![
        "new",
        path(project),
        "--transport",
        "sqlite-extract",
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
