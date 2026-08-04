//! Acceptance tests for the minimal `evidencectl new --openapi` path.

#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::TempDir;

const OPENAPI: &str = r#"openapi: 3.1.0
info:
  title: Records
  version: 1.0.0
servers:
  - url: http://127.0.0.1:8765/api
paths:
  /records/{person_id}:
    get:
      responses:
        '200':
          description: one record
          content:
            application/json:
              schema:
                type: object
                required: [status]
                properties:
                  status:
                    type: string
                    minLength: 1
                    maxLength: 16
"#;

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
    let spec = write_spec(workspace.path());
    let project = workspace.path().join("project");
    let output = evidencectl(&[
        "new",
        path(&project),
        "--openapi",
        path(&spec),
        "--operation",
        "GET /records/{person_id}",
        "--select",
        "/status",
    ]);

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
fn invalid_or_incomplete_openapi_input_writes_nothing() {
    let workspace = TempDir::new().expect("temporary directory");
    let spec = write_spec(workspace.path());
    let missing_decisions = workspace.path().join("missing-decisions");
    let output = evidencectl(&[
        "new",
        path(&missing_decisions),
        "--openapi",
        path(&spec),
        "--profile",
        "local",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("needs --operation and --select"));
    assert!(!missing_decisions.exists());

    let invalid_spec = workspace.path().join("invalid.yaml");
    fs::write(&invalid_spec, "not: openapi\n").expect("invalid spec");
    let invalid_project = workspace.path().join("invalid-project");
    let output = evidencectl(&[
        "new",
        path(&invalid_project),
        "--openapi",
        path(&invalid_spec),
        "--profile",
        "local",
        "--operation",
        "GET /records/{person_id}",
        "--select",
        "/status",
    ]);
    assert!(!output.status.success());
    assert!(!invalid_project.exists());
    assert_no_staging_directories(workspace.path());
}

#[test]
fn openapi_new_emits_only_mechanical_authoring_artifacts() {
    let workspace = TempDir::new().expect("temporary directory");
    let spec = write_spec(workspace.path());
    let project = workspace.path().join("project");
    let output = openapi_new(&project, &spec, &[]);
    assert!(output.status.success(), "{}", stderr(&output));

    assert_eq!(entries(&project), ["bundle"]);
    assert_eq!(
        entries(&project.join("bundle")),
        ["adapters", "evidence.yaml", "schemas"]
    );
    assert_eq!(
        entries(&project.join("bundle/adapters")),
        ["records-extract.rhai"]
    );
    assert_eq!(
        entries(&project.join("bundle/schemas")),
        ["records-facts.schema.yaml", "records-response.schema.yaml"]
    );

    let text = fs::read_to_string(project.join("bundle/evidence.yaml")).expect("source draft");
    let yaml: serde_norway::Value = serde_norway::from_str(&text).expect("draft YAML");
    let root = yaml.as_mapping().expect("draft mapping");
    assert_eq!(root.len(), 3, "unexpected generated root keys: {text}");
    assert_eq!(yaml["version"], 1);
    assert_eq!(yaml["assuranceProfile"], "local");
    let source = &yaml["sources"]["records"];
    assert_eq!(source["transport"], "http-json");
    assert_eq!(source["request"]["method"], "GET");
    assert_eq!(
        source["request"]["pathTemplate"],
        "/api/records/{person_id}"
    );
    assert_eq!(source["request"]["projection"][0], "/status");
    assert_eq!(
        source["request"]["fixedHeaders"][0]["value"],
        "application/json"
    );

    assert!(text.contains("# baseUrl: http://127.0.0.1:8765"));
    for absent in [
        "baseUrl:",
        "posture:",
        "authentication:",
        "selectorInputs:",
        "prepareScript:",
        "preparationLimits:",
        "redirects:",
        "timeoutMilliseconds:",
        "requirements:",
        "authorityProfiles:",
        "signing:",
        "audit:",
    ] {
        if absent == "baseUrl:" {
            assert_eq!(
                text.matches(absent).count(),
                1,
                "origin must be comment-only"
            );
        } else {
            assert!(!text.contains(absent), "draft invented `{absent}`:\n{text}");
        }
    }
    for absent in ["README.md", "runtime.yaml", "fixtures", "derivations"] {
        assert!(
            !project.join(absent).exists(),
            "unexpected generated {absent}"
        );
    }
    assert!(stdout(&output).contains("not a runnable deployment"));
}

#[test]
fn generate_keys_is_unbound_owner_only_and_prints_no_secret() {
    let workspace = TempDir::new().expect("temporary directory");
    let spec = write_spec(workspace.path());
    let project = workspace.path().join("project");
    let output = openapi_new(&project, &spec, &["--generate-keys"]);
    assert!(output.status.success(), "{}", stderr(&output));

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
    assert_eq!(
        fs::read_to_string(project.join(".gitignore")).expect("gitignore"),
        "secrets/\n"
    );

    let private = fs::read_to_string(project.join("secrets/signing-ed25519-private-jwk"))
        .expect("private JWK");
    let private: serde_json::Value = serde_json::from_str(&private).expect("private JWK JSON");
    let secret = private["d"].as_str().expect("private key member");
    assert!(!stdout(&output).contains(secret));
    assert!(!stderr(&output).contains(secret));

    let draft = fs::read_to_string(project.join("bundle/evidence.yaml")).expect("source draft");
    for binding in ["signing:", "activeKeyRef:", "audit:", "secret:file/"] {
        assert!(
            !draft.contains(binding),
            "generated keys were bound by `{binding}`"
        );
    }
}

#[test]
fn existing_paths_and_force_are_refused_without_changes() {
    let workspace = TempDir::new().expect("temporary directory");
    let spec = write_spec(workspace.path());

    let directory = workspace.path().join("existing");
    fs::create_dir(&directory).expect("existing directory");
    fs::write(directory.join("sentinel"), b"unchanged").expect("sentinel");
    let output = openapi_new(&directory, &spec, &[]);
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
    let output = openapi_new(&symlinked, &spec, &["--generate-keys"]);
    assert!(!output.status.success());
    assert_eq!(
        fs::read(external.join("sentinel")).expect("external sentinel"),
        b"external"
    );
    assert_eq!(entries(&external), ["sentinel"]);

    let forced = workspace.path().join("forced");
    let output = openapi_new(&forced, &spec, &["--force"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unexpected argument '--force'"));
    assert!(!forced.exists());
    assert_no_staging_directories(workspace.path());
}

fn openapi_new(project: &Path, spec: &Path, extra: &[&str]) -> Output {
    let mut arguments = vec![
        "new",
        path(project),
        "--openapi",
        path(spec),
        "--profile",
        "local",
        "--operation",
        "GET /records/{person_id}",
        "--select",
        "/status",
        "--source-id",
        "records",
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

fn write_spec(root: &Path) -> PathBuf {
    let path = root.join("records.openapi.yaml");
    fs::write(&path, OPENAPI).expect("OpenAPI fixture");
    path
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
