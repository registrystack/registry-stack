//! Acceptance tests for the minimal `evidencectl init` authoring paths.

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
fn bare_init_names_both_authoring_inputs_and_writes_nothing() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    let output = evidencectl(&["init", path(&project)]);

    assert_safe_usage_failure(&output);
    assert!(!project.exists());
}

#[test]
fn sqlite_extract_requires_the_explicit_local_profile_before_writing() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    let output = evidencectl(&["init", path(&project), "--transport", "sqlite-extract"]);

    assert_safe_usage_failure(&output);
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
    assert!(printed.contains("evidencectl check"));
    assert!(printed.contains("evidencectl test"));
    assert!(printed.contains("normalized synthetic Source, AssertionDefinition, and local target"));
    assert!(!printed.contains("source suggest"));
}

#[test]
fn readme_only_starter_creates_a_normalized_offline_project() {
    let workspace = TempDir::new().expect("temporary directory");
    let starter = write_local_starter(workspace.path());
    let project = workspace.path().join("project");
    let output = starter_new(&project, &starter, &[]);
    assert!(output.status.success(), "{}", stderr(&output));

    assert_starter_project(&project);
    let printed = stdout(&output);
    assert!(printed.contains("editable starter authoring project"));
    assert!(printed.contains("Starter files were copied from"));
    assert!(printed.contains("evidencectl check"));
    assert!(printed.contains("evidencectl test"));
    assert!(!printed.contains("source suggest"));
}

#[test]
fn a_complete_normalized_starter_is_preserved_with_its_assets_and_grants() {
    let workspace = TempDir::new().expect("temporary directory");
    let root = fs::canonicalize(workspace.path()).expect("canonical temporary directory");
    let starter = root.join("reviewed-starter");
    let created = sqlite_new(&starter, &[]);
    assert!(created.status.success(), "{}", stderr(&created));

    for relative in ["evidence.yaml", "local-target.yaml", "dev-authority.yaml"] {
        let path = starter.join(relative);
        let document = fs::read_to_string(&path).expect("starter document");
        fs::write(
            &path,
            document.replace("local-evidence", "reviewed-evidence"),
        )
        .expect("give the reviewed starter a distinct project id");
    }
    fs::write(
        starter.join("serve-source.py"),
        b"print('synthetic reviewed source')\n",
    )
    .expect("reviewed source helper");

    let expected = [
        "evidence.yaml",
        "local-target.yaml",
        "dev-authority.yaml",
        "functions/extract-record-status.rhai",
        "functions/derive-record-status.rhai",
        "queries/record-status.sql",
        "fixtures/record-status.yaml",
        "serve-source.py",
    ]
    .map(|relative| {
        (
            relative,
            fs::read(starter.join(relative)).expect("reviewed starter asset"),
        )
    });

    let project = root.join("project");
    let output = starter_new(&project, &starter, &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    for (relative, bytes) in expected {
        assert_eq!(
            fs::read(project.join(relative)).expect("copied starter asset"),
            bytes,
            "starter asset {relative} was not preserved"
        );
    }

    let project_document = registry_evidence_authoring::project::read_project(
        "evidence.yaml",
        &fs::read(project.join("evidence.yaml")).expect("copied project"),
    )
    .expect("copied normalized project")
    .value;
    assert_eq!(project_document.id.to_string(), "reviewed-evidence");
    assert_eq!(project_document.functions.len(), 2);
    assert_eq!(project_document.assertion_definitions.len(), 1);
    let authority = registry_evidence_authoring::target::read_authority(
        "dev-authority.yaml",
        &fs::read(project.join("dev-authority.yaml")).expect("copied authority"),
        &project_document,
    )
    .expect("copied complete authority")
    .value;
    assert_eq!(authority.access_profiles.len(), 1);
    assert_eq!(
        authority
            .access_profiles
            .values()
            .map(|profile| profile.grants.len())
            .sum::<usize>(),
        1
    );
}

#[test]
fn a_starter_without_authored_source_files_receives_the_normalized_synthetic_source() {
    let workspace = TempDir::new().expect("temporary directory");
    let starter = write_sourceless_starter(workspace.path());
    let project = workspace.path().join("project");
    let output = starter_new(&project, &starter, &[]);
    assert!(output.status.success(), "{}", stderr(&output));

    let printed = stdout(&output);
    assert!(printed.contains("to prove the copied starter"));
    assert!(project.join("evidence.yaml").is_file());
    assert!(project
        .join("functions/extract-record-status.rhai")
        .is_file());
}

/// A stub `evidence` binary that answers the version handshake with this
/// build's version and succeeds at every step: an empty provider publication
/// description for `render-discovery-description`, a fixed but well-formed
/// revision report for `bundle-check`, and `$CASES` evaluated cases for a
/// fixture evaluation. The real-binary journey separately proves the generated
/// normalized project; this stub isolates the evidencectl pipeline.
fn write_stub_evidence(dir: &Path) -> PathBuf {
    let path = dir.join("evidence");
    let script = format!(
        r#"#!/bin/sh
set -eu

if [ -n "${{EVIDENCE_STUB_LOG:-}}" ]; then
  printf '%s\n' "$*" >> "$EVIDENCE_STUB_LOG"
fi

if [ "${{1:-}}" = "--version" ]; then
  printf 'evidence %s\n' "{version}"
  exit 0
fi

if [ "$1" = "render-discovery-description" ]; then
  printf '{{}}\n'
  exit 0
fi

step=""
for arg in "$@"; do
  case "$arg" in
    bundle-check) step="bundle-check" ;;
    evaluate|bundle-evaluate) step="evaluate" ;;
  esac
done

if [ "$step" = "bundle-check" ]; then
  printf '{{"packageDigest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","requirements":[{{"id":"urn:example:stub:record-active","configurationRevision":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}]}}\n'
  exit 0
fi

if [ "$step" = "evaluate" ] && [ -n "${{CASES:-}}" ]; then
  printf 'Evidence fixture passed (%s evaluated cases)\n' "$CASES"
fi
exit 0
"#,
        version = registry_platform_buildinfo::DISPLAY_VERSION
    );
    fs::write(&path, script).expect("write stub evidence script");
    let mut permissions = fs::metadata(&path).expect("stat stub").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).expect("chmod stub");
    path
}

#[test]
fn the_generated_sqlite_starter_passes_check_and_test_without_source_import() {
    let workspace = TempDir::new().expect("temporary directory");
    let root = fs::canonicalize(workspace.path()).expect("canonical temporary directory");
    let project = root.join("project");
    let output = sqlite_new(&project, &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("to prove the synthetic starter"));
    assert!(project.join("evidence.yaml").is_file());
    assert!(project.join("local-target.yaml").is_file());

    let stub = write_stub_evidence(&root);
    let stub_log = root.join("evidence-stub.log");
    let checked = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(["check", path(&project)])
        .env("EVIDENCE_BIN", &stub)
        .env("EVIDENCE_STUB_LOG", &stub_log)
        .output()
        .expect("check the offline starter");
    assert!(checked.status.success(), "{}", stderr(&checked));
    assert!(
        stdout(&checked).contains("complete"),
        "{}",
        stdout(&checked)
    );

    let tested = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(["test", path(&project)])
        .arg("--evidence-bin")
        .arg(&stub)
        .env("CASES", "13")
        .env("EVIDENCE_STUB_LOG", &stub_log)
        .output()
        .expect("test the offline starter");
    assert!(
        tested.status.success(),
        "{}\nstub calls:\n{}",
        stderr(&tested),
        fs::read_to_string(&stub_log).unwrap_or_default()
    );
    let printed = stdout(&tested);
    assert!(
        printed.contains("PASS: fixtures/record-status.yaml (13 cases)"),
        "{printed}"
    );
}

/// A starter that begins a normalized project must supply its target and
/// authority too. Refuse the partial set before publishing any destination.
#[test]
fn a_partial_normalized_starter_is_refused_before_writing() {
    let workspace = TempDir::new().expect("temporary directory");
    let seed = workspace.path().join("seed");
    let created = sqlite_new(&seed, &[]);
    assert!(created.status.success(), "{}", stderr(&created));

    let starter = workspace.path().join("partial-starter");
    fs::create_dir(&starter).expect("partial starter directory");
    fs::write(starter.join("README.md"), b"# Partial reviewed starter\n")
        .expect("partial starter README");
    fs::copy(seed.join("evidence.yaml"), starter.join("evidence.yaml"))
        .expect("partial starter project");

    let project = workspace.path().join("project");
    let output = starter_new(&project, &starter, &[]);
    assert!(
        !output.status.success(),
        "partial normalized starter was accepted"
    );
    assert!(
        stderr(&output).contains("error[evidence.init.refused]"),
        "{}",
        stderr(&output)
    );
    assert!(!project.exists());
}

/// A SQLite starter whose one question declares a requirement validity of
/// 900 seconds, above the 300 second signing maximum a local target carries.
fn sqlite_project_with_validity_above_the_local_signing_maximum(project: &Path) {
    let output = evidencectl(&[
        "init",
        path(project),
        "--transport",
        "sqlite-extract",
        "--profile",
        "local",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));

    let project_file = project.join("evidence.yaml");
    let authored = fs::read_to_string(&project_file).expect("authored EvidenceProject");
    assert!(authored.contains("validitySeconds: 300"), "{authored}");
    fs::write(
        &project_file,
        authored.replace("validitySeconds: 300", "validitySeconds: 900"),
    )
    .expect("raise the authored requirement validity past the local signing maximum");
}

/// A project-only `check` has no deployment target, and the signing maximum
/// that caps a requirement validity belongs to the target. Any validity the
/// bundle grammar allows therefore passes here.
#[test]
fn project_only_check_accepts_a_requirement_validity_above_the_local_signing_maximum() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    sqlite_project_with_validity_above_the_local_signing_maximum(&project);

    let stub = write_stub_evidence(workspace.path());
    let checked = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(["check", path(&project)])
        .env("EVIDENCE_BIN", &stub)
        .output()
        .expect("check the project");

    assert!(
        checked.status.success(),
        "a project-only check must not apply a deployment signing maximum:\n{}{}",
        stdout(&checked),
        stderr(&checked)
    );
}

/// The offline target check requires the target to bind every extract profile
/// a Source uses, so the generated starter target must bind `record-status`.
/// The binding check lives in the real Evidence binary, so this exact gate
/// needs `EVIDENCE_BIN`.
#[test]
#[ignore = "exact gate: needs the real Evidence binary in EVIDENCE_BIN"]
fn the_generated_sqlite_starter_target_binds_its_extract_profile() {
    let workspace = TempDir::new().expect("temporary directory");
    let root = fs::canonicalize(workspace.path()).expect("canonical temporary directory");
    let project = root.join("project");
    let output = sqlite_new(&project, &[]);
    assert!(output.status.success(), "{}", stderr(&output));

    let evidence = std::env::var_os("EVIDENCE_BIN")
        .expect("set EVIDENCE_BIN to the Evidence binary built from this source");
    let checked = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(["check", path(&project), "--target"])
        .arg(project.join("local-target.yaml"))
        .env("EVIDENCE_BIN", evidence)
        .output()
        .expect("check the starter against its local target");
    let printed = format!("{}{}", stdout(&checked), stderr(&checked));
    assert!(checked.status.success(), "{printed}");
    assert!(!printed.contains("source-extract-unbound"), "{printed}");
}

/// `check --target` refuses a complete target authority grant that exceeds its
/// AssertionDefinition ceiling, then accepts the exact generated grant again.
#[test]
fn target_check_refuses_authority_grant_outside_the_definition_ceiling() {
    let workspace = TempDir::new().expect("temporary directory");
    // A deployment target path must have no symlinked component, and the
    // platform temporary directory may sit behind one.
    let root = fs::canonicalize(workspace.path()).expect("canonical temporary directory");
    let project = root.join("project");
    sqlite_project_with_validity_above_the_local_signing_maximum(&project);
    let target = project.join("targets/local");
    let created = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(["target", "new", path(&target), "--project", path(&project)])
        .arg("--local")
        .output()
        .expect("create a local target");
    assert!(created.status.success(), "{}", stderr(&created));
    let authority_path = target.join("authority.yaml");
    let authority = fs::read_to_string(&authority_path).expect("target authority");
    assert!(authority.contains("kind: EvidenceTargetAuthority"));
    let excessive = authority.replace("purpose: record-status-check", "purpose: unrelated-use");
    assert_ne!(excessive, authority);
    fs::write(&authority_path, excessive).expect("write excessive target grant");

    let explain_target = || {
        Command::new(env!("CARGO_BIN_EXE_evidencectl"))
            .args(["target", "explain", path(&target), path(&project)])
            .output()
            .expect("explain the project target")
    };

    let refused = explain_target();
    assert!(
        !refused.status.success(),
        "target explain must refuse a grant outside the definition ceiling:\n{}",
        stdout(&refused)
    );
    let printed = format!("{}{}", stdout(&refused), stderr(&refused));
    assert!(printed.contains("evidence.authority.ceiling"), "{printed}");

    fs::write(&authority_path, authority).expect("restore exact generated target authority");
    let accepted = explain_target();
    assert!(
        accepted.status.success(),
        "the exact generated target authority must pass:\n{}{}",
        stdout(&accepted),
        stderr(&accepted)
    );
}

#[test]
fn openapi_and_sqlite_extract_are_mutually_exclusive_before_writing() {
    let workspace = TempDir::new().expect("temporary directory");
    let spec = write_spec(workspace.path(), OPENAPI.as_bytes());
    let project = workspace.path().join("project");
    let output = evidencectl(&[
        "init",
        path(&project),
        "--openapi",
        path(&spec),
        "--transport",
        "sqlite-extract",
        "--profile",
        "local",
    ]);

    assert_safe_usage_failure(&output);
    assert!(!project.exists());

    let starter_project = workspace.path().join("starter-project");
    let output = evidencectl(&[
        "init",
        path(&starter_project),
        "--starter",
        "local",
        "--transport",
        "sqlite-extract",
        "--profile",
        "local",
    ]);
    assert_safe_usage_failure(&output);
    assert!(!starter_project.exists());
}

#[test]
fn openapi_requires_the_explicit_local_profile_before_writing() {
    let workspace = TempDir::new().expect("temporary directory");
    let spec = write_spec(workspace.path(), OPENAPI.as_bytes());
    let project = workspace.path().join("project");
    let output = evidencectl(&["init", path(&project), "--openapi", path(&spec)]);

    assert_safe_usage_failure(&output);
    assert!(!project.exists());

    let wrong = workspace.path().join("wrong");
    let output = evidencectl(&[
        "init",
        path(&wrong),
        "--openapi",
        path(&spec),
        "--profile",
        "production",
    ]);
    assert_safe_usage_failure(&output);
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
    assert!(stdout(&output).contains("normalized synthetic starter and local target"));
    let next = format!("evidencectl source suggest {}`", project.display());
    assert!(stdout(&output).contains(&next), "{}", stdout(&output));
    assert!(!stdout(&output).contains("--project"));
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
    let output = openapi_new(&invalid_project, path(&invalid), &[]);
    assert!(!output.status.success());
    assert!(!invalid_project.exists());

    let failed_url = serve_once(500, b"failure\n".to_vec());
    let failed_project = workspace.path().join("failed-project");
    let output = openapi_new(&failed_project, &failed_url, &[]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("HTTP 500"));
    assert!(stderr(&output).contains("evidence.openapi.http-status"));
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

    for (name, url, sensitive, expected, code) in [
        (
            "userinfo",
            format!("http://reader:userinfo-secret@{address}/openapi.yaml"),
            "userinfo-secret",
            "credentials",
            "evidence.openapi.url-credentials",
        ),
        (
            "query",
            format!("http://{address}/openapi.yaml?access_token=query-secret"),
            "query-secret",
            "query or fragment",
            "evidence.openapi.url-components",
        ),
        (
            "fragment",
            format!("http://{address}/openapi.yaml#private-fragment"),
            "private-fragment",
            "query or fragment",
            "evidence.openapi.url-components",
        ),
    ] {
        let project = workspace.path().join(name);
        let output = openapi_new(&project, &url, &[]);
        assert!(!output.status.success());
        let logged = format!("{}{}", stdout(&output), stderr(&output));
        assert!(logged.contains(expected), "unexpected refusal: {logged}");
        assert!(logged.contains(code), "unexpected refusal: {logged}");
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
        fs::metadata(project.join(".generated/secrets"))
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
            fs::metadata(project.join(".generated/secrets").join(name))
                .unwrap_or_else(|error| panic!("reading {name}: {error}"))
                .permissions()
                .mode()
                & 0o777,
            mode
        );
    }

    let private = fs::read_to_string(project.join(".generated/secrets/signing-p256-private-jwk"))
        .expect("private JWK");
    let private: serde_json::Value = serde_json::from_str(&private).expect("private JWK JSON");
    let secret = private["d"].as_str().expect("private key member");
    assert!(!stdout(&output).contains(secret));
    assert!(!stderr(&output).contains(secret));
    assert_no_staging_directories(workspace.path());
}

#[test]
fn init_writes_the_normalized_project_envelope() {
    let workspace = TempDir::new().expect("temporary directory");
    let spec = write_spec(workspace.path(), OPENAPI.as_bytes());
    let project = workspace.path().join("project");
    let output = openapi_new(&project, path(&spec), &[]);
    assert!(output.status.success(), "{}", stderr(&output));

    assert!(fs::read_to_string(project.join("evidence.yaml"))
        .expect("normalized EvidenceProject")
        .contains("kind: EvidenceProject"));
    let fixture_bytes = fs::read(project.join("fixtures/record-status.yaml")).unwrap();
    let fixture = registry_platform_yaml::Reader::new("fixture")
        .scan(&fixture_bytes)
        .unwrap()
        .unwrap()
        .to_json_value();
    assert_eq!(
        fixture["coequalAcceptanceDefinition"], true,
        "HTTP source cases select the coequal evaluator"
    );
    assert_eq!(fixture["syntheticOnly"], true);
    assert!(fixture["cases"][0].get("source").is_some());
    assert!(fixture["cases"][0].get("expectedValue").is_some());
    assert!(fixture.get("synthetic_only").is_none());

    assert_eq!(
        fs::metadata(project.join("evidence.yaml"))
            .expect("project metadata")
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
    let output = openapi_new(&symlinked, path(&spec), &[]);
    assert!(!output.status.success());
    assert_eq!(
        fs::read(external.join("sentinel")).expect("external sentinel"),
        b"external"
    );
    assert_eq!(entries(&external), ["sentinel"]);

    for unsupported in ["--force", "--generate-keys"] {
        let refused = workspace.path().join("refused");
        let output = openapi_new(&refused, path(&spec), &[unsupported]);
        assert_safe_usage_failure(&output);
        assert!(!refused.exists());
    }
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
        "evidence.yaml",
        "queries/record-status.sql",
        "functions/extract-record-status.rhai",
        "functions/derive-record-status.rhai",
        "fixtures/record-status.yaml",
        "local-target.yaml",
        "dev-authority.yaml",
        ".generated/secrets/",
    ] {
        assert!(readme.contains(named), "the README names {named}");
    }
    assert!(
        readme.contains("evidencectl test ."),
        "the README names the next command: {readme}"
    );
}

#[test]
fn the_retained_openapi_project_ships_a_readme_that_says_what_is_empty() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    let specification = write_spec(
        workspace.path(),
        br#"{"openapi":"3.1.0","info":{"title":"Records","version":"1.0.0"},"servers":[{"url":"https://records.example.test"}],"paths":{"/records":{"get":{"responses":{"200":{"description":"Record status","content":{"application/json":{"schema":{"type":"object","required":["active"],"properties":{"active":{"type":"boolean"}}}}}}}}}}}"#,
    );
    assert!(openapi_new(&project, path(&specification), &[])
        .status
        .success());

    let readme = fs::read_to_string(project.join("README.md")).expect("retained README reads");
    for named in [
        "evidence.yaml",
        "source.openapi.yaml",
        "functions/",
        "fixtures/",
        "local-target.yaml",
        "dev-authority.yaml",
        ".generated/secrets/",
    ] {
        assert!(readme.contains(named), "the README names {named}");
    }
    let template = readme
        .lines()
        .find(|line| line.starts_with("evidencectl source suggest "))
        .expect("the README gives a source suggestion command");
    let command = template
        .replace("<id>", "records")
        .replace("<METHOD /path>", "GET /records");
    let (arguments, operation) = command
        .strip_prefix("evidencectl ")
        .expect("the command invokes evidencectl")
        .split_once(" --operation '")
        .expect("the command quotes its operation");
    let operation = operation
        .strip_suffix('\'')
        .expect("the operation's closing quote");
    // Listing pointers exercises the documented project and operation arguments
    // without an interactive projection selection or a source request.
    let suggested = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(arguments.split_whitespace())
        .args(["--operation", operation, "--list-pointers"])
        .current_dir(&project)
        .output()
        .expect("run the generated README command");
    assert!(
        suggested.status.success(),
        "the README command must run: {}{}",
        stdout(&suggested),
        stderr(&suggested)
    );
    assert!(stdout(&suggested).contains("/active"));
}

#[test]
fn every_generated_starter_file_says_what_its_blocks_do() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    assert!(sqlite_new(&project, &[]).status.success());

    let project_file = project.join("evidence.yaml");
    let authored = registry_evidence_authoring::project::read_project(
        &project_file.to_string_lossy(),
        &fs::read(&project_file).expect("generated project reads"),
    )
    .expect("generated project is normalized")
    .value;
    assert_eq!(authored.functions.len(), 2);
    assert!(authored.functions.iter().all(|function| {
        function.source.starts_with("functions/") && function.source.ends_with(".rhai")
    }));
    let record_status = "record-status".parse().expect("valid local identifier");
    let source = authored.sources.get(&record_status).expect("named Source");
    assert!(source.prepare.is_none());
    assert_eq!(source.extract.function.to_string(), "extract-record-status");
    assert_eq!(source.response.maximum_bytes.get(), 8_192);
    assert_eq!(source.limits.attempt_timeout_milliseconds.get(), 2_000);
    assert_eq!(source.limits.maximum_concurrency.get(), 8);
    let definition = authored
        .assertion_definitions
        .get(&record_status)
        .expect("named AssertionDefinition");
    assert_eq!(
        definition.derive.function.to_string(),
        "derive-record-status"
    );
    let satisfied = "satisfied".parse().expect("valid output identifier");
    assert!(definition.outputs.contains_key(&satisfied));

    for relative in [
        "queries/record-status.sql",
        "functions/extract-record-status.rhai",
        "functions/derive-record-status.rhai",
        "fixtures/record-status.yaml",
    ] {
        assert!(project.join(relative).is_file(), "generated {relative}");
    }

    let target_file = project.join("local-target.yaml");
    let target = registry_evidence_authoring::target::read_target(
        &target_file.to_string_lossy(),
        &fs::read(&target_file).expect("generated target reads"),
    )
    .expect("generated target is normalized")
    .value;
    assert_eq!(target.project, authored.id);
    assert_eq!(target.authority, "dev-authority.yaml");
    let authority_file = project.join(&target.authority);
    let authority = registry_evidence_authoring::target::read_authority(
        &authority_file.to_string_lossy(),
        &fs::read(&authority_file).expect("generated authority reads"),
        &authored,
    )
    .expect("generated authority is complete")
    .value;
    let grants = authority
        .access_profiles
        .values()
        .flat_map(|profile| &profile.grants)
        .collect::<Vec<_>>();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].definition, record_status);
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
    let cli_reference = cli_reference_binaries();
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
                if let Some(binary) = route.strip_prefix("reference/cli/") {
                    // The CLI reference pages are generated from the command
                    // catalog when the site builds and are not tracked, so the
                    // catalog stands in for them.
                    assert!(
                        cli_reference.contains(&binary.to_owned()),
                        "{relative} links {link}, which names no catalogued binary"
                    );
                    assert!(
                        anchor.is_none(),
                        "{relative} links {link}; anchors on generated CLI pages are not checked"
                    );
                    continue;
                }
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

/// The binaries the CLI reference catalog documents, one generated page each.
fn cli_reference_binaries() -> Vec<String> {
    let catalog = Path::new(env!("CARGO_MANIFEST_DIR")).join("../registry-cli-docs/catalog.json");
    let catalog: serde_json::Value =
        serde_json::from_slice(&fs::read(catalog).expect("CLI catalog reads"))
            .expect("CLI catalog is JSON");
    catalog["binaries"]
        .as_array()
        .expect("CLI catalog lists binaries")
        .iter()
        .map(|binary| {
            binary["name"]
                .as_str()
                .expect("catalogued binary has a name")
                .to_owned()
        })
        .collect()
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
    let expected = vec![
        ".evidence-editor",
        ".generated",
        ".gitignore",
        ".vscode",
        ".zed",
        "README.md",
        "dev-authority.yaml",
        "evidence.yaml",
        "fixtures",
        "functions",
        "local-target.yaml",
        "source.openapi.yaml",
    ];
    assert_eq!(entries(project), expected);
    assert_editor_schema_mappings(project);
    assert!(project.join("evidence.yaml").is_file());
    assert!(project.join("local-target.yaml").is_file());
    assert!(project.join("dev-authority.yaml").is_file());
    assert!(project
        .join("functions/extract-record-status.rhai")
        .is_file());
    assert_eq!(
        fs::read_to_string(project.join(".gitignore")).expect("gitignore"),
        ".generated/secrets/\n.evidence/\n"
    );
    if with_keys {
        assert!(project.join(".generated/secrets").is_dir());
    }
    for absent in [
        "bundle",
        "runtime.yaml",
        "evidence-project.yaml",
        "questions",
    ] {
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
        vec![
            "access-client.schema.json",
            "fixture.schema.json",
            "mock-plan.schema.json",
            "project.schema.json",
            "target-authority.schema.json",
            "target.schema.json"
        ]
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
            ".evidence-editor/schemas/access-client.schema.json",
            include_str!("../schemas/authoring/access-client.schema.json"),
        ),
        (
            ".evidence-editor/schemas/mock-plan.schema.json",
            include_str!("../schemas/authoring/mock-plan.schema.json"),
        ),
        (
            ".evidence-editor/schemas/fixture.schema.json",
            include_str!("../../../products/evidence/generated/fixture/fixture.schema.json"),
        ),
        (
            ".evidence-editor/schemas/project.schema.json",
            include_str!("../schemas/authoring/project.schema.json"),
        ),
        (
            ".evidence-editor/schemas/target.schema.json",
            include_str!("../schemas/authoring/target.schema.json"),
        ),
        (
            ".evidence-editor/schemas/target-authority.schema.json",
            include_str!("../schemas/authoring/target-authority.schema.json"),
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
        settings["yaml.schemas"]["./.evidence-editor/schemas/project.schema.json"],
        serde_json::Value::String("evidence.yaml".to_string())
    );
}

fn assert_sqlite_project(project: &Path) {
    assert_eq!(
        entries(project),
        [
            ".evidence-editor",
            ".generated",
            ".gitignore",
            ".vscode",
            ".zed",
            "README.md",
            "dev-authority.yaml",
            "evidence.yaml",
            "fixtures",
            "functions",
            "local-target.yaml",
            "queries",
        ]
    );
    assert_common_starter_files(project);
}

fn assert_starter_project(project: &Path) {
    assert_eq!(
        entries(project),
        [
            ".evidence-editor",
            ".generated",
            ".gitignore",
            ".vscode",
            ".zed",
            "README.md",
            "dev-authority.yaml",
            "evidence.yaml",
            "fixtures",
            "functions",
            "local-target.yaml",
        ]
    );
    for file in [
        "evidence.yaml",
        "functions/extract-record-status.rhai",
        "functions/derive-record-status.rhai",
        "fixtures/record-status.yaml",
        "local-target.yaml",
        "dev-authority.yaml",
    ] {
        assert!(project.join(file).is_file(), "missing starter file {file}");
    }
    assert_editor_schema_mappings(project);
}

fn assert_common_starter_files(project: &Path) {
    for file in [
        "evidence.yaml",
        "queries/record-status.sql",
        "functions/extract-record-status.rhai",
        "functions/derive-record-status.rhai",
        "fixtures/record-status.yaml",
        "local-target.yaml",
        "dev-authority.yaml",
    ] {
        assert!(project.join(file).is_file(), "missing starter file {file}");
    }
    assert!(!project.join("source.openapi.yaml").exists());
    assert_eq!(
        fs::read_to_string(project.join(".gitignore")).expect("gitignore"),
        ".generated/secrets/\n.evidence/\n"
    );
    assert_eq!(
        fs::metadata(project.join(".generated/secrets"))
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
        "init",
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
        "init",
        path(project),
        "--transport",
        "sqlite-extract",
        "--profile",
        "local",
    ];
    arguments.extend_from_slice(extra);
    evidencectl(&arguments)
}

fn starter_new(project: &Path, starter: &Path, extra: &[&str]) -> Output {
    let mut arguments = vec![
        "init",
        path(project),
        "--starter",
        path(starter),
        "--profile",
        "local",
    ];
    arguments.extend_from_slice(extra);
    evidencectl(&arguments)
}

fn write_local_starter(root: &Path) -> PathBuf {
    let starter = root.join("starter");
    fs::create_dir(&starter).expect("starter directory");
    fs::write(starter.join("README.md"), b"# Reviewed starter\n").expect("starter README");
    starter
}

fn write_sourceless_starter(root: &Path) -> PathBuf {
    let starter = root.join("sourceless-starter");
    fs::create_dir(&starter).expect("starter directory");
    fs::write(starter.join("README.md"), b"# Source-first starter\n").expect("starter README");
    starter
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

fn assert_safe_usage_failure(output: &Output) {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        stderr(output),
        "error[evidencectl.usage] command line $: The Evidence command line is incomplete or contains conflicting or unsupported arguments.\n  next: Run evidencectl --help or the selected command with --help, then retry using the documented arguments.\n"
    );
}
