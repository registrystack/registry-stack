#![cfg(unix)]
#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]

use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt as _},
    path::Path,
    process::{Command, Output},
};

use registry_platform_crypto::{PrivateJwk, PublicJwk};
use serde_json::Value;

fn evidencectl(project: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(arguments)
        .arg("--project")
        .arg(project)
        .output()
        .expect("run evidencectl")
}

fn write_project(project: &Path, _definition: &str) {
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/evidence/examples/standalone");
    for file in ["evidence.yaml", "local-target.yaml", "dev-authority.yaml"] {
        fs::copy(source.join(file), project.join(file)).expect("normalized project fixture");
    }
    let path = project.join("dev-authority.yaml");
    let mut authority: Value = serde_norway::from_slice(&fs::read(&path).unwrap()).unwrap();
    authority["accessProfiles"] = serde_json::json!({});
    fs::write(path, serde_norway::to_string(&authority).unwrap()).unwrap();
}

/// Declare complete normalized authority in the fixture, then inspect it through the real CLI.
fn declare_profile(project: &Path, id: &str, definitions: &[&str]) -> Output {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/examples/standalone/dev-authority.yaml");
    let template: Value = serde_norway::from_slice(&fs::read(source).unwrap()).unwrap();
    let path = project.join("dev-authority.yaml");
    let mut authority: Value = serde_norway::from_slice(&fs::read(&path).unwrap()).unwrap();
    let mut profile = template["accessProfiles"]["standalone-service"].clone();
    profile["requesterTags"] = serde_json::json!([id]);
    profile["grants"] = Value::Array(
        definitions
            .iter()
            .map(|definition| {
                template["accessProfiles"]["standalone-service"]["grants"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|grant| grant["definition"] == *definition)
                    .cloned()
                    .unwrap_or_else(|| {
                        let mut grant =
                            template["accessProfiles"]["standalone-service"]["grants"][0].clone();
                        grant["definition"] = serde_json::json!(definition);
                        grant
                    })
            })
            .collect(),
    );
    authority["accessProfiles"][id] = profile;
    fs::write(path, serde_norway::to_string(&authority).unwrap()).unwrap();
    evidencectl(project, &["access", "profile", "list"])
}

fn add_client(project: &Path, id: &str, profiles: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_evidencectl"));
    command.args(["access", "client", "add", id]);
    for profile in profiles {
        command.args(["--access-profile", profile]);
    }
    command
        .arg("--generate-local-key")
        .arg("--project")
        .arg(project);
    command.output().expect("add client")
}

fn success(output: &Output) -> String {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).expect("stdout utf8")
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).expect("metadata").permissions().mode() & 0o7777
}

#[test]
fn references_governed_profile_while_isolating_private_client_key() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_project(project, "adult-status");

    assert_eq!(
        success(&declare_profile(project, "age-checks", &["adult-status"])),
        "PROFILE\tACTOR\tDEFINITIONS\nage-checks\tservice\tadult-status\n"
    );
    assert_eq!(
        success(&add_client(project, "age-checker", &["age-checks"])),
        "Added client age-checker with access profile age-checks.\n"
    );

    let authority_path = project.join("dev-authority.yaml");
    let client_path = project.join("access/clients/age-checker.yaml");
    let private_path = project.join(".evidence/clients/age-checker/private.jwk");
    assert_eq!(mode(&client_path), 0o644);
    assert_eq!(mode(private_path.parent().unwrap()), 0o700);
    assert_eq!(mode(&private_path), 0o600);
    let authority: Value = serde_norway::from_slice(&fs::read(authority_path).unwrap()).unwrap();
    assert_eq!(authority["kind"], "EvidenceTargetAuthority");
    assert_eq!(
        authority["accessProfiles"]["age-checks"]["grants"][0]["definition"],
        "adult-status"
    );
    assert_eq!(
        authority["accessProfiles"]["age-checks"]["grants"][0]["representations"],
        serde_json::json!(["signed-jws"])
    );

    let client: Value =
        serde_norway::from_slice(&fs::read(client_path).expect("client")).expect("client yaml");
    assert_eq!(client["clientId"], "age-checker");
    assert_eq!(client["status"], "active");
    assert_eq!(client["accessProfiles"], serde_json::json!(["age-checks"]));
    assert_eq!(client["keys"].as_array().unwrap().len(), 1);
    assert!(client["keys"][0].get("d").is_none());
    let public_text = serde_json::to_string(&client["keys"][0]).expect("public json");
    PublicJwk::parse(&public_text).expect("public JWK");

    let private_text = fs::read_to_string(private_path).expect("private key");
    let private = PrivateJwk::parse(&private_text).expect("private JWK");
    let private_value = private.d.clone().expect("private material");
    assert!(
        !String::from_utf8_lossy(&add_client(project, "age-checker", &["age-checks"]).stdout)
            .contains(&private_value)
    );

    let profiles = success(&evidencectl(project, &["access", "profile", "list"]));
    assert!(profiles.contains("age-checks\tservice\tadult-status"));
    let clients = success(&evidencectl(project, &["access", "client", "list"]));
    assert!(clients.contains("age-checker\tactive\tage-checks"));
}

#[test]
fn unknown_profile_fails_before_generating_or_publishing_client_state() {
    let fixture = tempfile::tempdir().expect("tempdir");
    write_project(fixture.path(), "adult-status");
    let output = add_client(fixture.path(), "unknown-client", &["missing-profile"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("access profile"));
    assert!(!fixture.path().join("access/clients").exists());
    assert!(!fixture.path().join(".evidence/clients").exists());
}

#[test]
fn overlapping_profile_membership_is_rejected_before_key_generation() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_project(project, "adult-status");
    success(&declare_profile(project, "first", &["adult-status"]));
    success(&declare_profile(project, "second", &["adult-status"]));

    let output = add_client(project, "ambiguous-client", &["first", "second"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("overlapping complete grant tuples"));
    assert!(!project
        .join("access/clients/ambiguous-client.yaml")
        .exists());
    assert!(!project.join(".evidence/clients/ambiguous-client").exists());
}

/// Run one `evidencectl` invocation under a strict file-creation mask.
///
/// The mask is set by a shell in the child alone, so no other test in this
/// binary runs under it.
fn evidencectl_under_umask_077(project: &Path, arguments: &[&str]) -> Output {
    Command::new("/bin/sh")
        .arg("-c")
        .arg(r#"umask 077; export DYLD_FALLBACK_LIBRARY_PATH="${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH:-}"; exec "$0" "$@""#)
        .env("REGISTRY_CARGO_RUNTIME_LIBRARY_PATH", std::env::var("REGISTRY_CARGO_RUNTIME_LIBRARY_PATH")
            .or_else(|_| std::env::var("DYLD_FALLBACK_LIBRARY_PATH")).unwrap_or_default())
        .arg(env!("CARGO_BIN_EXE_evidencectl"))
        .args(arguments)
        .arg("--project")
        .arg(project)
        .output()
        .expect("run evidencectl under umask 077")
}

/// An operator whose shell masks group and other bits still gets the public
/// access tree at its published modes. The mode check that follows each
/// creation refuses anything else, so a directory created at whatever the mask
/// left behind would fail the very command that created it.
#[test]
fn access_commands_create_their_directories_at_the_intended_modes_under_umask_077() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_project(project, "adult-status");

    success(&declare_profile(project, "age-checks", &["adult-status"]));
    assert_eq!(
        success(&evidencectl_under_umask_077(
            project,
            &[
                "access",
                "client",
                "add",
                "age-checker",
                "--access-profile",
                "age-checks",
                "--generate-local-key"
            ],
        )),
        "Added client age-checker with access profile age-checks.\n"
    );
    assert_eq!(mode(&project.join("access/clients")), 0o755);
    assert_eq!(
        mode(&project.join("access/clients/age-checker.yaml")),
        0o644
    );
    assert_eq!(mode(&project.join(".evidence")), 0o700);
    assert_eq!(mode(&project.join(".evidence/clients")), 0o700);
    assert_eq!(
        mode(&project.join(".evidence/clients/age-checker/private.jwk")),
        0o600
    );

    let profiles = success(&evidencectl_under_umask_077(
        project,
        &["access", "profile", "list"],
    ));
    assert!(profiles.contains("age-checks\tservice\tadult-status"));
}

#[test]
fn unsafe_identifiers_and_unknown_definitions_change_nothing() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_project(project, "adult-status");

    let unsafe_id = declare_profile(project, "../escape", &["adult-status"]);
    assert!(!unsafe_id.status.success());
    assert!(!project.join("access").exists());

    write_project(project, "adult-status");
    let unknown = declare_profile(project, "missing-definition", &["not-authored"]);
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("AssertionDefinition"));
    assert!(!project.join("access").exists());
}

#[test]
fn client_registration_never_rewrites_authority_or_existing_credentials() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_project(project, "adult-status");
    success(&declare_profile(project, "age-checks", &["adult-status"]));
    let authority_before = fs::read(project.join("dev-authority.yaml")).unwrap();
    success(&add_client(project, "age-checker", &["age-checks"]));
    let private_before =
        fs::read(project.join(".evidence/clients/age-checker/private.jwk")).unwrap();
    assert_eq!(
        fs::read(project.join("dev-authority.yaml")).unwrap(),
        authority_before
    );
    let duplicate_client = add_client(project, "age-checker", &["age-checks"]);
    assert!(!duplicate_client.status.success());
    assert_eq!(
        fs::read(project.join(".evidence/clients/age-checker/private.jwk")).unwrap(),
        private_before
    );
}

#[test]
fn revoke_updates_public_status_and_removes_the_local_private_key() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_project(project, "adult-status");
    success(&declare_profile(project, "age-checks", &["adult-status"]));
    success(&add_client(project, "age-checker", &["age-checks"]));
    let private_directory = project.join(".evidence/clients/age-checker");
    assert!(private_directory.join("private.jwk").is_file());

    let output = evidencectl(project, &["access", "client", "revoke", "age-checker"]);
    assert_eq!(
        success(&output),
        "Revoked client age-checker (removed local private key .evidence/clients/age-checker).\n"
    );
    assert!(!private_directory.exists());
    let list = success(&evidencectl(project, &["access", "client", "list"]));
    assert!(list.contains("age-checker\trevoked\tage-checks"));

    let duplicate = evidencectl(project, &["access", "client", "revoke", "age-checker"]);
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already revoked"));
}

#[test]
fn revoke_leaves_the_record_untouched_when_the_private_directory_cannot_be_removed() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_project(project, "adult-status");
    success(&declare_profile(project, "age-checks", &["adult-status"]));
    success(&add_client(project, "age-checker", &["age-checks"]));
    let private_directory = project.join(".evidence/clients/age-checker");
    let private_directory_mode = mode(&private_directory);

    // Read-only on the client directory itself (the parent of private.jwk)
    // blocks unlinking the key file, not just removing the now-empty
    // directory, so the removal fails before any private state is lost.
    fs::set_permissions(&private_directory, fs::Permissions::from_mode(0o500))
        .expect("read-only client directory");
    let blocked = evidencectl(project, &["access", "client", "revoke", "age-checker"]);
    fs::set_permissions(
        &private_directory,
        fs::Permissions::from_mode(private_directory_mode),
    )
    .expect("restore client directory mode");

    assert!(!blocked.status.success());
    assert!(private_directory.join("private.jwk").is_file());
    let document: Value = serde_norway::from_slice(
        &fs::read(project.join("access/clients/age-checker.yaml")).expect("client document"),
    )
    .expect("yaml");
    assert_eq!(document["status"], "active");

    let retried = evidencectl(project, &["access", "client", "revoke", "age-checker"]);
    assert_eq!(
        success(&retried),
        "Revoked client age-checker (removed local private key .evidence/clients/age-checker).\n"
    );
    assert!(!private_directory.exists());
}

#[test]
fn unsafe_or_symlinked_access_directory_publishes_no_access_artifact() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_project(project, "adult-status");
    success(&declare_profile(project, "age-checks", &["adult-status"]));
    fs::create_dir(project.join("access")).expect("access directory");
    fs::set_permissions(project.join("access"), fs::Permissions::from_mode(0o777))
        .expect("unsafe access mode");
    let unsafe_mode = add_client(project, "age-checker", &["age-checks"]);
    assert!(!unsafe_mode.status.success());
    assert!(!project.join("access/clients").exists());

    let symlink_fixture = tempfile::tempdir().expect("symlink fixture");
    let symlink_project = symlink_fixture.path().join("project");
    let outside = symlink_fixture.path().join("outside");
    fs::create_dir(&symlink_project).expect("project");
    fs::create_dir(&outside).expect("outside");
    write_project(&symlink_project, "adult-status");
    success(&declare_profile(
        &symlink_project,
        "age-checks",
        &["adult-status"],
    ));
    symlink(&outside, symlink_project.join("access")).expect("access symlink");
    let escaped = add_client(&symlink_project, "age-checker", &["age-checks"]);
    assert!(!escaped.status.success());
    assert_eq!(fs::read_dir(&outside).expect("outside").count(), 0);
}

#[test]
fn public_clients_without_local_keys_can_be_added_alongside_and_revoked() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_project(project, "adult-status");
    success(&declare_profile(project, "age-checks", &["adult-status"]));
    success(&add_client(project, "governed-client", &["age-checks"]));
    fs::remove_dir_all(project.join(".evidence/clients/governed-client"))
        .expect("remove local-only key as in a fresh clone");

    let local = add_client(project, "local-client", &["age-checks"]);
    assert_eq!(
        success(&local),
        "Added client local-client with access profile age-checks.\n"
    );
    assert!(project
        .join(".evidence/clients/local-client/private.jwk")
        .is_file());

    let revoke = evidencectl(project, &["access", "client", "revoke", "governed-client"]);
    assert_eq!(success(&revoke), "Revoked client governed-client.\n");
    let governed: Value = serde_norway::from_slice(
        &fs::read(project.join("access/clients/governed-client.yaml")).expect("governed client"),
    )
    .expect("governed client yaml");
    assert_eq!(governed["status"], "revoked");
}

#[test]
fn institutional_exchange_keeps_bootstrap_binding_explicit_and_preserves_it_on_revocation() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_project(project, "adult-status");
    success(&declare_profile(project, "age-checks", &["adult-status"]));
    let project_path = project.join("evidence.yaml");
    let mut config: Value = serde_norway::from_slice(&fs::read(&project_path).unwrap()).unwrap();
    config["assertionDefinitions"]["adult-status"]["grantCeiling"]["actorKinds"] =
        serde_json::json!(["agent"]);
    config["assertionDefinitions"]["adult-status"]["grantCeiling"]["valueOrigins"] =
        serde_json::json!(["authenticated-grant"]);
    fs::write(project_path, serde_norway::to_string(&config).unwrap()).unwrap();
    let authority_path = project.join("dev-authority.yaml");
    let mut authority: Value =
        serde_norway::from_slice(&fs::read(&authority_path).unwrap()).unwrap();
    let profile = &mut authority["accessProfiles"]["age-checks"];
    profile["actorKind"] = serde_json::json!("agent");
    profile["requesterClients"] = serde_json::json!(["task-checker", "default-task-checker"]);
    profile["grantSourceIssuer"] = serde_json::json!("https://casework.invalid");
    profile["grants"][0]["subjects"][0]["valueOrigin"] = serde_json::json!("authenticated-grant");
    profile["grants"][0]["subjects"][0]["valueClaims"] =
        serde_json::json!({"record-id":"grant.record_id"});
    fs::write(authority_path, serde_norway::to_string(&authority).unwrap()).unwrap();

    success(&evidencectl(
        project,
        &[
            "access",
            "client",
            "add",
            "task-checker",
            "--access-profile",
            "age-checks",
            "--generate-local-key",
            "--grant-bootstrap-scope",
            "tasks:assert",
            "--grant-bootstrap-resource",
            "urn:local:task-authority",
        ],
    ));
    let path = project.join("access/clients/task-checker.yaml");
    let document: Value =
        serde_norway::from_slice(&fs::read(&path).expect("client")).expect("yaml");
    assert_eq!(
        document["exchange"],
        serde_json::json!({
            "kind": "institutional-grant", "bootstrapScope": "tasks:assert",
            "bootstrapResource": "urn:local:task-authority",
        })
    );
    assert_eq!(
        document["evidenceAudience"],
        "urn:example:audience:standalone-app"
    );
    let key_directory = project.join(".evidence/clients/task-checker");
    success(&evidencectl(project, &["access", "client", "list"]));
    success(&evidencectl(
        project,
        &["access", "client", "revoke", "task-checker"],
    ));
    let revoked: Value = serde_norway::from_slice(&fs::read(path).expect("client")).expect("yaml");
    assert_eq!(revoked["status"], "revoked");
    assert_eq!(revoked["exchange"], document["exchange"]);
    assert!(
        !key_directory.exists(),
        "revocation removes the local private key state"
    );

    success(&evidencectl(
        project,
        &[
            "access",
            "client",
            "add",
            "default-task-checker",
            "--access-profile",
            "age-checks",
            "--generate-local-key",
            "--grant-bootstrap-scope",
            "tasks:assert",
        ],
    ));
    let default: Value = serde_norway::from_slice(
        &fs::read(project.join("access/clients/default-task-checker.yaml")).expect("client"),
    )
    .expect("yaml");
    assert!(default["exchange"]["bootstrapResource"].is_null());
}

#[test]
fn first_party_exchange_records_exact_context_issuer_and_bootstrap_resource() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_project(project, "adult-status");
    success(&declare_profile(project, "age-checks", &["adult-status"]));
    success(&evidencectl(
        project,
        &[
            "access",
            "client",
            "add",
            "portal-host",
            "--access-profile",
            "age-checks",
            "--generate-local-key",
            "--first-party-bootstrap-scope",
            "evidence:invoke",
            "--first-party-bootstrap-resource",
            "urn:seed-demo:evidence:growers",
            "--first-party-issuer",
            "http://127.0.0.1:4494",
        ],
    ));
    let document: Value = serde_norway::from_slice(
        &fs::read(project.join("access/clients/portal-host.yaml")).expect("client"),
    )
    .expect("yaml");
    assert_eq!(
        document["exchange"],
        serde_json::json!({
            "kind":"first-party", "bootstrapScope":"evidence:invoke",
            "bootstrapResource":"urn:seed-demo:evidence:growers",
            "sourceIssuer":"http://127.0.0.1:4494",
        })
    );
}

#[test]
fn invalid_or_ambiguous_exchange_binding_cannot_publish_a_client() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_project(project, "adult-status");
    success(&declare_profile(project, "age-checks", &["adult-status"]));
    for options in [
        vec!["--grant-bootstrap-resource", "urn:local:tasks"],
        vec!["--grant-bootstrap-scope", "tasks:assert evidence:invoke"],
        vec![
            "--grant-bootstrap-scope",
            "tasks:assert",
            "--grant-bootstrap-resource",
            "not-a-uri",
        ],
        vec!["--first-party-bootstrap-scope", "evidence:invoke"],
        vec![
            "--first-party-bootstrap-scope",
            "evidence:invoke",
            "--first-party-issuer",
            "http://127.0.0.1:4494",
        ],
        vec![
            "--first-party-bootstrap-scope",
            "evidence:invoke",
            "--first-party-bootstrap-resource",
            "urn:seed-demo:evidence:growers",
            "--first-party-issuer",
            "not-a-uri",
        ],
        vec![
            "--grant-bootstrap-scope",
            "tasks:assert",
            "--first-party-bootstrap-scope",
            "evidence:invoke",
            "--first-party-bootstrap-resource",
            "urn:seed-demo:evidence:growers",
            "--first-party-issuer",
            "http://127.0.0.1:4494",
        ],
    ] {
        let mut args = vec![
            "access",
            "client",
            "add",
            "invalid-client",
            "--access-profile",
            "age-checks",
            "--generate-local-key",
        ];
        args.extend(options);
        assert!(!evidencectl(project, &args).status.success());
        assert!(!project.join("access/clients/invalid-client.yaml").exists());
        assert!(!project.join(".evidence/clients/invalid-client").exists());
    }
    success(&add_client(project, "direct-client", &["age-checks"]));
    let path = project.join("access/clients/direct-client.yaml");
    let original: Value =
        serde_norway::from_slice(&fs::read(&path).expect("client")).expect("yaml");
    assert!(original.get("exchange").is_none());
    for exchange in [
        serde_json::json!({"kind":"unknown-mode", "bootstrapScope":"tasks:assert"}),
        serde_json::json!({"kind":"institutional-grant", "bootstrapScope":"tasks:assert", "unexpected":true}),
        serde_json::json!({"kind":"institutional-grant", "bootstrapScope":"tasks:assert other"}),
        serde_json::json!({"kind":"institutional-grant", "bootstrapScope":"tasks:assert", "bootstrapResource":"relative"}),
        serde_json::json!({"kind":"first-party", "bootstrapScope":"evidence:invoke", "bootstrapResource":"urn:seed-demo:evidence:growers"}),
    ] {
        let mut document = original.clone();
        document["exchange"] = exchange;
        fs::write(&path, serde_norway::to_string(&document).expect("yaml")).expect("write client");
        assert!(!evidencectl(project, &["access", "client", "list"])
            .status
            .success());
    }
}

#[test]
fn access_commands_report_the_shared_json_envelope() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fs::canonicalize(fixture.path()).expect("canonical project");
    let project = project.as_path();
    write_project(project, "adult-status");

    success(&declare_profile(project, "age-checks", &["adult-status"]));
    let profiles = json_output(&evidencectl(
        project,
        &["--format", "json", "access", "profile", "list"],
    ));
    assert_eq!(profiles["command"], "access profile list");
    assert_eq!(profiles["ok"], Value::Bool(true));
    assert_eq!(profiles["status"], "complete");
    assert_eq!(profiles["entries"][0]["id"], "age-checks");
    assert_eq!(
        profiles["entries"][0]["definitions"],
        serde_json::json!(["adult-status"])
    );
    assert!(profiles["entries"][0]["digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));

    let client = json_output(&evidencectl(
        project,
        &[
            "--format",
            "json",
            "access",
            "client",
            "add",
            "age-checker",
            "--access-profile",
            "age-checks",
            "--generate-local-key",
        ],
    ));
    assert_eq!(client["command"], "access client add");
    assert_eq!(client["client"], "age-checker");
    assert_eq!(client["accessProfiles"], serde_json::json!(["age-checks"]));
    let kid = client["kid"].as_str().expect("kid").to_owned();
    assert_eq!(kid.len(), 43, "an ES256 thumbprint kid");
    let files = client["files"].as_array().expect("files").clone();
    assert!(files.contains(&serde_json::json!(project
        .join(".evidence/clients/age-checker/private.jwk")
        .display()
        .to_string())));
    assert!(files.contains(&serde_json::json!(project
        .join("access/clients/age-checker.yaml")
        .display()
        .to_string())));
    // The kid is the registered public key's thumbprint, and the private
    // material itself never reaches the report.
    let registered: Value = serde_norway::from_slice(
        &fs::read(project.join("access/clients/age-checker.yaml")).expect("client"),
    )
    .expect("yaml");
    assert_eq!(registered["keys"][0]["kid"], Value::String(kid));

    let clients = json_output(&evidencectl(
        project,
        &["--format", "json", "access", "client", "list"],
    ));
    assert_eq!(
        clients["entries"],
        serde_json::json!([{"id": "age-checker", "status": "active", "accessProfiles": ["age-checks"]}])
    );

    let revoked = json_output(&evidencectl(
        project,
        &[
            "--format",
            "json",
            "access",
            "client",
            "revoke",
            "age-checker",
        ],
    ));
    assert_eq!(revoked["command"], "access client revoke");
    assert_eq!(revoked["client"], "age-checker");
    assert_eq!(revoked["removed"], ".evidence/clients/age-checker");
    assert!(!project.join(".evidence/clients/age-checker").exists());

    // A public client with no local key revokes with an explicit null member.
    success(&add_client(project, "governed-client", &["age-checks"]));
    fs::remove_dir_all(project.join(".evidence/clients/governed-client")).expect("fresh clone");
    let revoked = json_output(&evidencectl(
        project,
        &[
            "--format",
            "json",
            "access",
            "client",
            "revoke",
            "governed-client",
        ],
    ));
    assert_eq!(revoked["removed"], Value::Null);

    let empty = tempfile::tempdir().expect("empty project");
    let report = json_output(&evidencectl(
        empty.path(),
        &["--format", "json", "access", "client", "list"],
    ));
    assert_eq!(report["entries"], serde_json::json!([]));
    assert!(!evidencectl(empty.path(), &["access", "profile", "list"])
        .status
        .success());
}

fn json_output(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "JSON mode wrote human diagnostics: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("invalid JSON report: {error}"))
}

#[test]
fn profile_tags_cannot_activate_unassigned_authority() {
    let fixture = tempfile::tempdir().unwrap();
    let project = fixture.path();
    write_project(project, "adult-status");
    success(&declare_profile(project, "age-checks", &["adult-status"]));
    success(&declare_profile(
        project,
        "other-profile",
        &["residence-region"],
    ));
    let path = project.join("dev-authority.yaml");
    let mut authority: Value = serde_norway::from_slice(&fs::read(&path).unwrap()).unwrap();
    authority["accessProfiles"]["other-profile"]["requesterTags"] =
        serde_json::json!(["age-checks"]);
    fs::write(path, serde_norway::to_string(&authority).unwrap()).unwrap();
    let result = add_client(project, "narrow-client", &["age-checks"]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("unassigned access profile"));
    assert!(!project.join(".evidence/clients").exists());
}

#[test]
fn audience_choice_and_retired_members_fail_before_private_state() {
    let fixture = tempfile::tempdir().unwrap();
    let project = fixture.path();
    write_project(project, "adult-status");
    success(&declare_profile(project, "age-checks", &["adult-status"]));
    let path = project.join("evidence.yaml");
    let mut config: Value = serde_norway::from_slice(&fs::read(&path).unwrap()).unwrap();
    config["assertionDefinitions"]["adult-status"]["grantCeiling"]["audiences"] =
        serde_json::json!(["urn:example:one", "urn:example:two"]);
    fs::write(path, serde_norway::to_string(&config).unwrap()).unwrap();
    assert!(!add_client(project, "chosen", &["age-checks"])
        .status
        .success());
    assert!(!project.join(".evidence/clients").exists());
    success(&evidencectl(
        project,
        &[
            "access",
            "client",
            "add",
            "chosen",
            "--access-profile",
            "age-checks",
            "--generate-local-key",
            "--evidence-audience",
            "urn:example:two",
        ],
    ));
    assert!(!evidencectl(project, &["access", "policy", "list"])
        .status
        .success());
    let path = project.join("access/clients/chosen.yaml");
    let mut client: Value = serde_norway::from_slice(&fs::read(&path).unwrap()).unwrap();
    let profiles = client
        .as_object_mut()
        .unwrap()
        .remove("accessProfiles")
        .unwrap();
    client["policies"] = profiles;
    fs::write(path, serde_norway::to_string(&client).unwrap()).unwrap();
    assert!(!evidencectl(project, &["access", "client", "list"])
        .status
        .success());
}

#[test]
fn revocation_remains_available_after_target_authority_retirement() {
    let fixture = tempfile::tempdir().unwrap();
    let project = fixture.path();
    write_project(project, "adult-status");
    success(&declare_profile(project, "age-checks", &["adult-status"]));
    success(&add_client(project, "retired", &["age-checks"]));
    fs::remove_file(project.join("dev-authority.yaml")).unwrap();
    success(&evidencectl(
        project,
        &["access", "client", "revoke", "retired"],
    ));
    assert!(!project.join(".evidence/clients/retired").exists());
}
