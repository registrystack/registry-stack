#![cfg(unix)]

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

fn write_question(project: &Path, id: &str) {
    fs::create_dir_all(project.join("questions")).expect("questions directory");
    fs::write(
        project.join("questions").join(format!("{id}.yaml")),
        format!("id: {id}\n"),
    )
    .expect("question");
}

fn add_policy(project: &Path, id: &str, questions: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_evidencectl"));
    command.args(["access", "policy", "add", id]);
    for question in questions {
        command.args(["--question", question]);
    }
    command.arg("--project").arg(project);
    command.output().expect("add policy")
}

fn add_client(project: &Path, id: &str, policies: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_evidencectl"));
    command.args(["access", "client", "add", id]);
    for policy in policies {
        command.args(["--policy", policy]);
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
fn adds_reviewable_policy_and_public_client_while_isolating_private_key() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_question(project, "adult-status");

    assert_eq!(
        success(&add_policy(project, "age-checks", &["adult-status"])),
        "Added access policy age-checks for adult-status.\n"
    );
    assert_eq!(
        success(&add_client(project, "age-checker", &["age-checks"])),
        "Added client age-checker with policy age-checks.\n"
    );

    let policy_path = project.join("access/policies/age-checks.yaml");
    let client_path = project.join("access/clients/age-checker.yaml");
    let private_path = project.join(".evidence/clients/age-checker/private.jwk");
    assert_eq!(mode(&policy_path), 0o644);
    assert_eq!(mode(&client_path), 0o644);
    assert_eq!(mode(private_path.parent().unwrap()), 0o700);
    assert_eq!(mode(&private_path), 0o600);

    let policy: Value =
        serde_norway::from_slice(&fs::read(policy_path).expect("policy")).expect("policy yaml");
    assert_eq!(policy["version"], 1);
    assert_eq!(policy["id"], "age-checks");
    assert_eq!(policy["questions"], serde_json::json!(["adult-status"]));

    let client: Value =
        serde_norway::from_slice(&fs::read(client_path).expect("client")).expect("client yaml");
    assert_eq!(client["clientId"], "age-checker");
    assert_eq!(client["status"], "active");
    assert_eq!(client["policies"], serde_json::json!(["age-checks"]));
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

    let policies = success(&evidencectl(project, &["access", "policy", "list"]));
    assert!(policies.contains("age-checks\tadult-status"));
    let clients = success(&evidencectl(project, &["access", "client", "list"]));
    assert!(clients.contains("age-checker\tactive\tage-checks"));
}

#[test]
fn unknown_policy_fails_before_generating_or_publishing_client_state() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let output = add_client(fixture.path(), "unknown-client", &["missing-policy"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no access policies are configured"));
    assert!(!fixture.path().join("access/clients").exists());
    assert!(!fixture.path().join(".evidence/clients").exists());
}

#[test]
fn overlapping_policy_membership_is_rejected_before_key_generation() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_question(project, "adult-status");
    success(&add_policy(project, "first", &["adult-status"]));
    success(&add_policy(project, "second", &["adult-status"]));

    let output = add_client(project, "ambiguous-client", &["first", "second"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("grant the same authored entitlement for question adult-status"));
    assert!(!project
        .join("access/clients/ambiguous-client.yaml")
        .exists());
    assert!(!project.join(".evidence/clients/ambiguous-client").exists());
}

#[test]
fn unsafe_identifiers_and_unknown_questions_change_nothing() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_question(project, "adult-status");

    let unsafe_id = add_policy(project, "../escape", &["adult-status"]);
    assert!(!unsafe_id.status.success());
    assert!(!project.join("access").exists());

    let unknown = add_policy(project, "missing-question", &["not-authored"]);
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("not-authored.yaml"));
    assert!(!project.join("access").exists());
}

#[test]
fn add_never_overwrites_existing_policy_or_client() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_question(project, "adult-status");
    success(&add_policy(project, "age-checks", &["adult-status"]));
    let policy_before = fs::read(project.join("access/policies/age-checks.yaml")).unwrap();
    let duplicate_policy = add_policy(project, "age-checks", &["adult-status"]);
    assert!(!duplicate_policy.status.success());
    assert_eq!(
        fs::read(project.join("access/policies/age-checks.yaml")).unwrap(),
        policy_before
    );

    success(&add_client(project, "age-checker", &["age-checks"]));
    let private_before =
        fs::read(project.join(".evidence/clients/age-checker/private.jwk")).unwrap();
    let duplicate_client = add_client(project, "age-checker", &["age-checks"]);
    assert!(!duplicate_client.status.success());
    assert_eq!(
        fs::read(project.join(".evidence/clients/age-checker/private.jwk")).unwrap(),
        private_before
    );
}

#[test]
fn revoke_updates_public_status_but_retains_private_key() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_question(project, "adult-status");
    success(&add_policy(project, "age-checks", &["adult-status"]));
    success(&add_client(project, "age-checker", &["age-checks"]));
    let private_path = project.join(".evidence/clients/age-checker/private.jwk");
    let private_before = fs::read(&private_path).expect("private key");

    let output = evidencectl(project, &["access", "client", "revoke", "age-checker"]);
    assert_eq!(success(&output), "Revoked client age-checker.\n");
    assert_eq!(
        fs::read(&private_path).expect("retained private key"),
        private_before
    );
    let list = success(&evidencectl(project, &["access", "client", "list"]));
    assert!(list.contains("age-checker\trevoked\tage-checks"));

    let duplicate = evidencectl(project, &["access", "client", "revoke", "age-checker"]);
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already revoked"));
}

#[test]
fn unsafe_or_symlinked_access_directory_publishes_no_access_artifact() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_question(project, "adult-status");
    fs::create_dir(project.join("access")).expect("access directory");
    fs::set_permissions(project.join("access"), fs::Permissions::from_mode(0o777))
        .expect("unsafe access mode");
    let unsafe_mode = add_policy(project, "age-checks", &["adult-status"]);
    assert!(!unsafe_mode.status.success());
    assert!(!project.join("access/policies").exists());

    let symlink_fixture = tempfile::tempdir().expect("symlink fixture");
    let symlink_project = symlink_fixture.path().join("project");
    let outside = symlink_fixture.path().join("outside");
    fs::create_dir(&symlink_project).expect("project");
    fs::create_dir(&outside).expect("outside");
    write_question(&symlink_project, "adult-status");
    symlink(&outside, symlink_project.join("access")).expect("access symlink");
    let escaped = add_policy(&symlink_project, "age-checks", &["adult-status"]);
    assert!(!escaped.status.success());
    assert_eq!(fs::read_dir(&outside).expect("outside").count(), 0);
}

#[test]
fn public_clients_without_local_keys_can_be_added_alongside_and_revoked() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_question(project, "adult-status");
    success(&add_policy(project, "age-checks", &["adult-status"]));
    success(&add_client(project, "governed-client", &["age-checks"]));
    fs::remove_dir_all(project.join(".evidence/clients/governed-client"))
        .expect("remove local-only key as in a fresh clone");

    let local = add_client(project, "local-client", &["age-checks"]);
    assert_eq!(
        success(&local),
        "Added client local-client with policy age-checks.\n"
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
