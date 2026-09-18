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
fn revoke_updates_public_status_and_removes_the_local_private_key() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_question(project, "adult-status");
    success(&add_policy(project, "age-checks", &["adult-status"]));
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

#[test]
fn institutional_exchange_keeps_bootstrap_binding_explicit_and_preserves_it_on_revocation() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let project = fixture.path();
    write_question(project, "adult-status");
    success(&add_policy(project, "age-checks", &["adult-status"]));
    success(&evidencectl(
        project,
        &[
            "access",
            "client",
            "add",
            "task-checker",
            "--policy",
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
        "urn:registrystack:evidence:local:client:task-checker"
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
            "--policy",
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
    write_question(project, "adult-status");
    success(&add_policy(project, "age-checks", &["adult-status"]));
    success(&evidencectl(
        project,
        &[
            "access",
            "client",
            "add",
            "portal-host",
            "--policy",
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
    write_question(project, "adult-status");
    success(&add_policy(project, "age-checks", &["adult-status"]));
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
            "--policy",
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
    write_question(project, "adult-status");

    let policy = json_output(&evidencectl(
        project,
        &[
            "--format",
            "json",
            "access",
            "policy",
            "add",
            "age-checks",
            "--question",
            "adult-status",
        ],
    ));
    assert_eq!(policy["command"], "access policy add");
    assert_eq!(policy["ok"], Value::Bool(true));
    assert_eq!(policy["status"], "complete");
    assert_eq!(policy["policy"], "age-checks");
    assert_eq!(policy["questions"], serde_json::json!(["adult-status"]));
    assert_eq!(
        policy["files"],
        serde_json::json!([project
            .join("access/policies/age-checks.yaml")
            .display()
            .to_string()])
    );

    let policies = json_output(&evidencectl(
        project,
        &["--format", "json", "access", "policy", "list"],
    ));
    assert_eq!(policies["command"], "access policy list");
    assert_eq!(policies["status"], "complete");
    assert_eq!(
        policies["entries"],
        serde_json::json!([{"id": "age-checks", "questions": ["adult-status"]}])
    );

    let client = json_output(&evidencectl(
        project,
        &[
            "--format",
            "json",
            "access",
            "client",
            "add",
            "age-checker",
            "--policy",
            "age-checks",
            "--generate-local-key",
        ],
    ));
    assert_eq!(client["command"], "access client add");
    assert_eq!(client["client"], "age-checker");
    assert_eq!(client["policies"], serde_json::json!(["age-checks"]));
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
        serde_json::json!([{"id": "age-checker", "status": "active", "policies": ["age-checks"]}])
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

    // The empty-project listings stay the same shape.
    let empty = tempfile::tempdir().expect("empty project");
    for command in [
        vec!["access", "policy", "list"],
        vec!["access", "client", "list"],
    ] {
        let mut arguments = vec!["--format", "json"];
        arguments.extend(command);
        let report = json_output(&evidencectl(empty.path(), &arguments));
        assert_eq!(report["status"], "complete");
        assert_eq!(report["entries"], serde_json::json!([]));
    }
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
