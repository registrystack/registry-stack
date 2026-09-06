// SPDX-License-Identifier: Apache-2.0
use super::*;

fn fixture() -> (tempfile::TempDir, State, Clients, BTreeMap<String, Vec<u8>>) {
    let temporary = tempfile::tempdir().expect("temporary");
    let project = fs::canonicalize(temporary.path()).expect("canonical");
    fs::set_permissions(&project, fs::Permissions::from_mode(0o700)).unwrap();
    let parent = project.join(".breg");
    private::directory(&parent).expect("private");
    let clients = config::clients(
        br#"version: 1
clients:
  - id: operator
    accessProfiles: [operator]
    scopes: [registry:generic:operate]
    claims:
      registry_principal: generic-registry-operator
      registry_purpose: registry-operations
  - id: source
    accessProfiles: [evidence-source]
    scopes: [registry:evidence:lookup]
    claims:
      registry_principal: evidence-source
      registry_purpose: evidence-source-read
seed: []
"#,
    )
    .expect("clients");
    let state = State {
        version: 1,
        project: project.clone(),
        owner: uuid::Uuid::new_v4().to_string(),
        status: Status::Stopped,
        breg_port: 8094,
        mint_port: 8095,
        database_port: 55448,
        clients_file: project.join("clients.yaml"),
        source_digest: "a".repeat(64),
        instance_id: "generic-local".into(),
        source_revision: "local".into(),
        container_id: None,
        tls_files_copied: false,
        database_ready: false,
        package_revision: None,
        activated: false,
        seeded: BTreeSet::new(),
        outputs: vec![],
    };
    (
        temporary,
        state,
        clients,
        BTreeMap::from([("registry.yaml".into(), b"synthetic".to_vec())]),
    )
}

#[test]
fn initialization_keeps_distinct_keys_and_private_state_without_service_dependencies() {
    let (_temp, state, clients, files) = fixture();
    initialize(&state.root(), &state, &clients, &files).expect("initialize");
    let root = state.root();
    private::validate_tree(&root).expect("all generated state is private");
    let issuer = private::read(
        &root.join("credentials/issuer/assertion-key.jwk"),
        MAX_BYTES,
    )
    .expect("issuer");
    let operator = private::read(
        &root.join("credentials/operator/assertion-key.jwk"),
        MAX_BYTES,
    )
    .expect("operator");
    let source = private::read(
        &root.join("credentials/source/assertion-key.jwk"),
        MAX_BYTES,
    )
    .expect("source");
    assert!(issuer != operator);
    assert!(source != operator);
    assert!(source != issuer);
    let report = serde_json::to_string(&state.report().unwrap()).expect("report");
    assert!(!report.contains("\"d\""));
    let runtime: Value = serde_norway::from_slice(
        &private::read(&root.join("runtime-test.yaml"), MAX_BYTES).unwrap(),
    )
    .unwrap();
    assert_eq!(runtime["identity"]["environment"], "local");
    assert_eq!(runtime["database"]["roles"]["runtime"], RUNTIME_ROLE);
}

#[test]
fn clients_require_explicit_unique_profile_bindings_and_closed_fields() {
    let (_, _, clients, _) = fixture();
    let mut value = serde_json::to_value(&clients).unwrap();
    value["clients"][1]["accessProfiles"] = json!(["operator"]);
    assert!(config::clients(&serde_json::to_vec(&value).unwrap()).is_err());
    value["clients"][1]["accessProfiles"] = json!(["evidence-source"]);
    value["clients"][1]["secret"] = json!("must-not-be-accepted");
    assert!(config::clients(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn credential_publication_recovers_one_owned_half_and_refuses_conflicting_bytes() {
    let (_temp, state, mut clients, files) = fixture();
    let out = state.project.join("out");
    private::directory(&out).unwrap();
    clients.clients[1].client_id_file = Some(out.join("id"));
    clients.clients[1].assertion_key_file = Some(out.join("key"));
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let state = read_state(&state.root()).unwrap();
    assert!(!out.join("id").exists());
    private::create(&out.join("id"), b"source").unwrap();
    verify_outputs(&state).expect("resume consistent pair");
    let key = private::read(&out.join("key"), MAX_BYTES).unwrap();
    verify_outputs(&state).expect("idempotent pair reuse");
    assert!(private::read(&out.join("key"), MAX_BYTES).unwrap() == key);
    private::replace(&out.join("id"), b"somebody-else").unwrap();
    assert!(verify_outputs(&state).is_err());
    assert_eq!(
        private::read(&out.join("id"), MAX_BYTES).unwrap(),
        b"somebody-else"
    );
}

#[test]
fn existing_credential_outputs_are_refused_before_creating_state() {
    let (_temp, state, mut clients, files) = fixture();
    let out = state.project.join("out");
    private::directory(&out).unwrap();
    private::create(&out.join("key"), b"existing key").unwrap();
    clients.clients[1].client_id_file = Some(out.join("id"));
    clients.clients[1].assertion_key_file = Some(out.join("key"));
    assert!(initialize(&state.root(), &state, &clients, &files).is_err());
    assert!(!state.root().exists());
    assert_eq!(
        private::read(&out.join("key"), MAX_BYTES).unwrap(),
        b"existing key"
    );
}

#[test]
fn private_files_refuse_symlinks_hardlinks_and_public_modes() {
    let (temp, _, _, _) = fixture();
    let root = fs::canonicalize(temp.path()).unwrap();
    private::create(&root.join("ordinary"), b"private").unwrap();
    std::os::unix::fs::symlink(root.join("ordinary"), root.join("link")).unwrap();
    assert!(private::read(&root.join("link"), 20).is_err());
    fs::hard_link(root.join("ordinary"), root.join("hardlink")).unwrap();
    assert!(private::read(&root.join("ordinary"), 20).is_err());
    private::create(&root.join("public"), b"private").unwrap();
    fs::set_permissions(root.join("public"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(private::read(&root.join("public"), 20).is_err());
}

#[test]
fn state_refuses_changed_ownership_without_touching_paths() {
    let (_temp, state, clients, files) = fixture();
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let mut changed = state.clone();
    changed.project = state.project.join("another");
    private::replace(
        &state.root().join("state.json"),
        &serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    assert!(read_state(&state.root()).is_err());
}

#[test]
fn occupied_and_ambiguous_ports_are_refused() {
    assert!(ports(1, 1, 2).is_err());
    assert!(ports(0, 2, 3).is_err());
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    assert!(probe(listener.local_addr().unwrap().port()).is_err());
}

#[test]
fn stop_before_first_start_is_idempotent_without_docker() {
    let temporary = tempfile::tempdir().unwrap();
    assert_eq!(stop(temporary.path(), false).unwrap()["status"], "stopped");
    assert_eq!(stop(temporary.path(), false).unwrap()["status"], "stopped");
    assert_eq!(stop(temporary.path(), true).unwrap()["status"], "stopped");
}

#[test]
fn output_pump_bounds_persisted_diagnostics() {
    let input = vec![1; (MAX_BYTES + 10) as usize];
    let mut output = Vec::new();
    pump(input.as_slice(), &mut output).unwrap();
    assert_eq!(output.len(), MAX_BYTES as usize);
}

#[test]
fn database_roles_have_independent_passwords_and_hmac_files_are_secret_safe() {
    let (_temp, state, clients, files) = fixture();
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let root = state.root();
    let runtime = reqwest::Url::parse(
        &String::from_utf8(
            private::read(&root.join("secrets/runtime-database-url"), MAX_BYTES).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let migration = reqwest::Url::parse(
        &String::from_utf8(
            private::read(&root.join("secrets/migration-database-url"), MAX_BYTES).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let environment =
        String::from_utf8(private::read(&root.join("database/postgres.env"), MAX_BYTES).unwrap())
            .unwrap();
    assert!(runtime.password() != migration.password());
    assert!(!environment.contains(runtime.password().unwrap()));
    assert!(!environment.contains(migration.password().unwrap()));
    for file in ["audit-key", "cursor-key", "mint-audit-key"] {
        let bytes = private::read(&root.join("secrets").join(file), 64).unwrap();
        assert_eq!(bytes.len(), 43);
        assert!(bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')));
    }
}

#[test]
fn corrupt_clients_refuse_success_reports() {
    let (_temp, state, clients, files) = fixture();
    initialize(&state.root(), &state, &clients, &files).unwrap();
    private::replace(&state.root().join("clients.json"), b"invalid").unwrap();
    assert!(state.report().is_err());
}

#[test]
fn control_path_is_short_and_bound_to_the_owned_journal() {
    let (_temp, state, clients, files) = fixture();
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let directory = control_directory(&state.root()).unwrap();
    assert!(directory.join("control.sock").as_os_str().len() < 104);
    assert!(directory
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .ends_with(&state.owner));
}

fn doctor_refusal(code: &str, message: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"ok":false,"command":"doctor","diagnostics":[
        {"severity":"error","code":code,"artifact":"startupDependencies","path":"database",
         "message":message,"suggestedAction":"verifyStartupDependencies"}]}))
    .unwrap()
}

#[test]
fn only_an_unready_database_classifies_a_doctor_refusal_as_not_activated() {
    assert_eq!(activation(true, b"{}").unwrap(), Activation::Activated);
    assert_eq!(
        activation(
            false,
            &doctor_refusal(
                "startup.database.unready",
                "the database is not ready for the runtime package"
            )
        )
        .unwrap(),
        Activation::NotActivated
    );
    let refused = activation(
        false,
        &doctor_refusal("startup.package.refused", "the runtime package was refused"),
    )
    .expect_err("an unrelated doctor refusal aborts the start");
    let refused = format!("{refused:#}");
    assert!(refused.contains("startup.package.refused"), "{refused}");
    assert!(
        refused.contains("the runtime package was refused"),
        "{refused}"
    );
    assert!(activation(false, b"not a report").is_err());
    assert!(activation(false, br#"{"ok":false,"diagnostics":[]}"#).is_err());
}

#[test]
fn redaction_hides_whole_and_truncated_secret_runs() {
    let secret = b"6f0a1b2c3d4e5f60718293a4b5c6d7e8";
    assert_eq!(
        redact(b"before 6f0a1b2c3d4e5f60718293a4b5c6d7e8 after", secret),
        b"before [redacted] after".to_vec()
    );
    // A client can echo a window around an error position, not the whole
    // statement, so a long run of secret bytes must not survive either.
    assert_eq!(
        redact(b"LINE 1: ...a1b2c3d4e5f60718293a4b5c6d7... ", secret),
        b"LINE 1: ...[redacted]... ".to_vec()
    );
    assert_eq!(
        redact(b"unrelated diagnostics", secret),
        b"unrelated diagnostics".to_vec()
    );
}

#[test]
fn role_password_bytes_cannot_reach_diagnostics_or_errors() {
    let (_temp, state, clients, files) = fixture();
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let root = state.root();
    let password = "6f0a1b2c3d4e5f60718293a4b5c6d7e8";
    let statement = format!("DO $$ BEGIN CREATE ROLE r LOGIN PASSWORD '{password}'; END $$;");
    // A refused psql echoes the statement it could not run, both whole and as
    // the truncated window a client reports around an error position.
    let mut echo = Command::new("/bin/sh");
    echo.arg("-c").arg(
        "statement=$(cat)\n\
         printf 'ERROR:  syntax error at or near \"END\"\\nLINE 1: %s\\n' \"$statement\" >&2\n\
         printf 'CONTEXT: ...%s...\\n' \"$(printf '%s' \"$statement\" | cut -c 45-75)\" >&2\n\
         printf '{\"ok\":false,\"echo\":\"%s\"}\\n' \"$statement\"\n\
         exit 1\n",
    );
    let error = command(
        &mut echo,
        &root,
        "secret-echo",
        Some(Input {
            bytes: statement.as_bytes(),
            secret: Some(password.as_bytes()),
        }),
    )
    .expect_err("a refused prerequisite fails");
    let error = format!("{error:#}");
    assert!(!error.contains(password), "{error}");
    assert!(!error.contains(&password[2..30]), "{error}");
    let mut echoed = 0;
    for entry in fs::read_dir(root.join("logs")).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        let rendered = String::from_utf8(bytes).unwrap();
        assert!(!rendered.contains(password), "{rendered}");
        assert!(!rendered.contains(&password[2..30]), "{rendered}");
        if rendered.contains("[redacted]") {
            echoed += 1;
            assert!(rendered.contains("syntax error") || rendered.contains("\"ok\":false"));
        }
    }
    // Both the captured diagnostics and the preserved failure report keep
    // their surrounding text, so the redaction is not an empty assertion.
    assert_eq!(echoed, 2);
}

#[test]
fn reclamation_forgets_the_database_and_keeps_the_reusable_identities() {
    let (_temp, mut state, _clients, _files) = fixture();
    state.container_id = Some("c".repeat(64));
    state.tls_files_copied = true;
    state.database_ready = true;
    state.activated = true;
    state.package_revision = Some("revision-1".into());
    state.seeded.insert("first-record".into());
    state.status = Status::Ready;
    let owner = state.owner.clone();
    let clients_file = state.clients_file.clone();
    reclaimed(&mut state);
    assert!(state.container_id.is_none());
    assert!(!state.tls_files_copied);
    assert!(!state.database_ready);
    assert!(!state.activated);
    assert!(state.seeded.is_empty());
    assert!(matches!(state.status, Status::Stopped));
    // The next start recreates an empty database with the same identities,
    // ports, credentials and already built package.
    assert_eq!(state.owner, owner);
    assert_eq!(state.clients_file, clients_file);
    assert_eq!(state.package_revision.as_deref(), Some("revision-1"));
    assert_eq!(state.database_port, 55448);
    assert_eq!(state.volume_name(), format!("breg-dev-{owner}"));
}
