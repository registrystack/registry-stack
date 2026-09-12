// SPDX-License-Identifier: Apache-2.0
use super::*;

pub(super) fn fixture() -> (tempfile::TempDir, State, Clients, BTreeMap<String, Vec<u8>>) {
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
        webhook_port: None,
        clients_file: project.join("clients.yaml"),
        source_digest: "a".repeat(64),
        sequence: 1,
        baseline_runtime: None,
        instance_id: "generic-local".into(),
        source_revision: "local".into(),
        container_id: None,
        tls_files_copied: false,
        database_ready: false,
        package_revision: None,
        activated: false,
        seeded: BTreeSet::new(),
        outputs: vec![],
        binaries: BTreeMap::new(),
        failure: None,
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

fn write_init_project() -> (tempfile::TempDir, PathBuf) {
    let temporary = tempfile::tempdir().expect("temporary");
    let project = fs::canonicalize(temporary.path()).expect("canonical");
    for (path, bytes) in crate::init_files() {
        let full = project.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, bytes).unwrap();
    }
    (temporary, project)
}

#[test]
fn a_fresh_init_project_starts_without_edits() {
    // `bregctl dev` initializes only a `local` package at sequence 1 and needs
    // one client per profile the journeys use, so the project `bregctl init`
    // writes must satisfy both with its own clients file: a reader's first
    // start needs no edit between the two commands.
    let (_temporary, project) = write_init_project();
    let client_bytes = fs::read(project.join("dev-clients.yaml")).expect("init writes clients");
    let clients = config::clients(&client_bytes).expect("the initialized clients parse");
    let captured = capture(&project, &client_bytes).expect("a fresh init project is a dev project");
    assert_eq!(captured.instance_id, "generic-registry-1");
    bind_journey_profiles(&captured.files["tests/journeys.yaml"], &clients)
        .expect("every journey profile has a client");
}

#[test]
fn a_journey_profile_without_a_client_is_refused_before_any_service_starts() {
    let (_temporary, project) = write_init_project();
    let client_bytes = br#"version: 1
clients:
  - id: operator
    accessProfiles: [operator]
    scopes: [registry:generic:operate]
    claims:
      registry_principal: generic-registry-operator
      registry_purpose: registry-operations
"#;
    let clients = config::clients(client_bytes).expect("clients");
    let captured = capture(&project, client_bytes).expect("captured");
    let refusal = bind_journey_profiles(&captured.files["tests/journeys.yaml"], &clients)
        .expect_err("the reader profile has no client")
        .to_string();
    assert!(refusal.contains("record-reader"), "{refusal}");
    assert!(
        refusal.contains("read-record-within-the-claim"),
        "{refusal}"
    );
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

/// A client may bind no access profile. Such a client still needs its own
/// unique ID and explicit scopes; it registers with Mint and appears in
/// `allowedClients`, but no journey or seed can resolve it.
#[test]
fn clients_accept_an_explicitly_unbound_profile_free_client() {
    let clients = config::clients(
        br#"version: 1
clients:
  - id: operator
    accessProfiles: [operator]
    scopes: [registry:generic:operate]
    claims:
      registry_principal: generic-registry-operator
      registry_purpose: registry-operations
  - id: guest
    accessProfiles: []
    scopes: [registry:generic:introspect]
    claims:
      registry_principal: generic-registry-guest
seed: []
"#,
    )
    .expect("a profile-free client parses");
    let guest = clients
        .clients
        .iter()
        .find(|client| client.id == "guest")
        .expect("the unbound client is retained");
    assert!(guest.access_profiles.is_empty());
}

#[test]
fn an_unbound_client_registers_with_mint_and_appears_in_allowed_clients() {
    let (_temp, state, mut clients, files) = fixture();
    clients.clients.push(config::Client {
        id: "guest".into(),
        access_profiles: vec![],
        scopes: vec!["registry:generic:introspect".into()],
        claims: BTreeMap::new(),
        client_id_file: None,
        assertion_key_file: None,
    });
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let root = state.root();
    private::read(&root.join("mint/clients/guest.yaml"), MAX_BYTES)
        .expect("the unbound client still registers with the local Mint");
    let runtime: Value = serde_norway::from_slice(
        &private::read(&root.join("runtime-test.yaml"), MAX_BYTES).unwrap(),
    )
    .unwrap();
    let allowed = runtime["authentication"]["oidc"]["allowedClients"]
        .as_array()
        .expect("allowedClients is an array");
    assert!(
        allowed.iter().any(|id| id == "guest"),
        "the unbound client is listed in allowedClients: {allowed:?}"
    );
}

/// A client with no bound access profile never interferes with rehearsal
/// binding: every journey step still resolves to the client that actually
/// binds its profile.
#[test]
fn rehearsal_binding_still_resolves_each_journey_step_despite_an_unbound_client() {
    let (_temporary, project) = write_init_project();
    let client_bytes = fs::read(project.join("dev-clients.yaml")).expect("init writes clients");
    let mut clients = config::clients(&client_bytes).expect("the initialized clients parse");
    clients.clients.push(config::Client {
        id: "guest".into(),
        access_profiles: vec![],
        scopes: vec!["registry:generic:introspect".into()],
        claims: BTreeMap::new(),
        client_id_file: None,
        assertion_key_file: None,
    });
    let captured = capture(&project, &client_bytes).expect("a fresh init project is a dev project");
    bind_journey_profiles(&captured.files["tests/journeys.yaml"], &clients)
        .expect("every journey profile still has its bound client");
}

#[test]
fn a_seed_referencing_the_unbound_client_is_refused() {
    let error = config::clients(
        br#"version: 1
clients:
  - id: operator
    accessProfiles: [operator]
    scopes: [registry:generic:operate]
    claims:
      registry_principal: generic-registry-operator
      registry_purpose: registry-operations
  - id: guest
    accessProfiles: []
    scopes: [registry:generic:introspect]
    claims:
      registry_principal: generic-registry-guest
seed:
  - id: from-guest
    client: guest
    entity: record
    accessProfile: operator
    data: {}
"#,
    )
    .expect_err("a seed cannot reference a client with no bound access profile");
    assert!(
        format!("{error:#}").contains("bound client and access profile"),
        "{error:#}"
    );
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

fn script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn resolved_prerequisites_record_a_canonical_path_and_their_reported_version() {
    let (_temp, state, clients, files) = fixture();
    let root = state.root();
    initialize(&root, &state, &clients, &files).unwrap();
    let installed = state.project.join("installed-probe");
    script(&installed, "echo 'probe 9.9.9 (build 1)'");
    let linked = state.project.join("probe");
    std::os::unix::fs::symlink(&installed, &linked).unwrap();

    // The executed path keeps the installed command name, so a distribution
    // that routes a symlink by argv[0] still behaves as installed.
    let resolved = executable("probe", Some(&linked)).unwrap();
    assert_eq!(resolved, linked);
    // The recorded path resolves that symlink, so a later diagnosis names the
    // file that served the session rather than the name it was reached by.
    let recorded = binary(&root, &resolved).unwrap();
    assert_eq!(recorded.path, fs::canonicalize(&installed).unwrap());
    assert_eq!(recorded.version, "probe 9.9.9 (build 1)");

    // A prerequisite that cannot answer keeps its path and says so.
    let silent = state.project.join("silent-probe");
    script(&silent, "exit 3");
    let silent = binary(&root, &silent).unwrap();
    assert_eq!(silent.version, UNREPORTED_VERSION);
    assert!(silent.path.ends_with("silent-probe"));

    let mut recorded_state = read_state(&root).unwrap();
    recorded_state.binaries = BTreeMap::from([("probe".into(), recorded.clone())]);
    recorded_state.save().unwrap();
    assert_eq!(read_state(&root).unwrap().binaries["probe"], recorded);
    // A state document written before this record stays readable.
    let mut document = serde_json::to_value(&recorded_state).unwrap();
    document.as_object_mut().unwrap().remove("binaries");
    private::replace(
        &root.join("state.json"),
        &serde_json::to_vec(&document).unwrap(),
    )
    .unwrap();
    assert!(read_state(&root).unwrap().binaries.is_empty());
}

#[test]
fn prerequisites_from_another_release_are_refused_before_the_session_starts() {
    let own = registry_platform_buildinfo::DISPLAY_VERSION;
    let installed = |version: &str| Binary {
        path: PathBuf::from("/usr/local/bin/installed"),
        version: version.to_owned(),
    };
    // Docker belongs to no release of this stack and names itself in its own
    // shape, so it is never compared against the stack's version.
    let session = |breg: String, mint: String| {
        BTreeMap::from([
            ("breg".to_owned(), installed(&breg)),
            ("mint".to_owned(), installed(&mint)),
            (
                "docker".to_owned(),
                installed("Docker version 29.4.0, build 1a2b3c4"),
            ),
        ])
    };

    matching_versions(&session(format!("breg {own}"), format!("mint {own}")))
        .expect("the three binaries of one release start a session");

    for (name, binaries) in [
        (
            "breg",
            session("breg 0.26.1".to_owned(), format!("mint {own}")),
        ),
        (
            "mint",
            session(format!("breg {own}"), "mint 0.26.1".to_owned()),
        ),
    ] {
        let refusal = format!(
            "{:#}",
            matching_versions(&binaries).expect_err("a prerequisite from another release")
        );
        for expected in [name, "0.26.1", "bregctl", own, "same release"] {
            assert!(refusal.contains(expected), "{refusal}");
        }
    }

    // A prerequisite that declines to identify itself still serves the
    // session, as the installed lifecycle proof starts one that never answers.
    matching_versions(&session(
        UNREPORTED_VERSION.to_owned(),
        format!("mint {own}"),
    ))
    .expect("a prerequisite that reports no version is not compared");

    // A start resolves the prerequisites and compares them before it inspects
    // a container or launches the supervisor.
    let (_temporary, project) = write_init_project();
    let prerequisites = project.join("prerequisites");
    fs::create_dir(&prerequisites).unwrap();
    for (name, reported) in [
        ("breg", "breg 0.26.1".to_owned()),
        ("mint", format!("mint {own}")),
        ("docker", "Docker version 29.4.0, build 1a2b3c4".to_owned()),
    ] {
        script(&prerequisites.join(name), &format!("echo '{reported}'"));
    }
    let refused = format!(
        "{:#}",
        start(StartArgs {
            project: project.clone(),
            clients_file: None,
            breg_port: None,
            mint_port: None,
            database_port: None,
            breg_bin: Some(prerequisites.join("breg")),
            mint_bin: Some(prerequisites.join("mint")),
            docker_bin: Some(prerequisites.join("docker")),
        })
        .expect_err("a breg from another release never starts a session")
    );
    // The named override is the file compared, and the message names it.
    assert!(refused.contains("prerequisites/breg"), "{refused}");
    assert!(refused.contains("0.26.1"), "{refused}");
    assert!(refused.contains(own), "{refused}");
}

#[test]
fn stop_before_first_start_names_the_missing_session_without_docker() {
    let temporary = tempfile::tempdir().unwrap();
    let project = fs::canonicalize(temporary.path()).unwrap();
    fs::set_permissions(&project, fs::Permissions::from_mode(0o700)).unwrap();
    let refusals = [
        stop(&project, false, None).expect_err("a project without a session"),
        stop(&project, true, None).expect_err("reclaiming without a session"),
        {
            // A private .breg directory without a dev journal is the same absence.
            private::directory(&project.join(".breg")).unwrap();
            stop(&project, false, None).expect_err("a project without a dev journal")
        },
    ];
    for refusal in refusals {
        let refusal = format!("{refusal:#}");
        assert!(
            refusal.contains("no local development session"),
            "{refusal}"
        );
    }
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

/// The pinned image and the two deadlines are facts an operator checks before
/// a first start. Hold the owning document, the command's own help text and
/// the supervisor's constants equal so they cannot drift apart.
#[test]
fn the_documented_image_and_deadlines_are_the_supervisors_own() {
    let document = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/breg/DEV.md"),
    )
    .expect("the owning lifecycle document");
    // Read the tree the binary publishes. A long description set on DevArgs
    // never reaches an operator, because the variant that carries dev states
    // its own description after the arguments are augmented.
    let cli = <crate::Cli as clap::CommandFactory>::command();
    let dev = cli
        .get_subcommands()
        .find(|command| command.get_name() == "dev")
        .expect("bregctl publishes dev");
    let help = dev
        .get_subcommands()
        .find(|command| command.get_name() == "start")
        .and_then(|command| command.get_long_about())
        .expect("dev start describes its own supervision")
        .to_string();
    for fact in [
        IMAGE.to_owned(),
        format!("{} seconds", CHILD_DEADLINE.as_secs()),
        format!("{} seconds", READY_DEADLINE.as_secs()),
    ] {
        assert!(
            document.contains(&fact),
            "products/breg/DEV.md omits {fact}"
        );
        assert!(help.contains(&fact), "bregctl dev start help omits {fact}");
    }
}

#[test]
fn every_database_url_names_the_published_loopback_literal() {
    let (_temp, state, clients, files) = fixture();
    initialize(&state.root(), &state, &clients, &files).unwrap();
    for name in [
        "runtime-database-url",
        "migration-database-url",
        "test-runtime-database-url",
        "test-migration-database-url",
    ] {
        // The container publishes on 127.0.0.1 only, and a host that resolves
        // localhost to ::1 first cannot reach it. Compare the parsed host, so
        // a failure never prints the URL's password.
        let url = reqwest::Url::parse(
            &String::from_utf8(
                private::read(&state.root().join("secrets").join(name), MAX_BYTES).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(url.host_str(), Some("127.0.0.1"), "{name}");
        assert_eq!(url.port(), Some(state.database_port), "{name}");
    }
}

#[test]
fn verify_outputs_publishes_a_recorded_pair_after_a_partial_start() {
    let (_temp, state, mut clients, files) = fixture();
    let out = state.project.join("out");
    private::directory(&out).unwrap();
    clients.clients[1].client_id_file = Some(out.join("id"));
    clients.clients[1].assertion_key_file = Some(out.join("key"));
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let state = read_state(&state.root()).unwrap();
    // A start that failed before publishing leaves both halves absent. The
    // retry publishes the recorded pair from the retained credentials rather
    // than generating a second identity for the same client.
    assert!(!out.join("id").exists());
    assert!(!out.join("key").exists());
    verify_outputs(&state).expect("a retry publishes the recorded pair");
    let credentials = state.root().join("credentials/source");
    for (published, retained) in [("id", "client-id"), ("key", "assertion-key.jwk")] {
        assert_eq!(
            private::read(&out.join(published), MAX_BYTES).unwrap(),
            private::read(&credentials.join(retained), MAX_BYTES).unwrap()
        );
    }
    private::validate_tree(&out).expect("published credentials stay owner-only");

    // A retained credential replaced under the recorded pair stops the start
    // instead of publishing bytes the record does not name.
    private::replace(&credentials.join("client-id"), b"replaced-by-hand").unwrap();
    let refused = format!(
        "{:#}",
        verify_outputs(&state).expect_err("changed credential")
    );
    assert!(refused.contains("owned credential changed"), "{refused}");
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

fn schema_test_refusal(message: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"ok":false,"command":"test","diagnostics":[
        {"severity":"error","code":"test.step.failed","artifact":"fixtureJourneys",
         "path":"journeys[0].steps[1]","message":message,
         "suggestedAction":"correctFixtureJourneys"}]}))
    .unwrap()
}

#[test]
fn a_refused_native_command_names_its_first_failing_check_within_a_bound() {
    let message =
        "the fixture logical reference was refused: the request names a capture no earlier step declares";
    let named =
        refused_check(&schema_test_refusal(message)).expect("the report names its first check");
    assert!(named.contains("test.step.failed"), "{named}");
    assert!(named.contains("journeys[0].steps[1]"), "{named}");
    assert!(named.contains(message), "{named}");

    // A long refusal is bounded like every other captured output; the
    // retained report keeps the rest.
    let long = "x".repeat(MAX_REFUSAL * 2);
    let bounded =
        refused_check(&schema_test_refusal(&long)).expect("a long refusal is still named");
    assert!(bounded.chars().count() <= MAX_REFUSAL, "{}", bounded.len());

    // Output that names no diagnostic leaves the logs pointer as the answer.
    assert_eq!(refused_check(b"not a report"), None);
    assert_eq!(refused_check(br#"{"ok":false,"diagnostics":[]}"#), None);
}

#[test]
fn a_refused_schema_test_reports_the_check_that_failed_beside_the_report_log() {
    let (_temporary, state, clients, files) = fixture();
    let root = state.root();
    initialize(&root, &state, &clients, &files).unwrap();
    let message = "journeys[0].steps[1]: the fixture expectation did not match";
    let report = String::from_utf8(schema_test_refusal(message)).unwrap();
    let refusing = state.project.join("refusing-test");
    script(
        &refusing,
        &format!("cat <<'REPORT'\n{report}\nREPORT\nexit 1"),
    );
    let error = command(&mut Command::new(&refusing), &root, "schema-test", None)
        .expect_err("a refused schema test stops the start");
    let error = format!("{error:#}");
    assert!(error.contains(message), "{error}");
    assert!(error.contains("test.step.failed"), "{error}");
    assert!(
        error.contains(&root.join("logs").display().to_string()),
        "{error}"
    );
}

#[test]
fn a_supervisor_refusal_reaches_the_owner_who_asked_for_the_start() {
    let (_temporary, state, clients, files) = fixture();
    let root = state.root();
    initialize(&root, &state, &clients, &files).unwrap();
    let mut recorded = read_state(&root).unwrap();
    assert_eq!(recorded.failure, None);

    // The supervisor runs detached with both streams in a private log, so the
    // cause only reaches the terminal through the state document.
    recorded.status = Status::Failed;
    recorded.failure = Some("native schema-test refused: test.step.failed".to_owned());
    recorded.save().unwrap();
    let read = read_state(&root).unwrap();
    assert_eq!(
        read.failure.as_deref(),
        Some("native schema-test refused: test.step.failed")
    );
    let reported = format!("{:#}", start_failure(read.failure.as_deref(), &root));
    assert!(reported.contains("test.step.failed"), "{reported}");
    assert!(
        reported.contains(&root.join("logs").display().to_string()),
        "{reported}"
    );
    // A start that failed without a recorded cause still names the logs.
    let silent = format!("{:#}", start_failure(None, &root));
    assert!(
        silent.contains(&root.join("logs").display().to_string()),
        "{silent}"
    );

    // A cause that already names the retained log directory does not have it
    // repeated back to the reader.
    let logs = root.join("logs").display().to_string();
    let named = format!(
        "{:#}",
        start_failure(
            Some(&format!(
                "native schema-test refused: test.step.failed at journeys[0].steps[1]: the fixture expectation did not match. The full report and owner-only diagnostics are in {logs}"
            )),
            &root
        )
    );
    assert_eq!(named.matches(&logs).count(), 1, "{named}");
    assert!(named.contains("Retry the same command"), "{named}");

    // A state document written before this record stays readable.
    let mut document = serde_json::to_value(&read).unwrap();
    document.as_object_mut().unwrap().remove("failure");
    private::replace(
        &root.join("state.json"),
        &serde_json::to_vec(&document).unwrap(),
    )
    .unwrap();
    assert_eq!(read_state(&root).unwrap().failure, None);
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
    let canary = "6f0a1b2c3d4e5f60718293a4b5c6d7e8";
    let statement = format!("DO $$ BEGIN CREATE ROLE r LOGIN PASSWORD '{canary}'; END $$;");
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
            secret: Some(canary.as_bytes()),
        }),
    )
    .expect_err("a refused prerequisite fails");
    let error = format!("{error:#}");
    assert!(!error.contains(canary), "{error}");
    assert!(!error.contains(&canary[2..30]), "{error}");
    let mut echoed = 0;
    for entry in fs::read_dir(root.join("logs")).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        let rendered = String::from_utf8(bytes).unwrap();
        assert!(!rendered.contains(canary), "{rendered}");
        assert!(!rendered.contains(&canary[2..30]), "{rendered}");
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
fn a_control_command_split_across_writes_is_read_whole() {
    for (first, second, whole) in [
        (&b"sto"[..], &b"p\n"[..], &b"stop\n"[..]),
        (&b"stat"[..], &b"us\n"[..], &b"status\n"[..]),
    ] {
        let (mut reader, mut writer) = UnixStream::pair().expect("pair");
        reader
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("timeout");
        let writer_thread = thread::spawn(move || {
            writer.write_all(first).expect("first write");
            thread::sleep(Duration::from_millis(100));
            writer.write_all(second).expect("second write");
        });
        let bytes = read_control_command(&mut reader).expect("read");
        assert_eq!(bytes, whole);
        writer_thread.join().expect("writer thread");
    }
}

#[test]
fn a_control_command_stops_at_the_newline_or_the_size_bound() {
    {
        let (mut reader, mut writer) = UnixStream::pair().expect("pair");
        reader
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("timeout");
        writer.write_all(b"status\nextra").expect("write");
        let bytes = read_control_command(&mut reader).expect("read");
        assert_eq!(bytes, b"status\n");
    }
    {
        let (mut reader, mut writer) = UnixStream::pair().expect("pair");
        reader
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("timeout");
        writer.write_all(&[b'a'; 20]).expect("write");
        let bytes = read_control_command(&mut reader).expect("read");
        assert_eq!(bytes, vec![b'a'; 16]);
    }
    {
        let (mut reader, mut writer) = UnixStream::pair().expect("pair");
        reader
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("timeout");
        writer.write_all(b"sto").expect("write");
        drop(writer);
        let bytes = read_control_command(&mut reader).expect("read");
        assert_eq!(bytes, b"sto");
    }
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

/// A retained session initialized from the project `bregctl init` writes,
/// with the digest a start computes, so a later start compares real inputs.
fn retained_session(project: &Path, container_id: Option<String>) -> State {
    let client_bytes = fs::read(project.join("dev-clients.yaml")).unwrap();
    let clients = config::clients(&client_bytes).unwrap();
    let captured = capture(project, &client_bytes).unwrap();
    private::directory(&project.join(".breg")).unwrap();
    let state = State {
        version: 1,
        project: project.to_path_buf(),
        owner: uuid::Uuid::new_v4().to_string(),
        status: Status::Stopped,
        breg_port: 8094,
        mint_port: 8095,
        database_port: 55448,
        webhook_port: None,
        clients_file: project.join("dev-clients.yaml"),
        source_digest: captured.digest,
        sequence: 1,
        baseline_runtime: None,
        instance_id: captured.instance_id,
        source_revision: captured.source_revision,
        container_id,
        tls_files_copied: false,
        database_ready: false,
        package_revision: None,
        activated: false,
        seeded: BTreeSet::new(),
        outputs: vec![],
        binaries: BTreeMap::new(),
        failure: None,
    };
    initialize(&state.root(), &state, &clients, &captured.files).unwrap();
    read_state(&state.root()).unwrap()
}

fn start_without_binaries(project: &Path) -> Result<Value> {
    start(StartArgs {
        project: project.to_path_buf(),
        clients_file: None,
        breg_port: None,
        mint_port: None,
        database_port: None,
        breg_bin: Some(project.join("missing-breg")),
        mint_bin: None,
        docker_bin: None,
    })
}

#[test]
fn a_first_start_reads_the_projects_dev_clients_without_a_flag() {
    let (_temporary, project) = write_init_project();
    let expected = fs::canonicalize(project.join("dev-clients.yaml")).unwrap();
    assert_eq!(clients_file(None, None, &project).unwrap(), expected);

    // A retained session keeps the file it started with, wherever it is.
    let (_temp, retained, _clients, _files) = fixture();
    assert_eq!(
        clients_file(None, Some(&retained), &project).unwrap(),
        retained.clients_file
    );

    // An explicit file still wins, and must exist.
    let explicit = project.join("tests/journeys.yaml");
    assert_eq!(
        clients_file(Some(&explicit), Some(&retained), &project).unwrap(),
        fs::canonicalize(&explicit).unwrap()
    );
    let missing = clients_file(Some(&project.join("absent.yaml")), None, &project)
        .expect_err("a named file must exist")
        .to_string();
    assert!(missing.contains("clients file does not exist"), "{missing}");

    // A project without the generated file says which flag replaces it.
    fs::remove_file(project.join("dev-clients.yaml")).unwrap();
    let refusal = clients_file(None, None, &project)
        .expect_err("no clients anywhere")
        .to_string();
    assert!(refusal.contains("dev-clients.yaml"), "{refusal}");
    assert!(refusal.contains("--clients-file"), "{refusal}");
}

#[test]
fn changed_inputs_are_refused_while_the_session_holds_records() {
    let (_temporary, project) = write_init_project();
    let state = retained_session(&project, Some("c".repeat(64)));
    let registry = project.join("registry.yaml");
    let mut edited = fs::read(&registry).unwrap();
    edited.extend_from_slice(b"\n# edited after the first start\n");
    fs::write(&registry, edited).unwrap();

    let refusal = format!(
        "{:#}",
        start_without_binaries(&project).expect_err("records are retained")
    );
    assert!(refusal.contains("dev stop --remove"), "{refusal}");
    let unchanged = read_state(&state.root()).unwrap();
    assert_eq!(unchanged.source_digest, state.source_digest);
    assert_eq!(unchanged.owner, state.owner);
    assert!(state
        .root()
        .join("credentials/operator/assertion-key.jwk")
        .is_file());
}

#[test]
fn changed_inputs_replace_a_session_whose_records_were_discarded() {
    // After `dev stop --remove` nothing remains for the source pin to protect,
    // so an edited project starts a fresh session on the retained ports.
    let (_temporary, project) = write_init_project();
    let state = retained_session(&project, None);
    let previous_key =
        fs::read(state.root().join("credentials/operator/assertion-key.jwk")).unwrap();
    let registry = project.join("registry.yaml");
    let mut edited = fs::read(&registry).unwrap();
    edited.extend_from_slice(b"\n# edited after the records were discarded\n");
    fs::write(&registry, edited).unwrap();
    let client_bytes = fs::read(project.join("dev-clients.yaml")).unwrap();
    let expected = capture(&project, &client_bytes).unwrap().digest;

    // The start fails only once it looks for the breg binary, after the
    // replaced session is on disk.
    let failure = format!(
        "{:#}",
        start_without_binaries(&project).expect_err("no breg binary")
    );
    assert!(!failure.contains("dev stop --remove"), "{failure}");
    let replaced = read_state(&state.root()).unwrap();
    assert_eq!(replaced.source_digest, expected);
    assert_ne!(replaced.owner, state.owner);
    assert_eq!(
        (
            replaced.breg_port,
            replaced.mint_port,
            replaced.database_port
        ),
        (8094, 8095, 55448)
    );
    assert_eq!(replaced.clients_file, state.clients_file);
    assert!(replaced.container_id.is_none());
    let key = fs::read(state.root().join("credentials/operator/assertion-key.jwk")).unwrap();
    assert_ne!(key, previous_key);
}

#[test]
fn the_private_directory_is_ignored_by_version_control() {
    // The lock beside the session directory would otherwise be the one
    // private file a reader could commit.
    let temporary = tempfile::tempdir().unwrap();
    let project = fs::canonicalize(temporary.path()).unwrap();
    let parent = parent_directory(&project).unwrap();
    assert_eq!(parent, project.join(".breg"));
    let ignore = parent.join(".gitignore");
    assert_eq!(private::read(&ignore, MAX_BYTES).unwrap(), b"*\n");
    assert_eq!(parent_directory(&project).unwrap(), parent);
    assert_eq!(private::read(&ignore, MAX_BYTES).unwrap(), b"*\n");

    // A file the reader wrote is theirs.
    fs::write(&ignore, "dev/\n").unwrap();
    parent_directory(&project).unwrap();
    assert_eq!(fs::read(&ignore).unwrap(), b"dev/\n");
}

fn export_args(state: &State) -> export_client::ExportClientArgs {
    export_client::ExportClientArgs {
        project: state.project.clone(),
        client: "source".into(),
        client_id_file: state.project.join("export-id"),
        assertion_key_file: state.project.join("export-key"),
    }
}

#[test]
fn export_client_copies_a_stopped_retained_pair_and_retries_without_state_changes() {
    let (_temp, state, clients, files) = fixture();
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let before = fs::read(state.root().join("state.json")).unwrap();
    let registrations = fs::read(state.root().join("mint/clients/source.yaml")).unwrap();
    let retained_clients = fs::read(state.root().join("clients.json")).unwrap();
    // Authored input is deliberately absent: only the retained session is used.
    let report = export_client::run(export_args(&state)).unwrap();
    assert_eq!(report["client"], "source");
    assert_eq!(report["accessProfiles"], json!(["evidence-source"]));
    let id = fs::read(state.root().join("credentials/source/client-id")).unwrap();
    let key = fs::read(state.root().join("credentials/source/assertion-key.jwk")).unwrap();
    assert_eq!(fs::read(&export_args(&state).client_id_file).unwrap(), id);
    assert_eq!(
        fs::read(&export_args(&state).assertion_key_file).unwrap(),
        key
    );
    assert!(!report.to_string().contains("\"d\""));
    export_client::run(export_args(&state)).expect("identical re-export");
    fs::remove_file(export_args(&state).assertion_key_file).unwrap();
    export_client::run(export_args(&state)).expect("retry a partially published pair");
    assert_eq!(fs::read(state.root().join("state.json")).unwrap(), before);
    assert_eq!(
        fs::read(state.root().join("clients.json")).unwrap(),
        retained_clients
    );
    assert_eq!(
        fs::read(state.root().join("mint/clients/source.yaml")).unwrap(),
        registrations
    );
    assert_eq!(
        fs::read(&export_args(&state).assertion_key_file).unwrap(),
        key
    );
    private::check(&export_args(&state).client_id_file, false).unwrap();
    private::check(&export_args(&state).assertion_key_file, false).unwrap();
}

#[test]
fn export_client_refuses_missing_session_client_and_incomplete_credentials_before_output() {
    let (_temp, state, clients, files) = fixture();
    assert!(export_client::run(export_args(&state))
        .unwrap_err()
        .to_string()
        .contains("no retained"));
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let mut args = export_args(&state);
    args.client = "absent".into();
    assert!(export_client::run(args)
        .unwrap_err()
        .to_string()
        .contains("absent"));
    private::replace(
        &state.root().join("credentials/source/assertion-key.jwk"),
        b"SECRET-CANARY",
    )
    .unwrap();
    let error = export_client::run(export_args(&state)).unwrap_err();
    assert!(!format!("{error:#}").contains("SECRET-CANARY"));
    assert!(!export_args(&state).client_id_file.exists());
    fs::remove_file(state.root().join("credentials/source/assertion-key.jwk")).unwrap();
    assert!(export_client::run(export_args(&state)).is_err());
    assert!(!export_args(&state).client_id_file.exists());
}

#[test]
fn export_client_preflights_both_outputs_and_preserves_conflicts() {
    let (_temp, state, clients, files) = fixture();
    initialize(&state.root(), &state, &clients, &files).unwrap();
    private::create(&export_args(&state).assertion_key_file, b"SECRET-CANARY").unwrap();
    let error = export_client::run(export_args(&state)).unwrap_err();
    assert!(error.to_string().contains("fresh output paths"));
    assert!(!format!("{error:#}").contains("SECRET-CANARY"));
    assert!(!export_args(&state).client_id_file.exists());
    assert_eq!(
        fs::read(export_args(&state).assertion_key_file).unwrap(),
        b"SECRET-CANARY"
    );
    let mut args = export_args(&state);
    args.assertion_key_file = args.client_id_file.clone();
    assert!(export_client::run(args)
        .unwrap_err()
        .to_string()
        .contains("distinct"));
}

#[test]
fn export_client_refuses_unsafe_destinations_and_source_links() {
    use std::os::unix::fs::symlink;
    for kind in [
        "symlink",
        "hardlink",
        "public-file",
        "directory",
        "public-parent",
        "source-link",
    ] {
        let (_temp, state, clients, files) = fixture();
        initialize(&state.root(), &state, &clients, &files).unwrap();
        let args = export_args(&state);
        let source = state.root().join("credentials/source/assertion-key.jwk");
        match kind {
            "symlink" => symlink(&source, &args.assertion_key_file).unwrap(),
            "hardlink" => fs::hard_link(&source, &args.assertion_key_file).unwrap(),
            "public-file" => {
                fs::write(&args.assertion_key_file, fs::read(&source).unwrap()).unwrap();
                fs::set_permissions(&args.assertion_key_file, fs::Permissions::from_mode(0o644))
                    .unwrap();
            }
            "directory" => fs::create_dir(&args.assertion_key_file).unwrap(),
            "public-parent" => {
                fs::set_permissions(&state.project, fs::Permissions::from_mode(0o755)).unwrap()
            }
            "source-link" => {
                fs::remove_file(&source).unwrap();
                symlink("public.jwk", &source).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(export_client::run(args).is_err(), "{kind}");
        assert!(!export_args(&state).client_id_file.exists(), "{kind}");
    }
}

#[test]
fn plain_init_source_client_has_only_the_explicit_lookup_profile_and_a_distinct_key() {
    let (_temp, mut state, _, files) = fixture();
    let clients = config::clients(crate::INIT_DEV_CLIENTS).unwrap();
    let source = clients
        .clients
        .iter()
        .find(|client| client.id == "source")
        .unwrap();
    assert_eq!(source.access_profiles, ["evidence-source"]);
    assert_eq!(source.scopes, ["registry:evidence:lookup"]);
    assert_eq!(source.claims["registry_purpose"], "evidence-source-read");
    assert_eq!(
        source.claims["registry_principal"],
        "generic-registry-source"
    );
    assert!(source.client_id_file.is_none() && source.assertion_key_file.is_none());
    state.status = Status::Stopped;
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let key = fs::read(state.root().join("credentials/source/assertion-key.jwk")).unwrap();
    for other in ["operator", "reader", "issuer"] {
        assert_ne!(
            key,
            fs::read(
                state
                    .root()
                    .join(format!("credentials/{other}/assertion-key.jwk"))
            )
            .unwrap()
        );
    }
}

#[test]
fn export_client_reuses_readable_nonexecutable_credentials_only() {
    for mode in [0o400, 0o600, 0o700] {
        let (_temp, state, clients, files) = fixture();
        initialize(&state.root(), &state, &clients, &files).unwrap();
        let args = export_args(&state);
        let key = fs::read(state.root().join("credentials/source/assertion-key.jwk")).unwrap();
        private::create(&args.assertion_key_file, &key).unwrap();
        fs::set_permissions(&args.assertion_key_file, fs::Permissions::from_mode(mode)).unwrap();
        let result = export_client::run(args);
        if mode == 0o700 {
            assert!(
                result.is_err(),
                "executable credential output must be refused"
            );
            assert!(!export_args(&state).client_id_file.exists());
        } else {
            result.expect("identical readable credential is reusable");
            assert!(export_args(&state).client_id_file.exists());
        }
        assert_eq!(
            fs::read(export_args(&state).assertion_key_file).unwrap(),
            key
        );
        assert_eq!(
            fs::metadata(export_args(&state).assertion_key_file)
                .unwrap()
                .mode()
                & 0o7777,
            mode
        );
    }
}

#[test]
fn removed_successor_database_is_refused_before_any_prerequisite_or_recreation() {
    let (_temporary, project) = write_init_project();
    let mut state = retained_session(&project, Some("a".repeat(64)));
    state.sequence = 2;
    state.baseline_runtime = Some(state.root().join("baseline-1/runtime.yaml"));
    reclaimed(&mut state);
    state.save().unwrap();
    let before = private::read(&state.root().join("state.json"), MAX_BYTES).unwrap();
    let error = start_without_binaries(&project).unwrap_err().to_string();
    assert!(
        error.contains("successor database was explicitly removed"),
        "{error}"
    );
    assert_eq!(
        private::read(&state.root().join("state.json"), MAX_BYTES).unwrap(),
        before
    );
    assert!(read_state(&state.root()).unwrap().container_id.is_none());
}

#[test]
fn package_rebuild_accepts_public_native_receipts_and_preserves_the_baseline() {
    let (_temporary, state, clients, files) = fixture();
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let root = state.root();
    let receipt = root.join("schema-test-receipt.json");
    fs::write(&receipt, b"{}\n").unwrap();
    fs::set_permissions(&receipt, fs::Permissions::from_mode(0o644)).unwrap();
    private::create(&root.join("runtime.yaml"), b"private deployment binding").unwrap();
    private::directory(&root.join("build")).unwrap();
    private::directory(&root.join("baseline-1")).unwrap();
    private::directory(&root.join("baseline-1/build")).unwrap();
    private::create(&root.join("baseline-1/build/retained"), b"predecessor").unwrap();
    clear_package_outputs(&root).unwrap();
    assert!(!receipt.exists());
    assert!(!root.join("runtime.yaml").exists());
    assert!(!root.join("build").exists());
    assert_eq!(
        fs::read(root.join("baseline-1/build/retained")).unwrap(),
        b"predecessor"
    );
    clear_package_outputs(&root).unwrap();
}

#[test]
fn package_rebuild_refuses_linked_receipts_and_public_runtime_bindings() {
    let (_temporary, state, clients, files) = fixture();
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let root = state.root();
    let other = root.join("unrelated");
    private::create(&other, b"preserve").unwrap();
    let receipt = root.join("schema-test-receipt.json");
    std::os::unix::fs::symlink(&other, &receipt).unwrap();
    assert!(clear_package_outputs(&root).is_err());
    assert_eq!(fs::read(&other).unwrap(), b"preserve");
    fs::remove_file(&receipt).unwrap();
    fs::hard_link(&other, &receipt).unwrap();
    assert!(clear_package_outputs(&root).is_err());
    fs::remove_file(&receipt).unwrap();
    let runtime = root.join("runtime.yaml");
    fs::write(&runtime, b"private deployment binding").unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(clear_package_outputs(&root).is_err());
    assert!(runtime.exists());
}

/// `dev prepare-source` is the owning operation `evidencectl source add`
/// drives, not a step an adopter runs by hand, so `bregctl dev --help` lists
/// the lifecycle commands only. It stays a working command behind that help.
#[test]
fn prepare_source_stays_runnable_while_dev_help_omits_it() {
    let cli = <crate::Cli as clap::CommandFactory>::command();
    let dev = cli
        .get_subcommands()
        .find(|command| command.get_name() == "dev")
        .expect("bregctl publishes dev");
    let listed: Vec<_> = dev
        .get_subcommands()
        .filter(|command| !command.is_hide_set())
        .map(clap::Command::get_name)
        .collect();
    assert!(
        !listed.contains(&"prepare-source"),
        "dev help lists {listed:?}"
    );
    assert!(listed.contains(&"start"), "dev help lists {listed:?}");
    assert!(
        dev.get_subcommands()
            .any(|command| command.get_name() == "prepare-source"),
        "dev keeps prepare-source as a command"
    );

    let temporary = tempfile::tempdir().expect("temporary");
    let project = fs::canonicalize(temporary.path()).expect("canonical");
    let parsed = <crate::Cli as clap::Parser>::try_parse_from([
        "bregctl".as_ref(),
        "dev".as_ref(),
        "prepare-source".as_ref(),
        project.as_os_str(),
    ])
    .expect("hidden commands still parse");
    let crate::Command::Dev(args) = parsed.command else {
        panic!("dev prepare-source parsed");
    };
    // The command runs and reaches its own refusal, not a parser error.
    let error = format!("{:#}", run(args).expect_err("no session exists here"));
    assert!(error.contains("local state path is missing"), "{error}");
}

/// Every published starter is a project a first `bregctl dev` starts with no
/// clients flag, so each one carries the file name that start reads.
#[test]
fn every_published_starter_carries_the_clients_file_a_first_start_reads() {
    let starters = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/breg/starters");
    let mut covered = 0;
    for entry in fs::read_dir(&starters).expect("the published starters") {
        let project = entry.expect("starter entry").path().join("core");
        if !project.is_dir() {
            continue;
        }
        let resolved = clients_file(None, None, &project).expect("a first start reads the file");
        assert_eq!(
            resolved,
            fs::canonicalize(project.join("dev-clients.yaml")).unwrap()
        );
        config::clients(&fs::read(&resolved).unwrap()).expect("starter clients parse");
        covered += 1;
    }
    // Naming the starters here would hold their subjects in shipped source.
    assert_eq!(covered, 4, "every published starter is covered");
}

#[test]
fn declared_events_receive_exact_private_bindings_in_rehearsal_and_runtime() {
    let (_project_temp, project) = write_init_project();
    let module = project.join("registry.yaml");
    let mut source: Value = serde_norway::from_slice(&fs::read(&module).unwrap()).unwrap();
    let entity = source["entities"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entity| entity["id"] == "record")
        .unwrap();
    entity["events"] = json!([
        {"id":"record-created-v1","trigger":"created","projection":["code"],"webhook":{"destinationId":"local-hook"}},
        {"id":"record-patched-v1","trigger":"patched","projection":["label"],"webhook":{"destinationId":"local-hook"}},
        {"id":"record-second-v1","trigger":"created","projection":["code"],"webhook":{"destinationId":"second-hook"}}
    ]);
    fs::write(&module, serde_norway::to_string(&source).unwrap()).unwrap();
    let bytes = fs::read(project.join("dev-clients.yaml")).unwrap();
    let clients = config::clients(&bytes).unwrap();
    let captured = capture(&project, &bytes).unwrap();
    let (_temp, mut state, _, _) = fixture();
    state.webhook_port = Some(18996);
    initialize(&state.root(), &state, &clients, &captured.files).unwrap();
    let root = state.root();
    private::directory(&root.join("build")).unwrap();
    private::directory(&root.join("build/package")).unwrap();
    config::runtime(
        &root,
        &state,
        &clients,
        &format!("sha256:{}", "1".repeat(64)),
        false,
    )
    .unwrap();
    let compiled = crate::compile(&root.join("project"), crate::ProfileArg::Production, "dev")
        .unwrap_or_else(|failure| panic!("{}", serde_json::to_string(&failure).unwrap()));
    for filename in ["runtime-test.yaml", "runtime.yaml"] {
        let runtime =
            registry_breg::runtime_config::load_runtime_config(&root.join(filename)).unwrap();
        let activated = runtime
            .activate_event_destinations(&compiled)
            .expect("all declared destinations activate");
        assert!(activated.lookup("local-hook").is_some());
        assert!(activated.lookup("second-hook").is_some());
        assert!(activated.lookup("undeclared").is_none());
        let value: Value =
            serde_norway::from_slice(&fs::read(root.join(filename)).unwrap()).unwrap();
        assert_eq!(value["eventDestinations"].as_object().unwrap().len(), 2);
        for binding in value["eventDestinations"].as_object().unwrap().values() {
            assert_eq!(binding["origin"], "http://127.0.0.1:18996");
            assert_eq!(binding["networkProfile"], "loopbackDevelopmentHttp");
            assert_eq!(binding["classificationCeiling"], "internal");
            assert_eq!(binding["deliveryCeilings"]["maximumAttempts"], 5);
            assert_eq!(
                binding["deliveryCeilings"]["attemptTimeoutMilliseconds"],
                5000
            );
        }
    }
    private::validate_tree(&root).unwrap();
    let saved = read_state(&root).unwrap();
    assert_eq!(saved.webhook_port, Some(18996));
    // Reproduce an older failed first start: owned database and credentials,
    // but empty destination bindings and no retained receiver state/key.
    let credentials = fs::read(root.join("credentials/operator/assertion-key.jwk")).unwrap();
    let mut old = saved.clone();
    old.webhook_port = None;
    old.container_id = Some("a".repeat(64));
    old.status = Status::Failed;
    fs::remove_file(root.join("secrets/webhook-key")).unwrap();
    fs::remove_file(root.join("runtime-test.yaml")).unwrap();
    config::runtime(
        &root,
        &old,
        &clients,
        &format!("sha256:{}", "1".repeat(64)),
        true,
    )
    .unwrap();
    old.save().unwrap();
    prepare_receiver(&mut old, &clients).unwrap();
    let retained_port = old.webhook_port.unwrap();
    let retained_key = fs::read(root.join("secrets/webhook-key")).unwrap();
    prepare_receiver(&mut old, &clients).unwrap();
    assert_eq!(old.webhook_port, Some(retained_port));
    assert_eq!(old.container_id.as_deref(), Some("a".repeat(64).as_str()));
    assert_eq!(
        fs::read(root.join("secrets/webhook-key")).unwrap(),
        retained_key
    );
    assert_eq!(
        fs::read(root.join("credentials/operator/assertion-key.jwk")).unwrap(),
        credentials
    );
    registry_breg::runtime_config::load_runtime_config(&root.join("runtime-test.yaml"))
        .unwrap()
        .activate_event_destinations(&compiled)
        .unwrap();
    let mut invalid = saved;
    invalid.webhook_port = Some(invalid.breg_port);
    invalid.save().unwrap();
    assert!(read_state(&root).is_err());
}

#[test]
fn old_event_free_sessions_keep_working_without_receiver_state() {
    let (_temp, state, clients, files) = fixture();
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let mut value = serde_json::to_value(&state).unwrap();
    value.as_object_mut().unwrap().remove("webhookPort");
    private::replace(
        &state.root().join("state.json"),
        &serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    assert_eq!(read_state(&state.root()).unwrap().webhook_port, None);
    assert!(!state.root().join("secrets/webhook-key").exists());
    let report = events::report(&state.root(), false).unwrap();
    assert_eq!(report["deliveries"], json!([]));
}
