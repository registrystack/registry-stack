// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::project::{STANDALONE_DEV_CLIENTS, STANDALONE_YAML};
use clap::Parser;
use registry_casework::RuntimeConfig;

fn session(project: &Path) -> State {
    State {
        version: 1,
        project: project.to_path_buf(),
        owner: uuid::Uuid::new_v4().to_string(),
        status: Status::Stopped,
        casework_port: 8092,
        mint_port: 8093,
        database_port: 55433,
        clients_file: project.join("dev-clients.yaml"),
        source_digest: String::new(),
        clients: Vec::new(),
        container_id: None,
        tls_files_copied: false,
        database_ready: false,
        migrated: false,
        seeded: BTreeSet::new(),
        directory_revision: 0,
        directory_teams: 0,
        binaries: BTreeMap::new(),
        failure: None,
    }
}

/// An authored standalone project, exactly as `caseworkctl init` writes it.
fn standalone(root: &Path) -> PathBuf {
    let project = root.join("project");
    fs::create_dir(&project).unwrap();
    fs::write(project.join("casework.yaml"), STANDALONE_YAML).unwrap();
    fs::write(project.join("dev-clients.yaml"), STANDALONE_DEV_CLIENTS).unwrap();
    project
}

fn wait_for_process_exit(pid: rustix::process::Pid, grace: Duration) -> bool {
    let deadline = Instant::now() + grace;
    while rustix::process::test_kill_process(pid).is_ok() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    rustix::process::test_kill_process(pid).is_err()
}

#[test]
fn init_clients_bind_the_standalone_template() {
    let root = tempfile::tempdir().unwrap();
    let project = standalone(root.path());
    let policy = crate::project::load_and_check_policy(&project).unwrap();
    let clients = config::clients(STANDALONE_DEV_CLIENTS.as_bytes()).unwrap();
    let bound = config::bind(&clients, &policy).unwrap();

    let roles: BTreeMap<&str, CaseworkRole> = bound
        .iter()
        .map(|entry| (entry.client.id.as_str(), entry.role))
        .collect();
    assert_eq!(roles["administrator"], CaseworkRole::Administrator);
    assert_eq!(roles["supervisor"], CaseworkRole::Supervisor);
    assert_eq!(roles["staff"], CaseworkRole::Staff);
    assert_eq!(roles["requester"], CaseworkRole::Requester);
    // Only a person carries the human identity claim.
    for entry in &bound {
        let human = entry.client.claims.contains_key(config::HUMAN_CLAIM);
        assert_eq!(human, entry.role != CaseworkRole::Requester);
    }
    assert_eq!(clients.directory.len(), 1);
    assert_eq!(clients.directory[0].queue, "decisions");
}

#[test]
fn clients_file_refuses_unknown_keys_and_repeated_identity() {
    let unknown = b"version: 1\nclients:\n  - id: staff\n    accessProfile: staff\n    scopes: [casework:staff]\n    principal: urn:someone\n";
    assert!(config::clients(unknown).is_err());

    let version = b"version: 2\nclients:\n  - id: staff\n    accessProfile: staff\n    scopes: [casework:staff]\n";
    assert!(config::clients(version).is_err());

    let duplicate = b"version: 1\nclients:\n  - id: staff\n    accessProfile: staff\n    scopes: [casework:staff]\n  - id: staff\n    accessProfile: supervisor\n    scopes: [casework:supervisor]\n";
    assert!(config::clients(duplicate).is_err());

    // The local issuer owns this identity; a client may not take it.
    let reserved = b"version: 1\nclients:\n  - id: issuer\n    accessProfile: staff\n    scopes: [casework:staff]\n";
    assert!(config::clients(reserved).is_err());

    let redefined = b"version: 1\nclients:\n  - id: staff\n    accessProfile: staff\n    scopes: [casework:staff]\n    claims:\n      scope: casework:admin\n";
    assert!(config::clients(redefined).is_err());

    let unknown_member = b"version: 1\nclients:\n  - id: staff\n    accessProfile: staff\n    scopes: [casework:staff]\ndirectory:\n  - team: decisions-team\n    queue: decisions\n    staff: [absent]\n";
    let refusal = format!("{:#}", config::clients(unknown_member).unwrap_err());
    assert!(refusal.contains("absent"), "{refusal}");
}

#[test]
fn clients_file_refuses_duplicate_and_non_rfc6749_scopes() {
    for scopes in [
        "[casework:staff, casework:staff]",
        "['casework:\"staff']",
        r"['casework:\staff']",
        "[casework:stáff]",
    ] {
        let invalid = STANDALONE_DEV_CLIENTS
            .replace("scopes: [casework:staff]", &format!("scopes: {scopes}"));
        assert_ne!(invalid, STANDALONE_DEV_CLIENTS);

        let refusal = format!("{:#}", config::clients(invalid.as_bytes()).unwrap_err());
        assert!(refusal.contains("unique"), "{refusal}");
        assert!(refusal.contains("RFC 6749 scope-tokens"), "{refusal}");
    }
}

#[test]
fn clients_file_refuses_invalid_and_mint_reserved_claim_names() {
    let invalid_name = STANDALONE_DEV_CLIENTS.replace(
        "registry_actor_kind: human",
        r"'registry\actor_kind': human",
    );
    assert_ne!(invalid_name, STANDALONE_DEV_CLIENTS);
    let refusal = format!(
        "{:#}",
        config::clients(invalid_name.as_bytes()).unwrap_err()
    );
    assert!(refusal.contains("claim names"), "{refusal}");
    assert!(refusal.contains("RFC 6749 scope-tokens"), "{refusal}");

    // `aud` was previously accepted here, then rejected when `dev` copied it
    // into Mint's closed client-registration contract.
    let reserved = STANDALONE_DEV_CLIENTS.replace("registry_actor_kind: human", "aud: human");
    assert_ne!(reserved, STANDALONE_DEV_CLIENTS);
    let refusal = format!("{:#}", config::clients(reserved.as_bytes()).unwrap_err());
    assert!(
        refusal.contains("registered access-token claims"),
        "{refusal}"
    );
}

#[test]
fn clients_file_refuses_repeated_members_within_each_team_role() {
    for (members, repeated, expected) in [
        ("staff: [staff]", "staff: [staff, staff]", "staff list"),
        (
            "supervisors: [supervisor]",
            "supervisors: [supervisor, supervisor]",
            "supervisors list",
        ),
    ] {
        let invalid = STANDALONE_DEV_CLIENTS.replace(members, repeated);
        assert_ne!(invalid, STANDALONE_DEV_CLIENTS);

        let refusal = format!("{:#}", config::clients(invalid.as_bytes()).unwrap_err());
        assert!(refusal.contains("decisions-team"), "{refusal}");
        assert!(refusal.contains(expected), "{refusal}");
        assert!(refusal.contains("at most once"), "{refusal}");
    }
}

#[test]
fn clients_file_refuses_two_teams_assigned_to_one_queue() {
    let duplicate_queue = STANDALONE_DEV_CLIENTS.replace(
        "  - team: decisions-team\n",
        "  - team: intake-team\n    queue: decisions\n    staff: [staff]\n    supervisors: [supervisor]\n  - team: decisions-team\n",
    );
    assert_ne!(duplicate_queue, STANDALONE_DEV_CLIENTS);

    let refusal = format!(
        "{:#}",
        config::clients(duplicate_queue.as_bytes()).unwrap_err()
    );
    assert!(refusal.contains("decisions"), "{refusal}");
    assert!(refusal.contains("only one team"), "{refusal}");
}

#[test]
fn binding_refuses_a_requester_with_a_human_claim() {
    let root = tempfile::tempdir().unwrap();
    let project = standalone(root.path());
    let policy = crate::project::load_and_check_policy(&project).unwrap();
    let text = STANDALONE_DEV_CLIENTS.replace(
        "  - id: requester\n    accessProfile: requester\n    scopes: [casework:request]\n",
        "  - id: requester\n    accessProfile: requester\n    scopes: [casework:request]\n    claims:\n      registry_actor_kind: human\n",
    );
    assert_ne!(text, STANDALONE_DEV_CLIENTS);
    let clients = config::clients(text.as_bytes()).unwrap();
    let refusal = format!("{:#}", config::bind(&clients, &policy).unwrap_err());
    assert!(refusal.contains("registry_actor_kind"), "{refusal}");
    assert!(refusal.contains("not a person"), "{refusal}");
}

#[test]
fn binding_accepts_a_client_with_every_required_profile_scope() {
    let root = tempfile::tempdir().unwrap();
    let project = standalone(root.path());
    fs::write(
        project.join("casework.yaml"),
        STANDALONE_YAML.replace(
            "requiredScopes: [casework:staff]",
            "requiredScopes: [casework:staff, casework:read]",
        ),
    )
    .unwrap();
    let policy = crate::project::load_and_check_policy(&project).unwrap();
    let text = STANDALONE_DEV_CLIENTS.replace(
        "scopes: [casework:staff]",
        "scopes: [casework:staff, casework:read]",
    );
    let clients = config::clients(text.as_bytes()).unwrap();

    config::bind(&clients, &policy).unwrap();
}

#[test]
fn binding_refuses_a_client_missing_one_required_profile_scope() {
    let root = tempfile::tempdir().unwrap();
    let project = standalone(root.path());
    fs::write(
        project.join("casework.yaml"),
        STANDALONE_YAML.replace(
            "requiredScopes: [casework:staff]",
            "requiredScopes: [casework:staff, casework:read]",
        ),
    )
    .unwrap();
    let policy = crate::project::load_and_check_policy(&project).unwrap();
    let clients = config::clients(STANDALONE_DEV_CLIENTS.as_bytes()).unwrap();

    let refusal = format!("{:#}", config::bind(&clients, &policy).unwrap_err());
    assert!(refusal.contains("staff"), "{refusal}");
    assert!(
        refusal.contains("all of that profile's required scopes"),
        "{refusal}"
    );
}

#[test]
fn binding_accepts_directory_members_with_matching_roles() {
    let root = tempfile::tempdir().unwrap();
    let project = standalone(root.path());
    let policy = crate::project::load_and_check_policy(&project).unwrap();
    let clients = config::clients(STANDALONE_DEV_CLIENTS.as_bytes()).unwrap();

    let bound = config::bind(&clients, &policy).unwrap();
    let roles: BTreeMap<&str, CaseworkRole> = bound
        .iter()
        .map(|entry| (entry.client.id.as_str(), entry.role))
        .collect();
    assert_eq!(
        roles[clients.directory[0].staff[0].as_str()],
        CaseworkRole::Staff
    );
    assert_eq!(
        roles[clients.directory[0].supervisors[0].as_str()],
        CaseworkRole::Supervisor
    );
}

#[test]
fn binding_refuses_repeated_resolved_principals_within_each_membership_kind() {
    let root = tempfile::tempdir().unwrap();
    let project = standalone(root.path());

    for (role, existing_id, second_id, membership_kind) in [
        (CaseworkRole::Staff, "staff", "second-staff", "staff"),
        (
            CaseworkRole::Supervisor,
            "supervisor",
            "second-supervisor",
            "supervisor",
        ),
    ] {
        let mut policy = crate::project::load_and_check_policy(&project).unwrap();
        let profile = policy
            .access_profiles
            .iter_mut()
            .find(|profile| profile.role == role)
            .unwrap();
        profile.principal_claim = "registry_principal".to_owned();
        let mut second_profile = profile.clone();
        second_profile.id = second_id.to_owned();
        policy.access_profiles.push(second_profile);

        let mut clients = config::clients(STANDALONE_DEV_CLIENTS.as_bytes()).unwrap();
        let client = clients
            .clients
            .iter_mut()
            .find(|client| client.id == existing_id)
            .unwrap();
        client
            .claims
            .insert("registry_principal".to_owned(), "shared-person".to_owned());
        let mut second_client = client.clone();
        second_client.id = second_id.to_owned();
        second_client.access_profile = second_id.to_owned();
        clients.clients.push(second_client);
        match role {
            CaseworkRole::Staff => clients.directory[0].staff.push(second_id.to_owned()),
            CaseworkRole::Supervisor => clients.directory[0].supervisors.push(second_id.to_owned()),
            _ => unreachable!(),
        }

        let refusal = format!("{:#}", config::bind(&clients, &policy).unwrap_err());
        assert!(refusal.contains("decisions-team"), "{refusal}");
        assert!(refusal.contains(membership_kind), "{refusal}");
        assert!(refusal.contains(second_id), "{refusal}");
        assert!(refusal.contains("unique principals"), "{refusal}");
    }
}

#[test]
fn binding_accepts_one_resolved_principal_in_each_membership_kind() {
    let root = tempfile::tempdir().unwrap();
    let project = standalone(root.path());
    let mut policy = crate::project::load_and_check_policy(&project).unwrap();
    for profile in &mut policy.access_profiles {
        if matches!(profile.role, CaseworkRole::Staff | CaseworkRole::Supervisor) {
            profile.principal_claim = "registry_principal".to_owned();
        }
    }
    let mut clients = config::clients(STANDALONE_DEV_CLIENTS.as_bytes()).unwrap();
    for client in &mut clients.clients {
        if client.id == "staff" || client.id == "supervisor" {
            client
                .claims
                .insert("registry_principal".to_owned(), "shared-person".to_owned());
        }
    }

    config::bind(&clients, &policy).unwrap();
}

#[test]
fn binding_refuses_directory_members_with_mismatched_roles() {
    let root = tempfile::tempdir().unwrap();
    let project = standalone(root.path());
    let policy = crate::project::load_and_check_policy(&project).unwrap();

    for (from, to, expected) in [
        ("staff: [staff]", "staff: [supervisor]", "Staff profile"),
        (
            "supervisors: [supervisor]",
            "supervisors: [staff]",
            "Supervisor profile",
        ),
        ("staff: [staff]", "staff: [requester]", "Requester client"),
    ] {
        let text = STANDALONE_DEV_CLIENTS.replace(from, to);
        assert_ne!(text, STANDALONE_DEV_CLIENTS);
        let clients = config::clients(text.as_bytes()).unwrap();
        let refusal = format!("{:#}", config::bind(&clients, &policy).unwrap_err());
        assert!(refusal.contains(expected), "{refusal}");
    }
}

#[test]
fn binding_refuses_an_unserved_queue_and_a_missing_administrator() {
    let root = tempfile::tempdir().unwrap();
    let project = standalone(root.path());
    let policy = crate::project::load_and_check_policy(&project).unwrap();

    let unserved = STANDALONE_DEV_CLIENTS
        .split("directory:")
        .next()
        .unwrap()
        .to_owned();
    let clients = config::clients(unserved.as_bytes()).unwrap();
    let refusal = format!("{:#}", config::bind(&clients, &policy).unwrap_err());
    assert!(refusal.contains("decisions"), "{refusal}");

    let without_administrator = b"version: 1\nclients:\n  - id: staff\n    accessProfile: staff\n    scopes: [casework:staff]\n    claims:\n      registry_actor_kind: human\ndirectory:\n  - team: decisions-team\n    queue: decisions\n    staff: [staff]\n";
    let clients = config::clients(without_administrator).unwrap();
    let refusal = format!("{:#}", config::bind(&clients, &policy).unwrap_err());
    assert!(refusal.contains("Administrator"), "{refusal}");

    let unknown_queue = b"version: 1\nclients:\n  - id: administrator\n    accessProfile: administrator\n    scopes: [casework:admin]\n    claims:\n      registry_actor_kind: human\ndirectory:\n  - team: other-team\n    queue: corrections\n    staff: [administrator]\n";
    let clients = config::clients(unknown_queue).unwrap();
    let refusal = format!("{:#}", config::bind(&clients, &policy).unwrap_err());
    assert!(refusal.contains("corrections"), "{refusal}");
}

#[test]
fn generated_secrets_are_nul_free_lowercase_hexadecimal() {
    // registry-platform-config refuses a secret file holding any NUL byte, so
    // every generated secret is text (GitHub issue #976).
    for _ in 0..8 {
        let secret = config::hex_secret().unwrap();
        assert_eq!(secret.len(), 64);
        assert!(!secret.contains('\0'));
        assert!(secret
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    }
}

#[test]
fn generated_operator_config_loads_through_the_runtime_contract() {
    let root = tempfile::tempdir().unwrap();
    let project = standalone(root.path());
    let state = session(&project);
    let session_root = state.root();
    fs::create_dir_all(&session_root).unwrap();
    fs::set_permissions(project.join(".casework"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&session_root, fs::Permissions::from_mode(0o700)).unwrap();
    let path = session_root.join("operator.yaml");
    config::write_yaml(&path, &config::operator(&state)).unwrap();

    let config = RuntimeConfig::load(&path).unwrap();
    assert_eq!(config.listen, "127.0.0.1:8092".parse().unwrap());
    // Mint emits one space-delimited `scope` claim, not the deployment default.
    assert_eq!(config.authentication.oidc.scope_claim, "scope");
    assert!(matches!(
        config.authentication.oidc.jwks_source,
        registry_casework::OidcJwksSource::Static { ref document_ref }
            if document_ref == "secret:file/mint-jwks"
    ));
    assert_eq!(
        config.tls_termination,
        registry_casework::TlsTermination::DevelopmentLoopback
    );
    assert_eq!(config.audit.secret_ref, "secret:file/casework-audit-key");
    assert_eq!(
        config.database.trusted_root_certificate_ref.as_deref(),
        Some("secret:file/database-root.pem")
    );
    // The authored project the reader edits is what the session serves.
    assert_eq!(config.project, project.join("casework.yaml"));
    assert_eq!(config.authentication.oidc.issuer, state.mint_origin());
    assert_eq!(config.authentication.oidc.audience, state.audience());
}

#[test]
fn a_project_declaring_sources_is_refused_before_anything_starts() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    crate::project::init(&project, "professional-review").unwrap();
    let clients = fs::read(project.join("dev-clients.yaml")).unwrap();
    let refusal = format!("{:#}", capture(&project, &clients).unwrap_err());
    assert!(refusal.contains("source"), "{refusal}");
}

#[test]
fn the_source_digest_pins_the_project_and_its_clients() {
    let root = tempfile::tempdir().unwrap();
    let project = standalone(root.path());
    let clients = fs::read(project.join("dev-clients.yaml")).unwrap();
    let first = capture(&project, &clients).unwrap().digest;
    assert_eq!(first, capture(&project, &clients).unwrap().digest);

    let edited = format!("{STANDALONE_DEV_CLIENTS}\n");
    assert_ne!(first, capture(&project, edited.as_bytes()).unwrap().digest);

    fs::write(
        project.join("casework.yaml"),
        STANDALONE_YAML.replace("Decisions awaiting review", "Decisions"),
    )
    .unwrap();
    assert_ne!(first, capture(&project, &clients).unwrap().digest);
}

#[test]
fn redaction_hides_every_run_of_a_secret() {
    let secret = b"pa55word-long-enough";
    let hidden = redact(
        b"psql: password authentication failed for pa55word-long-enough",
        secret,
    );
    let hidden = String::from_utf8(hidden).unwrap();
    assert!(!hidden.contains("pa55word"), "{hidden}");
    assert!(hidden.contains("[redacted]"), "{hidden}");
    assert!(hidden.starts_with("psql: "), "{hidden}");
}

#[test]
fn version_comparison_refuses_a_mismatched_runtime() {
    let own = registry_platform_buildinfo::DISPLAY_VERSION;
    let binaries = |version: &str| {
        BTreeMap::from([(
            "casework".to_owned(),
            Binary {
                path: PathBuf::from("/usr/local/bin/casework"),
                version: version.to_owned(),
            },
        )])
    };
    matching_versions(&binaries(&format!("casework {own}"))).unwrap();
    // Nothing to compare is not a mismatch.
    matching_versions(&binaries(UNREPORTED_VERSION)).unwrap();
    matching_versions(&binaries("casework")).unwrap();
    let refusal = format!(
        "{:#}",
        matching_versions(&binaries("casework 0.0.1-other")).unwrap_err()
    );
    assert!(refusal.contains("0.0.1-other"), "{refusal}");
    assert!(refusal.contains(own), "{refusal}");
    // Docker belongs to no release of this stack.
    matching_versions(&BTreeMap::from([(
        "docker".to_owned(),
        Binary {
            path: PathBuf::from("/usr/local/bin/docker"),
            version: "Docker version 28.0.0, build abcdef".to_owned(),
        },
    )]))
    .unwrap();
}

#[test]
fn ports_must_be_three_distinct_loopback_ports() {
    ports(8092, 8093, 55433).unwrap();
    assert!(ports(8092, 8092, 55433).is_err());
    assert!(ports(0, 8093, 55433).is_err());
}

#[test]
fn start_ports_fall_back_to_named_environment_variables() {
    let casework_var = "CASEWORKCTL_DEV_CASEWORK_PORT";
    let mint_var = "CASEWORKCTL_DEV_MINT_PORT";
    let database_var = "CASEWORKCTL_DEV_DATABASE_PORT";
    std::env::set_var(casework_var, "19092");
    std::env::set_var(mint_var, "19093");
    std::env::set_var(database_var, "19099");

    let parsed =
        crate::Cli::try_parse_from(["caseworkctl", "dev", "start", "/tmp/casework-project"])
            .unwrap();
    std::env::remove_var(casework_var);
    std::env::remove_var(mint_var);
    std::env::remove_var(database_var);

    let crate::Command::Dev(DevArgs {
        action: Some(DevAction::Start(start)),
        ..
    }) = parsed.command
    else {
        panic!("expected dev start");
    };
    assert_eq!(start.casework_port, Some(19092));
    assert_eq!(start.mint_port, Some(19093));
    assert_eq!(start.database_port, Some(19099));
}

#[test]
fn start_ports_prefer_an_explicit_flag_over_the_environment() {
    let casework_var = "CASEWORKCTL_DEV_CASEWORK_PORT";
    std::env::set_var(casework_var, "19092");

    let parsed = crate::Cli::try_parse_from([
        "caseworkctl",
        "dev",
        "start",
        "/tmp/casework-project",
        "--casework-port",
        "9100",
    ])
    .unwrap();
    std::env::remove_var(casework_var);

    let crate::Command::Dev(DevArgs {
        action: Some(DevAction::Start(start)),
        ..
    }) = parsed.command
    else {
        panic!("expected dev start");
    };
    assert_eq!(start.casework_port, Some(9100));
}

#[test]
fn bare_dev_alias_ports_also_fall_back_to_the_environment() {
    let database_var = "CASEWORKCTL_DEV_DATABASE_PORT";
    std::env::set_var(database_var, "19099");

    let parsed =
        crate::Cli::try_parse_from(["caseworkctl", "dev", "/tmp/casework-project"]).unwrap();
    std::env::remove_var(database_var);

    let crate::Command::Dev(DevArgs { start, .. }) = parsed.command else {
        panic!("expected dev");
    };
    assert_eq!(start.database_port, Some(19099));
}

#[test]
fn events_reports_only_the_bounded_journal_tail() {
    let root = tempfile::tempdir().unwrap();
    let project = standalone(root.path());
    let logs = project.join(".casework/dev/logs");
    fs::create_dir_all(&logs).unwrap();
    for directory in [
        project.join(".casework"),
        project.join(".casework/dev"),
        logs.clone(),
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let journal = logs.join("casework.log");
    let mut written = String::new();
    for index in 0..700 {
        written.push_str(&format!("event-{index:04}-{}\n", "x".repeat(500)));
    }
    fs::write(&journal, written).unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();

    let result = events(&project).unwrap();
    let reported = result["events"].as_array().unwrap();
    let expected_last = format!("event-0699-{}", "x".repeat(500));
    assert!(result["truncated"].as_bool().unwrap());
    assert!(reported.len() <= 512);
    assert_eq!(
        reported.last().and_then(Value::as_str),
        Some(expected_last.as_str())
    );
    assert!(
        reported
            .iter()
            .filter_map(Value::as_str)
            .map(str::len)
            .sum::<usize>()
            <= 256 * 1024
    );

    let short = (0..600)
        .map(|index| format!("short-{index:04}"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&journal, short).unwrap();
    let limited = events(&project).unwrap();
    let reported = limited["events"].as_array().unwrap();
    assert_eq!(reported.len(), 512);
    assert!(limited["truncated"].as_bool().unwrap());
    assert_eq!(reported.first().and_then(Value::as_str), Some("short-0088"));
    assert_eq!(reported.last().and_then(Value::as_str), Some("short-0599"));
}

#[test]
fn stopping_a_project_that_never_started_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let project = standalone(root.path());
    let refusal = format!("{:#}", stop(&project, false, None).unwrap_err());
    assert!(refusal.contains("nothing was stopped"), "{refusal}");
    let refusal = format!("{:#}", events(&project).unwrap_err());
    assert!(refusal.contains("nothing was stopped"), "{refusal}");
}

#[test]
fn a_first_start_without_a_clients_file_names_the_flag() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    fs::create_dir(&project).unwrap();
    let refusal = format!("{:#}", clients_file(None, None, &project).unwrap_err());
    assert!(refusal.contains("--clients-file"), "{refusal}");
    assert!(refusal.contains("dev-clients.yaml"), "{refusal}");
}

#[test]
fn a_stopped_session_retains_an_explicit_equivalent_clients_file() {
    let root = tempfile::tempdir().unwrap();
    let project = fs::canonicalize(standalone(root.path())).unwrap();
    let original_clients = fs::read(project.join("dev-clients.yaml")).unwrap();
    let replacement = project.join("replacement-clients.yaml");
    fs::write(&replacement, &original_clients).unwrap();
    let captured = capture(&project, &original_clients).unwrap();
    let mut state = session(&project);
    state.source_digest = captured.digest.clone();
    state.clients = captured.reported;
    state.container_id = Some("a".repeat(64));
    state.database_ready = true;
    state.migrated = true;
    state.seeded.insert("decisions-team".to_owned());
    state.directory_revision = 7;
    state.directory_teams = 1;
    parent_directory(&project).unwrap();
    initialize(&state.root(), &state, &captured.clients).unwrap();

    // Stop after retained-state selection, before prerequisite or service work.
    assert!(start(StartArgs {
        project: project.clone(),
        clients_file: Some(replacement.clone()),
        casework_port: None,
        mint_port: None,
        database_port: None,
        casework_bin: Some(project.join("missing-casework")),
        mint_bin: None,
        docker_bin: None,
    })
    .is_err());

    let retained = read_state(&state.root()).unwrap();
    assert_eq!(
        retained.clients_file,
        fs::canonicalize(replacement).unwrap()
    );
    assert_eq!(
        clients_file(None, Some(&retained), &project).unwrap(),
        retained.clients_file
    );
    assert_eq!(retained.source_digest, captured.digest);
    assert_eq!(retained.owner, state.owner);
    assert_eq!(retained.container_id, state.container_id);
    assert!(retained.database_ready);
    assert!(retained.migrated);
    assert_eq!(retained.seeded, state.seeded);
    assert_eq!(retained.directory_revision, 7);
    assert_eq!(retained.directory_teams, 1);
}

#[test]
fn the_report_names_every_local_credential_without_a_secret() {
    let root = tempfile::tempdir().unwrap();
    let project = standalone(root.path());
    let mut state = session(&project);
    state.status = Status::Ready;
    state.clients = vec![ReportedClient {
        id: "requester".to_owned(),
        profile: "requester".to_owned(),
        role: CaseworkRole::Requester,
        principal: config::principal("requester"),
    }];
    state.directory_revision = 1;
    state.directory_teams = 1;
    let report = state.report();
    assert_eq!(report["caseworkUrl"], "http://127.0.0.1:8092");
    assert_eq!(report["tokenEndpoint"], "http://127.0.0.1:8093/token");
    assert_eq!(report["audience"], state.audience());
    assert_eq!(report["directory"]["teams"], 1);
    assert_eq!(report["directory"]["revision"], 1);
    assert_eq!(report["clients"][0]["id"], "requester");
    assert_eq!(report["clients"][0]["role"], "requester");
    assert_eq!(
        report["clients"][0]["assertionKeyFile"],
        json!(state.root().join("credentials/requester/assertion-key.jwk"))
    );
    let text = report.to_string();
    assert!(!text.contains("token\":\""), "{text}");
    assert!(!text.contains("password"), "{text}");
}

#[test]
fn stop_control_waits_for_the_complete_sequential_cleanup_budget() {
    let child_shutdowns = Duration::from_secs(35 * 2);
    // A timed-out Docker prerequisite gets its own graceful child shutdown
    // before the supervisor can send the final response.
    let database_shutdown = CHILD_DEADLINE * 3;
    assert!(control_response_deadline("stop") >= child_shutdowns + database_shutdown);
    assert!(control_response_deadline("status") < control_response_deadline("stop"));
}

#[test]
fn a_completed_session_can_be_reclaimed_after_its_ports_are_reused() {
    assert!(!service_ports_must_be_free(&Status::Stopped));
    assert!(!service_ports_must_be_free(&Status::Failed));
    assert!(service_ports_must_be_free(&Status::Starting));
    assert!(service_ports_must_be_free(&Status::Ready));
    assert!(service_ports_must_be_free(&Status::Stopping));
}

struct DockerInventory {
    _root: tempfile::TempDir,
    executable: PathBuf,
    container: PathBuf,
    volume: PathBuf,
    fail_create: PathBuf,
}

impl DockerInventory {
    fn new(state: &State) -> Self {
        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("docker");
        let container = root.path().join("container-active");
        let volume = root.path().join("volume-active");
        let fail_create = root.path().join("fail-create");
        fs::write(
            &executable,
            br#"#!/bin/sh
set -eu
fixture=$(dirname "$0")
if [ "$1" = "ps" ]; then
    if [ -f "$fixture/container-active" ]; then printf 'container\n'; fi
elif [ "$1" = "inspect" ]; then
    cat "$fixture/container.json"
elif [ "$1" = "volume" ] && [ "$2" = "create" ]; then
    touch "$fixture/volume-active"
    cat "$fixture/volume-name"
elif [ "$1" = "volume" ] && [ "$2" = "ls" ]; then
    if [ -f "$fixture/volume-active" ]; then cat "$fixture/volume-name"; fi
elif [ "$1" = "volume" ] && [ "$2" = "inspect" ]; then
    cat "$fixture/volume.json"
elif [ "$1" = "create" ]; then
    if [ -f "$fixture/fail-create" ]; then
        printf 'injected container creation failure\n' >&2
        exit 42
    fi
    touch "$fixture/container-active"
    cat "$fixture/container-id"
else
    printf 'unexpected fake Docker command: %s\n' "$*" >&2
    exit 43
fi
"#,
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let id = "a".repeat(64);
        fs::write(root.path().join("container-id"), format!("{id}\n")).unwrap();
        fs::write(
            root.path().join("container.json"),
            serde_json::to_vec(&json!([{
                "Id": id,
                "Name": format!("/{}", state.container_name()),
                "Config": {
                    "Labels": { (LABEL): state.owner.clone() },
                    "Image": IMAGE,
                },
                "State": { "Running": false },
            }]))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            root.path().join("volume-name"),
            format!("{}\n", state.volume_name()),
        )
        .unwrap();
        fs::write(
            root.path().join("volume.json"),
            serde_json::to_vec(&json!([{
                "Name": state.volume_name(),
                "Labels": { (LABEL): state.owner.clone() },
            }]))
            .unwrap(),
        )
        .unwrap();
        Self {
            _root: root,
            executable,
            container,
            volume,
            fail_create,
        }
    }

    fn deactivate(&self) {
        for path in [&self.container, &self.volume] {
            if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
    }
}

fn persisted_session(project: &Path) -> State {
    let state = session(project);
    private::directory(&project.join(".casework")).unwrap();
    private::directory(&state.root()).unwrap();
    private::directory(&state.root().join("logs")).unwrap();
    state.save().unwrap();
    state
}

#[test]
fn config_change_keeps_the_owner_after_container_creation_fails() {
    let workspace = tempfile::tempdir().unwrap();
    let project = standalone(workspace.path());
    let mut state = persisted_session(&project);
    let docker = DockerInventory::new(&state);
    fs::write(&docker.fail_create, b"").unwrap();

    let refusal = format!(
        "{:#}",
        database(&docker.executable, &mut state, &AtomicBool::new(false)).unwrap_err()
    );
    assert!(refusal.contains("create-database failed"), "{refusal}");
    let retained = read_state(&state.root()).unwrap();
    assert_eq!(retained.owner, state.owner);
    assert!(retained.container_id.is_none());
    assert!(docker.volume.exists());
    assert!(!docker.container.exists());

    let refusal = format!(
        "{:#}",
        discard_changed_state(&state.root(), &retained, Some(&docker.executable)).unwrap_err()
    );
    assert!(
        refusal.contains("still owns database resources"),
        "{refusal}"
    );
    assert_eq!(read_state(&state.root()).unwrap().owner, retained.owner);

    docker.deactivate();
    discard_changed_state(&state.root(), &retained, Some(&docker.executable)).unwrap();
    assert!(!state.root().exists());
}

#[test]
fn config_change_keeps_the_owner_after_created_container_cannot_be_saved() {
    let workspace = tempfile::tempdir().unwrap();
    let project = standalone(workspace.path());
    let mut state = persisted_session(&project);
    let docker = DockerInventory::new(&state);
    fs::set_permissions(state.root(), fs::Permissions::from_mode(0o500)).unwrap();

    let result = database(&docker.executable, &mut state, &AtomicBool::new(false));
    fs::set_permissions(state.root(), fs::Permissions::from_mode(0o700)).unwrap();
    let refusal = format!("{:#}", result.unwrap_err());
    assert!(refusal.contains("cannot be created"), "{refusal}");
    let retained = read_state(&state.root()).unwrap();
    assert_eq!(retained.owner, state.owner);
    assert!(retained.container_id.is_none());
    assert!(docker.volume.exists());
    assert!(docker.container.exists());

    let refusal = format!(
        "{:#}",
        discard_changed_state(&state.root(), &retained, Some(&docker.executable)).unwrap_err()
    );
    assert!(
        refusal.contains("still owns database resources"),
        "{refusal}"
    );
    assert_eq!(read_state(&state.root()).unwrap().owner, retained.owner);

    docker.deactivate();
    discard_changed_state(&state.root(), &retained, Some(&docker.executable)).unwrap();
    assert!(!state.root().exists());
}

#[test]
fn volume_removal_requires_the_retained_owner_label() {
    let root = tempfile::tempdir().unwrap();
    let project = standalone(root.path());
    let state = session(&project);
    let mut wrong_labels = serde_json::Map::new();
    wrong_labels.insert(LABEL.to_owned(), Value::String("another-owner".to_owned()));
    let unrelated = json!({
        "Name": state.volume_name(),
        "Labels": Value::Object(wrong_labels),
    });
    let mut removed = false;

    let refusal = format!(
        "{:#}",
        remove_verified_volume(&state, Some(unrelated), None, |_| {
            removed = true;
            Ok(())
        })
        .unwrap_err()
    );

    assert!(refusal.contains("volume ownership differs"), "{refusal}");
    assert!(!removed);

    let mut owned_labels = serde_json::Map::new();
    owned_labels.insert(LABEL.to_owned(), Value::String(state.owner.clone()));
    let owned = json!({
        "Name": state.volume_name(),
        "Labels": Value::Object(owned_labels),
    });
    remove_verified_volume(&state, Some(owned), None, |name| {
        assert_eq!(name, state.volume_name());
        removed = true;
        Ok(())
    })
    .unwrap();
    assert!(removed);
}

fn legacy_database_container(state: &State, volume_name: &str, destination: &str) -> Value {
    let mut labels = serde_json::Map::new();
    labels.insert(LABEL.to_owned(), Value::String(state.owner.clone()));
    json!({
        "Id": state.container_id.as_ref().unwrap(),
        "Name": format!("/{}", state.container_name()),
        "Config": {
            "Labels": Value::Object(labels),
            "Image": IMAGE,
        },
        "Mounts": [{
            "Type": "volume",
            "Name": volume_name,
            "Destination": destination,
        }],
    })
}

#[test]
fn legacy_unlabeled_volume_requires_the_exact_retained_container_and_mount() {
    let root = tempfile::tempdir().unwrap();
    let project = standalone(root.path());
    let mut state = session(&project);
    state.container_id = Some("retained-container-id".to_owned());
    let volume = json!({
        "Name": state.volume_name(),
        "Labels": null,
    });
    let container =
        legacy_database_container(&state, &state.volume_name(), "/var/lib/postgresql/data");
    let mut removed = false;

    remove_verified_volume(&state, Some(volume.clone()), Some(&container), |name| {
        assert_eq!(name, state.volume_name());
        removed = true;
        Ok(())
    })
    .unwrap();
    assert!(removed);

    for (container, expected) in [
        (None, "retained container is absent"),
        (
            Some(legacy_database_container(
                &state,
                "different-volume",
                "/var/lib/postgresql/data",
            )),
            "is not mounted",
        ),
        (
            Some(legacy_database_container(
                &state,
                &state.volume_name(),
                "/different-destination",
            )),
            "is not mounted",
        ),
    ] {
        removed = false;
        let refusal = format!(
            "{:#}",
            remove_verified_volume(&state, Some(volume.clone()), container.as_ref(), |_| {
                removed = true;
                Ok(())
            })
            .unwrap_err()
        );
        assert!(refusal.contains(expected), "{refusal}");
        assert!(!removed);
    }

    let mut wrong_container = container.clone();
    wrong_container["Id"] = Value::String("different-container-id".to_owned());
    removed = false;
    let refusal = format!(
        "{:#}",
        remove_verified_volume(&state, Some(volume), Some(&wrong_container), |_| {
            removed = true;
            Ok(())
        })
        .unwrap_err()
    );
    assert!(refusal.contains("container ownership differs"), "{refusal}");
    assert!(!removed);
}

#[test]
fn foreground_interruption_terminates_and_reaps_its_owned_supervisor() {
    let workspace = tempfile::tempdir().unwrap();
    let project = standalone(workspace.path());
    let mut state = session(&project);
    state.status = Status::Starting;
    fs::create_dir_all(state.root()).unwrap();
    fs::set_permissions(project.join(".casework"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(state.root(), fs::Permissions::from_mode(0o700)).unwrap();
    state.save().unwrap();
    let mut supervisor = Command::new("/bin/sh")
        .args(["-c", "while :; do :; done"])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let interrupted = AtomicBool::new(true);

    let refusal = format!(
        "{:#}",
        wait_for_start(&state.root(), &mut supervisor, &interrupted).unwrap_err()
    );

    assert!(refusal.contains("local start interrupted"), "{refusal}");
    assert!(supervisor.try_wait().unwrap().is_some());
    let retained = read_state(&state.root()).unwrap();
    assert!(matches!(retained.status, Status::Failed));
    assert!(retained
        .failure
        .is_some_and(|failure| failure.contains("interrupted")));
}

#[test]
fn failed_start_waits_for_the_supervisor_lock_to_be_released() {
    let workspace = tempfile::tempdir().unwrap();
    let project = standalone(workspace.path());
    let mut state = session(&project);
    state.status = Status::Failed;
    state.failure = Some("injected supervisor failure".to_owned());
    fs::create_dir_all(state.root()).unwrap();
    fs::set_permissions(project.join(".casework"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(state.root(), fs::Permissions::from_mode(0o700)).unwrap();
    state.save().unwrap();
    let lock = private::lock(&state.root().join("supervisor.lock")).unwrap();
    let release = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        drop(lock);
    });
    let mut supervisor = Command::new("/bin/sleep").arg("0.2").spawn().unwrap();
    let interrupted = AtomicBool::new(false);
    let started = Instant::now();

    let refusal = format!(
        "{:#}",
        wait_for_start(&state.root(), &mut supervisor, &interrupted).unwrap_err()
    );
    let elapsed = started.elapsed();
    release.join().unwrap();

    assert!(refusal.contains("injected supervisor failure"), "{refusal}");
    assert!(supervisor.try_wait().unwrap().is_some());
    assert!(
        elapsed >= Duration::from_millis(150),
        "elapsed: {elapsed:?}"
    );
    assert!(elapsed < Duration::from_secs(1), "elapsed: {elapsed:?}");
}

#[test]
fn migration_failures_use_the_bounded_native_diagnostic_stream() {
    let root = tempfile::tempdir().unwrap();
    private::directory(&root.path().join("logs")).unwrap();
    let refusal = format!(
        "{:#}",
        command(
            Command::new("/bin/sh").args([
                "-c",
                "printf 'casework: schema upgrade refused safely\\n' >&2; exit 1",
            ]),
            root.path(),
            "migrate",
            None,
        )
        .unwrap_err()
    );
    assert!(
        refusal.contains("schema upgrade refused safely"),
        "{refusal}"
    );
    assert!(refusal.contains("owner-only diagnostics"), "{refusal}");
}

#[test]
fn database_readiness_commands_stop_at_the_aggregate_deadline() {
    let root = tempfile::tempdir().unwrap();
    private::directory(&root.path().join("logs")).unwrap();
    let started = Instant::now();
    let deadline = started + Duration::from_millis(75);
    let terminate = AtomicBool::new(false);

    let refusal = format!(
        "{:#}",
        command_before_cancellable(
            Command::new("/bin/sh").args(["-c", "while :; do :; done"]),
            root.path(),
            "database-readiness",
            None,
            deadline,
            &terminate,
        )
        .unwrap_err()
    );

    assert!(refusal.contains("timed out"), "{refusal}");
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn interrupted_native_prerequisite_is_killed_and_reaped() {
    let root = tempfile::tempdir().unwrap();
    private::directory(&root.path().join("logs")).unwrap();
    let marker = root.path().join("prerequisite.pid");
    let terminate = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&terminate);
    let marker_for_signal = marker.clone();
    let interrupter = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(1);
        while !marker_for_signal.exists() {
            assert!(Instant::now() < deadline, "prerequisite did not start");
            thread::sleep(Duration::from_millis(5));
        }
        signal.store(true, Ordering::Relaxed);
    });
    let started = Instant::now();

    let refusal = format!(
        "{:#}",
        command_cancellable(
            Command::new("/bin/sh")
                .arg("-c")
                .arg("printf '%s' \"$$\" > \"$1\"; while :; do :; done")
                .arg("prerequisite")
                .arg(&marker),
            root.path(),
            "interruptible-prerequisite",
            None,
            &terminate,
        )
        .unwrap_err()
    );
    interrupter.join().unwrap();
    let pid = fs::read_to_string(&marker).unwrap().parse::<i32>().unwrap();
    let pid = rustix::process::Pid::from_raw(pid).unwrap();

    assert!(refusal.contains("interrupted"), "{refusal}");
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(rustix::process::test_kill_process(pid).is_err());
}

#[test]
fn native_pump_setup_failures_reap_the_child_and_join_started_pumps() {
    let root = tempfile::tempdir().unwrap();
    private::directory(&root.path().join("logs")).unwrap();
    for fail_on in [1, 2] {
        let child = Command::new("/bin/sleep")
            .arg("5")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
        let log = log_file(root.path(), "pump-setup").unwrap();
        let joined = Arc::new(AtomicBool::new(false));
        let mut calls = 0;
        let started = Instant::now();

        let refusal = format!(
            "{:#}",
            output_from_child_with_pump_spawner(
                child,
                NativeRun {
                    root: root.path(),
                    name: "pump-setup",
                    log,
                    input: None,
                    aggregate_deadline: None,
                    terminate: None,
                },
                |_stream, task| {
                    calls += 1;
                    if calls == fail_on {
                        return Err(std::io::Error::other("injected pump spawn failure"));
                    }
                    let joined = Arc::clone(&joined);
                    thread::Builder::new().spawn(move || {
                        let result = task();
                        joined.store(true, Ordering::Relaxed);
                        result
                    })
                },
            )
            .err()
            .expect("selected pump spawn must fail")
        );

        let reader = if fail_on == 1 { "output" } else { "diagnostic" };
        assert!(refusal.contains(reader), "{refusal}");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(joined.load(Ordering::Relaxed), fail_on == 2);
        assert!(rustix::process::test_kill_process(pid).is_err());
    }
}

#[test]
fn failed_native_stdin_write_reaps_the_child_and_joins_pumps() {
    let root = tempfile::tempdir().unwrap();
    private::directory(&root.path().join("logs")).unwrap();
    let child = Command::new("/bin/sh")
        .args(["-c", "exec 0<&-; while :; do :; done"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
    let log = log_file(root.path(), "closed-stdin").unwrap();
    let input = vec![b'x'; MAX_BYTES as usize];
    let stdout_joined = Arc::new(AtomicBool::new(false));
    let stderr_joined = Arc::new(AtomicBool::new(false));
    let started = Instant::now();

    let refusal = format!(
        "{:#}",
        output_from_child_with_pump_spawner(
            child,
            NativeRun {
                root: root.path(),
                name: "closed-stdin",
                log,
                input: Some(Input {
                    bytes: &input,
                    secret: None,
                }),
                aggregate_deadline: None,
                terminate: None,
            },
            |stream, task| {
                let joined = if stream == "stdout" {
                    Arc::clone(&stdout_joined)
                } else {
                    Arc::clone(&stderr_joined)
                };
                thread::Builder::new().spawn(move || {
                    let result = task();
                    joined.store(true, Ordering::Relaxed);
                    result
                })
            },
        )
        .err()
        .expect("closed stdin must refuse the input")
    );

    assert!(
        refusal.contains("write native prerequisite input"),
        "{refusal}"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(stdout_joined.load(Ordering::Relaxed));
    assert!(stderr_joined.load(Ordering::Relaxed));
    assert!(rustix::process::test_kill_process(pid).is_err());
}

#[test]
fn active_http_prerequisite_stops_promptly_when_interrupted() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let terminate = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&terminate);
    let release_server = Arc::clone(&release);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut request = [0u8; 1];
        assert_eq!(stream.read(&mut request).unwrap(), 1);
        signal.store(true, Ordering::Relaxed);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !release_server.load(Ordering::Relaxed) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
    });
    let started = Instant::now();

    let result = http_cancellable(
        "GET",
        &format!("http://{address}/never-respond"),
        None,
        &[],
        None,
        &terminate,
    );
    let elapsed = started.elapsed();
    release.store(true, Ordering::Relaxed);
    server.join().unwrap();
    let refusal = format!("{:#}", result.unwrap_err());

    assert!(refusal.contains("interrupted"), "{refusal}");
    assert!(elapsed < Duration::from_secs(1), "elapsed: {elapsed:?}");
}

#[test]
fn service_http_readiness_stops_at_the_phase_deadline() {
    let child = Command::new("/bin/sleep")
        .arg("5")
        .process_group(0)
        .spawn()
        .unwrap();
    let mut service = Service::from_guard(child, Vec::new()).unwrap();
    let terminate = AtomicBool::new(false);
    let started = Instant::now();
    let deadline = started + Duration::from_millis(75);
    let mut request_timeouts = Vec::new();

    let refusal = format!(
        "{:#}",
        ready_with_probe(&service, &terminate, deadline, |timeout| {
            request_timeouts.push(timeout);
            // Model an HTTP request that consumes its entire allowance. The
            // readiness phase must pass only its remaining budget each time.
            thread::sleep(timeout);
            false
        })
        .unwrap_err()
    );
    let elapsed = started.elapsed();
    let _ = service.stop_with_grace(Duration::from_millis(50), Duration::from_millis(10));

    assert!(refusal.contains("readiness timed out"), "{refusal}");
    assert!(elapsed < Duration::from_secs(1), "elapsed: {elapsed:?}");
    assert!(!request_timeouts.is_empty());
    assert!(request_timeouts[0] <= deadline.duration_since(started));
}

#[test]
fn service_http_readiness_keeps_the_normal_request_timeout() {
    assert_eq!(
        readiness_http_timeout(HTTP_TIMEOUT + Duration::from_secs(5)),
        HTTP_TIMEOUT
    );
    assert_eq!(
        readiness_http_timeout(Duration::from_millis(75)),
        Duration::from_millis(75)
    );
}

#[test]
fn prerequisite_logs_are_bounded_and_keep_the_latest_diagnostics() {
    let root = tempfile::tempdir().unwrap();
    let logs = root.path().join("logs");
    private::directory(&logs).unwrap();
    let latest = format!("diagnostic-{}", MAX_PREREQUISITE_LOGS + 7);
    for index in 0..MAX_PREREQUISITE_LOGS + 8 {
        let mut log = log_file(root.path(), "probe").unwrap();
        writeln!(log, "diagnostic-{index}").unwrap();
    }

    let retained = fs::read_dir(&logs)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(retained.len(), MAX_PREREQUISITE_LOGS);
    assert!(retained
        .iter()
        .any(|path| String::from_utf8_lossy(&fs::read(path).unwrap()).contains(&latest)));
    for path in retained {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o077, 0);
        assert_eq!(metadata.nlink(), 1);
    }

    let unsafe_root = tempfile::tempdir().unwrap();
    let unsafe_logs = unsafe_root.path().join("logs");
    private::directory(&unsafe_logs).unwrap();
    let unsafe_path = unsafe_logs.join(format!("probe-{}.log", uuid::Uuid::new_v4()));
    fs::write(&unsafe_path, b"must not rotate\n").unwrap();
    fs::set_permissions(&unsafe_path, fs::Permissions::from_mode(0o644)).unwrap();
    let refusal = format!("{:#}", log_file(unsafe_root.path(), "probe").unwrap_err());
    assert!(refusal.contains("owner-only"), "{refusal}");
    assert!(unsafe_path.exists());
}

#[test]
fn prerequisite_log_rotation_stays_in_the_opened_directory_after_a_path_swap() {
    let root = tempfile::tempdir().unwrap();
    let logs = root.path().join("logs");
    private::directory(&logs).unwrap();
    for index in 0..MAX_PREREQUISITE_LOGS {
        let mut log = log_file(root.path(), "probe").unwrap();
        writeln!(log, "diagnostic-{index}").unwrap();
    }
    let redirected = tempfile::tempdir().unwrap();
    let names = fs::read_dir(&logs)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    for name in &names {
        let path = redirected.path().join(name);
        fs::write(&path, b"unrelated\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let opened_logs = root.path().join("opened-logs");

    let mut log = log_file_with_rotation(root.path(), "probe", || {
        fs::rename(&logs, &opened_logs).unwrap();
        std::os::unix::fs::symlink(redirected.path(), &logs).unwrap();
    })
    .unwrap();
    writeln!(log, "new diagnostic").unwrap();

    assert!(names
        .iter()
        .all(|name| redirected.path().join(name).exists()));
    assert_eq!(
        fs::read_dir(&opened_logs).unwrap().count(),
        MAX_PREREQUISITE_LOGS
    );
}

#[test]
fn retained_service_journal_stays_bounded_and_keeps_latest_diagnostics() {
    let root = tempfile::tempdir().unwrap();
    let logs = root.path().join("logs");
    private::directory(&logs).unwrap();
    let path = logs.join("casework.log");
    let old_marker = b"latest-before-restart\n";
    let mut oversized = vec![b'o'; MAX_BYTES as usize + 1024];
    oversized.extend_from_slice(old_marker);
    private::create(&path, &oversized).unwrap();

    let journal = RetainedJournal::open(&path).unwrap();
    drop(journal);
    let compacted = fs::read(&path).unwrap();
    assert!(compacted.len() <= MAX_BYTES as usize);
    assert!(compacted.ends_with(old_marker));

    let new_marker = b"latest-during-service\n";
    let mut service_output = vec![b'n'; MAX_BYTES as usize + 1024];
    service_output.extend_from_slice(new_marker);
    pump_retained(
        std::io::Cursor::new(service_output),
        RetainedJournal::open(&path).unwrap(),
    )
    .unwrap();
    let after_service = fs::read(&path).unwrap();
    assert!(after_service.len() <= MAX_BYTES as usize);
    assert!(after_service.ends_with(new_marker));

    let restart_marker = b"latest-after-restart\n";
    pump_retained(
        std::io::Cursor::new(restart_marker),
        RetainedJournal::open(&path).unwrap(),
    )
    .unwrap();
    let after_restart = fs::read(&path).unwrap();
    assert!(after_restart.len() <= MAX_BYTES as usize);
    assert!(after_restart.ends_with(restart_marker));
    assert!(after_restart
        .windows(new_marker.len())
        .any(|window| window == new_marker));
    let metadata = fs::symlink_metadata(&path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o077, 0);
    assert_eq!(metadata.nlink(), 1);
}

#[test]
fn supervisor_log_stays_bounded_and_resists_path_swaps_and_links() {
    let root = tempfile::tempdir().unwrap();
    let logs = root.path().join("logs");
    private::directory(&logs).unwrap();
    let path = logs.join("supervisor.log");
    let old_marker = b"latest-previous-supervisor-failure\n";
    let mut oversized = vec![b'o'; MAX_BYTES as usize + 1024];
    oversized.extend_from_slice(old_marker);
    private::create(&path, &oversized).unwrap();
    let new_error = anyhow::anyhow!(
        "latest-current-supervisor-failure:{}",
        "\u{1f980}".repeat(MAX_REFUSAL)
    );
    let bounded = bounded_supervisor_error(&new_error);

    let mut log = supervisor_log(root.path()).unwrap();
    writeln!(log, "{bounded}").unwrap();
    drop(log);

    let retained = fs::read(&path).unwrap();
    assert!(retained.len() <= MAX_BYTES as usize);
    assert!(retained
        .windows(old_marker.len())
        .any(|window| window == old_marker));
    assert!(String::from_utf8_lossy(&retained).contains("latest-current-supervisor-failure"));
    assert_eq!(bounded.chars().count(), MAX_REFUSAL);
    let maximum_width =
        bounded_supervisor_error(&anyhow::anyhow!("{}", "\u{1f980}".repeat(MAX_REFUSAL + 1)));
    // `main_entry` writes this string directly with `eprintln!("{error:#}")`:
    // no prefix, and exactly one framing newline.
    assert_eq!(maximum_width.len() + 1, MAX_SUPERVISOR_ERROR_BYTES as usize);
    let metadata = fs::symlink_metadata(&path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o077, 0);
    assert_eq!(metadata.nlink(), 1);

    let swap_root = tempfile::tempdir().unwrap();
    let swap_logs = swap_root.path().join("logs");
    let moved_logs = swap_root.path().join("original-logs");
    let replacement_logs = swap_root.path().join("replacement-logs");
    private::directory(&swap_logs).unwrap();
    private::directory(&replacement_logs).unwrap();
    private::create(
        &swap_logs.join("supervisor.log"),
        b"original recent failure\n",
    )
    .unwrap();
    private::create(
        &replacement_logs.join("supervisor.log"),
        b"replacement must stay unchanged\n",
    )
    .unwrap();
    let mut log = supervisor_log_with_open(swap_root.path(), || {
        fs::rename(&swap_logs, &moved_logs).unwrap();
        fs::rename(&replacement_logs, &swap_logs).unwrap();
    })
    .unwrap();
    writeln!(log, "current failure").unwrap();
    drop(log);
    assert_eq!(
        fs::read(swap_logs.join("supervisor.log")).unwrap(),
        b"replacement must stay unchanged\n"
    );
    assert_eq!(
        fs::read(moved_logs.join("supervisor.log")).unwrap(),
        b"original recent failure\ncurrent failure\n"
    );

    let hardlink_root = tempfile::tempdir().unwrap();
    let hardlink_logs = hardlink_root.path().join("logs");
    private::directory(&hardlink_logs).unwrap();
    let target = hardlink_logs.join("target.log");
    private::create(&target, b"preserve me").unwrap();
    let linked = hardlink_logs.join("supervisor.log");
    fs::hard_link(&target, &linked).unwrap();
    let refusal = format!("{:#}", supervisor_log(hardlink_root.path()).unwrap_err());
    assert!(refusal.contains("single-link"), "{refusal}");
    assert_eq!(fs::read(&target).unwrap(), b"preserve me");

    let symlink_root = tempfile::tempdir().unwrap();
    let symlink_logs = symlink_root.path().join("logs");
    private::directory(&symlink_logs).unwrap();
    let target = symlink_logs.join("target.log");
    private::create(&target, b"preserve me too").unwrap();
    let linked = symlink_logs.join("supervisor.log");
    std::os::unix::fs::symlink(&target, &linked).unwrap();
    let refusal = format!("{:#}", supervisor_log(symlink_root.path()).unwrap_err());
    assert!(refusal.contains("supervisor journal"), "{refusal}");
    assert_eq!(fs::read(&target).unwrap(), b"preserve me too");
}

#[test]
fn invalid_service_journal_is_refused_before_the_child_starts() {
    let root = tempfile::tempdir().unwrap();
    let logs = root.path().join("logs");
    private::directory(&logs).unwrap();
    let journal = logs.join("casework.log");
    fs::write(&journal, b"").unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o644)).unwrap();
    let marker = root.path().join("child-started");

    let refusal = format!(
        "{:#}",
        service(
            Path::new("/usr/bin/touch"),
            &[],
            &marker,
            &[],
            root.path(),
            "casework",
        )
        .err()
        .expect("unsafe journal must be refused")
    );
    thread::sleep(Duration::from_millis(100));

    assert!(refusal.contains("owner-only"), "{refusal}");
    assert!(!marker.exists());
}

#[test]
fn service_guard_process_helper() {
    let Some(encoded) = std::env::var_os("CASEWORKCTL_TEST_SERVICE_GUARD_ARGV") else {
        return;
    };
    let mut arguments: Vec<String> = serde_json::from_str(&encoded.to_string_lossy()).unwrap();
    let binary = arguments.remove(0);
    let interruption = StartInterruption::install().unwrap();
    let mut command = Command::new(binary);
    command.args(arguments).stdin(Stdio::null());
    let forced = guard_service_command(
        command,
        std::io::stdin(),
        Arc::clone(&interruption.requested),
        Duration::from_millis(500),
        Duration::from_millis(500),
    )
    .unwrap();
    if forced {
        std::process::exit(i32::from(SERVICE_GUARD_FORCED_EXIT));
    }
}

#[test]
fn service_guard_supervisor_helper() {
    let Some(root) = std::env::var_os("CASEWORKCTL_TEST_GUARD_ROOT").map(PathBuf::from) else {
        return;
    };
    let binary = PathBuf::from(std::env::var_os("CASEWORKCTL_TEST_GUARD_BINARY").unwrap());
    private::directory(&root.join("logs")).unwrap();
    let _service = service(
        &binary,
        &[],
        &root.join("service.pid"),
        &[],
        &root,
        "guarded",
    )
    .unwrap();
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

#[test]
fn nonzero_outer_guard_helper() {
    let Some(service_pid_file) =
        std::env::var_os("CASEWORKCTL_TEST_NONZERO_GUARD_PID").map(PathBuf::from)
    else {
        return;
    };
    let service_binary = std::env::var_os("CASEWORKCTL_TEST_NONZERO_GUARD_SERVICE").unwrap();
    let _child = Command::new(service_binary)
        .arg(&service_pid_file)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !service_pid_file.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(service_pid_file.exists(), "service did not become ready");
    std::process::exit(23);
}

#[test]
fn guarded_service_stops_after_its_supervisor_is_killed() {
    let root = tempfile::tempdir().unwrap();
    let binary = root.path().join("service.sh");
    fs::write(
        &binary,
        b"#!/bin/sh\nprintf '%s' \"$$\" > \"$1\"\nwhile :; do sleep 0.02; done\n",
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let mut supervisor = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "dev::tests::service_guard_supervisor_helper",
            "--nocapture",
        ])
        .env("CASEWORKCTL_TEST_GUARD_ROOT", root.path())
        .env("CASEWORKCTL_TEST_GUARD_BINARY", &binary)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let service_pid_file = root.path().join("service.pid");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !service_pid_file.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    if !service_pid_file.exists() {
        supervisor.kill().unwrap();
        supervisor.wait().unwrap();
        panic!("guarded service did not start");
    }
    let service_pid = fs::read_to_string(&service_pid_file)
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let service_pid = rustix::process::Pid::from_raw(service_pid).unwrap();
    let started = Instant::now();

    // SIGKILL skips every supervisor destructor. The kernel still closes the
    // supervisor's liveness writer, which must stop the exact guarded child.
    supervisor.kill().unwrap();
    supervisor.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while rustix::process::test_kill_process(service_pid).is_ok() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let stopped = rustix::process::test_kill_process(service_pid).is_err();
    if !stopped {
        rustix::process::kill_process(service_pid, rustix::process::Signal::KILL).unwrap();
    }

    assert!(stopped, "guarded service survived supervisor death");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn service_guard_owns_a_stubborn_child_during_startup_interruption() {
    let root = tempfile::tempdir().unwrap();
    let binary = root.path().join("stubborn.sh");
    let service_pid_file = root.path().join("service.pid");
    fs::write(
        &binary,
        b"#!/bin/sh\ntrap '' TERM\nprintf '%s' \"$$\" > \"$1\"\nwhile :; do sleep 0.02; done\n",
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let (reader, writer) = UnixStream::pair().unwrap();
    let terminate = Arc::new(AtomicBool::new(false));
    let request = Arc::clone(&terminate);
    let marker = service_pid_file.clone();
    let requester = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !marker.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        let ready = marker.exists();
        if ready {
            request.store(true, Ordering::Relaxed);
        }
        // EOF is also a cleanup request if readiness failed, so the assertion
        // below cannot strand whatever the guard managed to spawn.
        drop(writer);
        ready
    });
    let mut command = Command::new(&binary);
    command.arg(&service_pid_file).stdin(Stdio::null());

    let forced = guard_service_command(
        command,
        reader,
        terminate,
        Duration::from_millis(50),
        Duration::from_millis(50),
    )
    .unwrap();
    let ready = requester.join().unwrap();
    assert!(
        ready,
        "stubborn service did not reach its startup handshake"
    );
    let service_pid = fs::read_to_string(&service_pid_file)
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let service_pid = rustix::process::Pid::from_raw(service_pid).unwrap();

    assert!(forced);
    assert!(wait_for_process_exit(service_pid, Duration::from_secs(2)));
}

#[test]
fn service_guard_does_not_force_kill_after_a_fast_term_exit() {
    let (reader, writer) = UnixStream::pair().unwrap();
    drop(writer);
    let mut command = Command::new("/bin/sleep");
    command.arg("5").stdin(Stdio::null());

    let forced = guard_service_command(
        command,
        reader,
        Arc::new(AtomicBool::new(false)),
        Duration::from_millis(100),
        Duration::from_millis(100),
    )
    .unwrap();

    assert!(!forced);
}

#[test]
fn established_service_keeps_its_graceful_shutdown_window() {
    let root = tempfile::tempdir().unwrap();
    private::directory(&root.path().join("logs")).unwrap();
    let binary = root.path().join("service.sh");
    let graceful = root.path().join("graceful");
    fs::write(
        &binary,
        b"#!/bin/sh\ntrap 'sleep 0.2; printf graceful > \"$2\"; exit 0' TERM\nprintf '%s' \"$$\" > \"$1\"\nwhile :; do sleep 0.02; done\n",
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let service_pid_file = root.path().join("service.pid");
    let mut service = service(
        &binary,
        &[],
        &service_pid_file,
        &[graceful.to_str().unwrap()],
        root.path(),
        "guarded",
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !service_pid_file.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    if !service_pid_file.exists() {
        let _ = service.stop();
        panic!("service did not reach its startup handshake");
    }

    let started = Instant::now();
    service.stop().unwrap();

    assert!(graceful.exists(), "guardian truncated graceful shutdown");
    assert!(started.elapsed() >= Duration::from_millis(150));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn established_stubborn_service_reports_forced_shutdown() {
    let root = tempfile::tempdir().unwrap();
    private::directory(&root.path().join("logs")).unwrap();
    let binary = root.path().join("stubborn.sh");
    let service_pid_file = root.path().join("service.pid");
    fs::write(
        &binary,
        b"#!/bin/sh\ntrap '' TERM\nprintf '%s' \"$$\" > \"$1\"\nwhile :; do sleep 0.02; done\n",
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let mut service =
        service(&binary, &[], &service_pid_file, &[], root.path(), "guarded").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !service_pid_file.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    if !service_pid_file.exists() {
        let _ = service.stop();
        panic!("stubborn service did not reach its startup handshake");
    }
    let service_pid = fs::read_to_string(&service_pid_file)
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let service_pid = rustix::process::Pid::from_raw(service_pid).unwrap();

    let refusal = format!("{:#}", service.stop().unwrap_err());

    assert!(refusal.contains("required forced shutdown"), "{refusal}");
    assert!(wait_for_process_exit(service_pid, Duration::from_secs(2)));
}

#[test]
fn killed_guard_leaves_the_supervisor_to_clean_its_exact_service_group() {
    let root = tempfile::tempdir().unwrap();
    private::directory(&root.path().join("logs")).unwrap();
    let binary = root.path().join("stubborn.sh");
    let service_pid_file = root.path().join("service.pid");
    fs::write(
        &binary,
        b"#!/bin/sh\ntrap '' TERM\nprintf '%s' \"$$\" > \"$1\"\nwhile :; do sleep 0.02; done\n",
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let mut service =
        service(&binary, &[], &service_pid_file, &[], root.path(), "guarded").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !service_pid_file.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(service_pid_file.exists(), "guarded service did not start");
    let service_pid = rustix::process::Pid::from_raw(
        fs::read_to_string(&service_pid_file)
            .unwrap()
            .parse::<i32>()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        rustix::process::getpgid(Some(service_pid)).unwrap(),
        service.guard_pgid,
        "the actual service must inherit the guard's pinned group"
    );

    rustix::process::kill_process(service.guard_pid, rustix::process::Signal::KILL).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while service.guard_exit().unwrap().is_none() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        service.guard_exit().unwrap().is_some(),
        "killed guard did not become waitable"
    );
    assert!(
        rustix::process::test_kill_process(service_pid).is_ok(),
        "the regression requires a service left alive by its killed guard"
    );

    let refusal = format!(
        "{:#}",
        service
            .stop_with_grace(Duration::from_millis(100), Duration::from_millis(25))
            .unwrap_err()
    );

    assert!(refusal.contains("guard exited abnormally"), "{refusal}");
    assert!(wait_for_process_exit(service_pid, Duration::from_secs(2)));
}

#[test]
fn nonzero_guard_exit_is_detected_without_waiting_for_pump_eof() {
    let root = tempfile::tempdir().unwrap();
    private::directory(&root.path().join("logs")).unwrap();
    let service_pid_file = root.path().join("service.pid");
    let service_binary = root.path().join("service.sh");
    fs::write(
        &service_binary,
        b"#!/bin/sh\ntrap '' HUP TERM\nprintf '%s' \"$$\" > \"$1\"\nwhile :; do sleep 0.02; done\n",
    )
    .unwrap();
    fs::set_permissions(&service_binary, fs::Permissions::from_mode(0o700)).unwrap();
    let mut guard = Command::new(std::env::current_exe().unwrap());
    guard
        .args([
            "--exact",
            "dev::tests::nonzero_outer_guard_helper",
            "--nocapture",
        ])
        .env("CASEWORKCTL_TEST_NONZERO_GUARD_PID", &service_pid_file)
        .env("CASEWORKCTL_TEST_NONZERO_GUARD_SERVICE", &service_binary);
    let mut service = service_with_guard_command(guard, root.path(), "guarded").unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while (!service_pid_file.exists() || service.guard_exit().unwrap().is_none())
        && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        service_pid_file.exists(),
        "guard did not create its service"
    );
    assert!(
        service.guard_exit().unwrap().is_some(),
        "nonzero guard did not become waitable"
    );
    let service_pid = rustix::process::Pid::from_raw(
        fs::read_to_string(&service_pid_file)
            .unwrap()
            .parse::<i32>()
            .unwrap(),
    )
    .unwrap();
    assert!(rustix::process::test_kill_process(service_pid).is_ok());
    let started = Instant::now();

    let refusal = format!(
        "{:#}",
        service
            .stop_with_grace(Duration::from_millis(50), Duration::from_millis(10))
            .unwrap_err()
    );

    assert!(refusal.contains("guard exited abnormally"), "{refusal}");
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(wait_for_process_exit(service_pid, Duration::from_secs(2)));
}

#[test]
fn live_guard_timeout_kills_the_pinned_group_before_reaping() {
    let root = tempfile::tempdir().unwrap();
    private::directory(&root.path().join("logs")).unwrap();
    let service_binary = root.path().join("service.sh");
    let guard_binary = root.path().join("guard.sh");
    let service_pid_file = root.path().join("service.pid");
    fs::write(
        &service_binary,
        b"#!/bin/sh\ntrap '' TERM\nprintf '%s' \"$$\" > \"$1\"\nwhile :; do sleep 0.02; done\n",
    )
    .unwrap();
    fs::write(
        &guard_binary,
        b"#!/bin/sh\ntrap '' TERM\n\"$1\" \"$2\" &\nwhile [ ! -s \"$2\" ]; do sleep 0.01; done\nwhile :; do sleep 0.02; done\n",
    )
    .unwrap();
    fs::set_permissions(&service_binary, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&guard_binary, fs::Permissions::from_mode(0o700)).unwrap();
    let mut guard = Command::new(&guard_binary);
    guard.arg(&service_binary).arg(&service_pid_file);
    let mut service = service_with_guard_command(guard, root.path(), "guarded").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !service_pid_file.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(service_pid_file.exists(), "guarded service did not start");
    let service_pid = rustix::process::Pid::from_raw(
        fs::read_to_string(&service_pid_file)
            .unwrap()
            .parse::<i32>()
            .unwrap(),
    )
    .unwrap();
    let started = Instant::now();

    let refusal = format!(
        "{:#}",
        service
            .stop_with_grace(Duration::from_millis(75), Duration::from_millis(10))
            .unwrap_err()
    );

    assert!(refusal.contains("required forced shutdown"), "{refusal}");
    assert!(started.elapsed() >= Duration::from_millis(70));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(wait_for_process_exit(service_pid, Duration::from_secs(2)));
}

#[test]
fn post_kill_wait_is_bounded_when_a_guard_does_not_become_waitable() {
    let mut guard = Command::new("/bin/sleep")
        .arg("5")
        .process_group(0)
        .spawn()
        .unwrap();
    let guard_pid = rustix::process::Pid::from_raw(guard.id() as i32).unwrap();
    let started = Instant::now();

    // Model a kernel reporting successful group KILL without making the guard
    // waitable. Cleanup must return at its own bound instead of entering a
    // blocking Child::wait.
    let refusal = format!(
        "{:#}",
        kill_guard_group_and_reap_with(&mut guard, guard_pid, Duration::from_millis(40), |_pgid| {
            Ok(())
        },)
        .unwrap_err()
    );

    assert!(refusal.contains("bounded cleanup wait"), "{refusal}");
    assert!(started.elapsed() >= Duration::from_millis(35));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(guard_exit(guard_pid).unwrap().is_none());
    rustix::process::kill_process(guard_pid, rustix::process::Signal::KILL).unwrap();
    guard.wait().unwrap();
}

#[test]
fn failed_group_kill_never_enters_a_blocking_guard_wait() {
    let mut guard = Command::new("/bin/sleep")
        .arg("5")
        .process_group(0)
        .spawn()
        .unwrap();
    let guard_pid = rustix::process::Pid::from_raw(guard.id() as i32).unwrap();
    let started = Instant::now();

    let refusal = format!(
        "{:#}",
        kill_guard_group_and_reap_with(&mut guard, guard_pid, Duration::from_secs(1), |_pgid| Err(
            anyhow::anyhow!("injected group KILL failure")
        ),)
        .unwrap_err()
    );

    assert!(refusal.contains("cannot KILL"), "{refusal}");
    assert!(refusal.contains("injected group KILL failure"), "{refusal}");
    assert!(started.elapsed() < Duration::from_millis(100));
    assert!(guard_exit(guard_pid).unwrap().is_none());
    rustix::process::kill_process(guard_pid, rustix::process::Signal::KILL).unwrap();
    guard.wait().unwrap();
}

#[test]
fn service_pump_setup_failures_reap_the_child_and_join_started_pumps() {
    let root = tempfile::tempdir().unwrap();
    let logs = root.path().join("logs");
    private::directory(&logs).unwrap();
    for fail_on in [1, 2] {
        let journal = RetainedJournal::open(&logs.join("casework.log")).unwrap();
        let child = Command::new("/bin/sh")
            .args(["-c", "read ignored || exit 0"])
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
        let joined = Arc::new(AtomicBool::new(false));
        let mut calls = 0;
        let started = Instant::now();

        let refusal = format!(
            "{:#}",
            service_with_pump_spawner(child, journal, |_stream, task| {
                calls += 1;
                if calls == fail_on {
                    return Err(std::io::Error::other("injected pump spawn failure"));
                }
                let joined = Arc::clone(&joined);
                thread::Builder::new().spawn(move || {
                    let result = task();
                    joined.store(true, Ordering::Relaxed);
                    result
                })
            })
            .err()
            .expect("selected pump spawn must fail")
        );

        let reader = if fail_on == 1 { "output" } else { "diagnostic" };
        assert!(refusal.contains(reader), "{refusal}");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(joined.load(Ordering::Relaxed), fail_on == 2);
        assert!(rustix::process::test_kill_process(pid).is_err());
    }
}

#[test]
fn guardian_pump_setup_failure_reaps_a_stubborn_owned_service() {
    let root = tempfile::tempdir().unwrap();
    let logs = root.path().join("logs");
    private::directory(&logs).unwrap();
    let binary = root.path().join("stubborn.sh");
    let service_pid_file = root.path().join("service.pid");
    fs::write(
        &binary,
        b"#!/bin/sh\ntrap '' TERM\nprintf '%s' \"$$\" > \"$1\"\nwhile :; do sleep 0.02; done\n",
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let mut guardian =
        service_guard_command(&binary, &[service_pid_file.as_os_str().to_owned()]).unwrap();
    let child = guardian
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let journal = RetainedJournal::open(&logs.join("casework.log")).unwrap();
    let started = Instant::now();
    let mut ready = false;

    let refusal = format!(
        "{:#}",
        service_with_pump_spawner(child, journal, |_stream, _task| {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !service_pid_file.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            ready = service_pid_file.exists();
            Err(std::io::Error::other("injected pump spawn failure"))
        })
        .err()
        .expect("injected guardian pump spawn must fail")
    );
    assert!(
        ready,
        "stubborn service did not reach its startup handshake"
    );
    let service_pid = fs::read_to_string(&service_pid_file)
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let service_pid = rustix::process::Pid::from_raw(service_pid).unwrap();

    assert!(refusal.contains("output reader"), "{refusal}");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(rustix::process::test_kill_process(service_pid).is_err());
}

#[test]
fn seeding_administrator_token_is_issued_after_every_other_client() {
    let root = tempfile::tempdir().unwrap();
    let project = standalone(root.path());
    let mut state = session(&project);
    let clients = Clients {
        version: 1,
        clients: (0..32)
            .map(|index| config::Client {
                id: if index == 0 {
                    "administrator".to_owned()
                } else {
                    format!("client-{index}")
                },
                access_profile: format!("profile-{index}"),
                scopes: vec!["casework:test".to_owned()],
                claims: BTreeMap::new(),
            })
            .collect(),
        directory: Vec::new(),
    };
    state.clients = clients
        .clients
        .iter()
        .enumerate()
        .map(|(index, client)| ReportedClient {
            id: client.id.clone(),
            profile: client.access_profile.clone(),
            role: if index == 0 {
                CaseworkRole::Administrator
            } else {
                CaseworkRole::Requester
            },
            principal: config::principal(&client.id),
        })
        .collect();
    let mut issued = Vec::new();
    let terminate = AtomicBool::new(false);

    issue_tokens(&state, &clients, &terminate, |id| {
        issued.push(id.to_owned());
        Ok(())
    })
    .unwrap();

    assert_eq!(issued.len(), clients.clients.len());
    assert_eq!(issued.last().map(String::as_str), Some("administrator"));
    assert_eq!(
        issued.into_iter().collect::<BTreeSet<_>>(),
        clients
            .clients
            .iter()
            .map(|client| client.id.clone())
            .collect()
    );
}

#[test]
fn token_issuance_stops_between_clients_when_interrupted() {
    let root = tempfile::tempdir().unwrap();
    let project = standalone(root.path());
    let mut state = session(&project);
    let clients = Clients {
        version: 1,
        clients: vec![
            config::Client {
                id: "administrator".to_owned(),
                access_profile: "administrator".to_owned(),
                scopes: vec!["casework:admin".to_owned()],
                claims: BTreeMap::new(),
            },
            config::Client {
                id: "requester".to_owned(),
                access_profile: "requester".to_owned(),
                scopes: vec!["casework:request".to_owned()],
                claims: BTreeMap::new(),
            },
        ],
        directory: Vec::new(),
    };
    state.clients = vec![
        ReportedClient {
            id: "administrator".to_owned(),
            profile: "administrator".to_owned(),
            role: CaseworkRole::Administrator,
            principal: config::principal("administrator"),
        },
        ReportedClient {
            id: "requester".to_owned(),
            profile: "requester".to_owned(),
            role: CaseworkRole::Requester,
            principal: config::principal("requester"),
        },
    ];
    let terminate = AtomicBool::new(false);
    let mut issued = Vec::new();

    let refusal = format!(
        "{:#}",
        issue_tokens(&state, &clients, &terminate, |id| {
            issued.push(id.to_owned());
            terminate.store(true, Ordering::Relaxed);
            Ok(())
        })
        .unwrap_err()
    );

    assert!(refusal.contains("interrupted"), "{refusal}");
    assert_eq!(issued, ["requester"]);
}

#[test]
fn service_cleanup_joins_every_log_pump() {
    let child = Command::new("/usr/bin/true")
        .process_group(0)
        .spawn()
        .unwrap();
    let joined = Arc::new(AtomicBool::new(false));
    let marker = Arc::clone(&joined);
    let pump = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        marker.store(true, Ordering::Relaxed);
        Ok(())
    });
    let mut children = Children {
        casework: Some(Service::from_guard(child, vec![pump]).unwrap()),
        mint: None,
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    while !children.exited().unwrap() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(children.exited().unwrap(), "guard did not become waitable");

    children.stop().unwrap();
    assert!(joined.load(Ordering::Relaxed));
}
