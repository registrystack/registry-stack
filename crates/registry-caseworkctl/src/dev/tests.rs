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
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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
fn service_cleanup_joins_every_log_pump() {
    let child = Command::new("/usr/bin/true").spawn().unwrap();
    let joined = Arc::new(AtomicBool::new(false));
    let marker = Arc::clone(&joined);
    let pump = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        marker.store(true, Ordering::Relaxed);
        Ok(())
    });
    let mut children = Children {
        casework: Some(Service {
            child,
            pumps: vec![pump],
        }),
        mint: None,
    };

    children.stop().unwrap();
    assert!(joined.load(Ordering::Relaxed));
}
