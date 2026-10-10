// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::project::{STANDALONE_DEV_CLIENTS, STANDALONE_YAML};
use clap::Parser;
use registry_casework::RuntimeConfig;

fn session(project: &Path) -> State {
    State {
        api_version: DEV_STATE_API_VERSION.to_owned(),
        kind: DEV_STATE_KIND.to_owned(),
        project: project.to_path_buf(),
        owner: uuid::Uuid::new_v4().to_string(),
        status: Status::Stopped,
        casework_port: 8092,
        issuer_port: 8093,
        issuer_project: None,
        issuer_owner: None,
        database_port: 55433,
        clients_file: project.join("dev-clients.yaml"),
        source_digest: String::new(),
        resource: None,
        clients: Vec::new(),
        container_id: None,
        tls_files_copied: false,
        database_ready: false,
        migrated: false,
        seeded: Vec::new(),
        directory_revision: 0,
        directory_teams: 0,
        binaries: BTreeMap::new(),
        failure: None,
        sources: BTreeMap::new(),
        borrowed_scopes: BTreeMap::new(),
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

/// Only a hung child reaches this: each wait ends as soon as its event
/// happens, so a starved runner makes a test slower, never wrong. Matches
/// the outer bound the language-server and evidencectl process tests use.
const TEST_EVENT_BOUND: Duration = Duration::from_secs(120);

/// Polls `condition` until it holds or [`TEST_EVENT_BOUND`] passes.
fn eventually(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + TEST_EVENT_BOUND;
    while !condition() {
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(5));
    }
    true
}

fn wait_for_process_exit(pid: rustix::process::Pid) -> bool {
    eventually(|| rustix::process::test_kill_process(pid).is_err())
}

fn file_has_bytes(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0)
}

/// The PID a child wrote to `path`, or `None` if it wrote nothing within
/// [`TEST_EVENT_BOUND`].
fn announced_pid(path: &Path) -> Option<rustix::process::Pid> {
    if !eventually(|| file_has_bytes(path)) {
        return None;
    }
    let pid = fs::read_to_string(path).unwrap().parse::<i32>().unwrap();
    Some(rustix::process::Pid::from_raw(pid).unwrap())
}

/// The envelope every clients file starts with.
const CLIENTS_ENVELOPE: &str =
    "apiVersion: id.registrystack.org/formats/casework/dev-clients/v1alpha1\nkind: CaseworkDevClients\n";

/// A clients file the reader accepts.
fn accepted(bytes: &[u8]) -> config::Clients {
    config::read("dev-clients.yaml", bytes).unwrap().value
}

/// Each diagnostic's code and pointer, from a clients file the reader refuses.
fn refused(bytes: &[u8]) -> Vec<(String, String)> {
    config::read("dev-clients.yaml", bytes)
        .unwrap_err()
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
        .collect()
}

/// Each finding's code and pointer, from clients the project does not bind.
fn unbound(
    clients: &config::Clients,
    policy: &registry_casework_core::CaseworkProject,
) -> Vec<(String, String)> {
    config::bind(clients, policy)
        .unwrap_err()
        .iter()
        .map(|finding| (finding.code.to_owned(), finding.pointer.clone()))
        .collect()
}

fn expected(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(code, pointer)| ((*code).to_owned(), (*pointer).to_owned()))
        .collect()
}

/// One client bound to the standalone staff profile, then `rest`.
fn one_staff(rest: &str) -> String {
    format!("{CLIENTS_ENVELOPE}clients:\n  - id: staff\n    accessProfile: staff\n    scopes: [casework:staff]\n{rest}")
}

#[test]
fn init_clients_bind_the_standalone_template() {
    let root = crate::canonical_tempdir();
    let project = standalone(root.path());
    let policy = crate::project::load_and_check_policy(&project).unwrap();
    let clients = accepted(STANDALONE_DEV_CLIENTS.as_bytes());
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
    let unknown = one_staff("").replace(
        "scopes: [casework:staff]\n",
        "scopes: [casework:staff]\n    principal: urn:someone\n",
    );
    assert_eq!(
        refused(unknown.as_bytes()),
        expected(&[("config.unknown-key", "/clients/0/principal")])
    );

    let duplicate = one_staff(
        "  - id: staff\n    accessProfile: supervisor\n    scopes: [casework:supervisor]\n",
    );
    assert_eq!(
        refused(duplicate.as_bytes()),
        expected(&[("casework.dev-clients.duplicate-id", "/clients/1/id")])
    );

    // The local issuer owns this identity; a client may not take it.
    let reserved = one_staff("").replace("id: staff", "id: issuer");
    assert_eq!(
        refused(reserved.as_bytes()),
        expected(&[("casework.dev-clients.reserved-id", "/clients/0/id")])
    );

    let redefined = one_staff("    claims:\n      scope: casework:admin\n");
    assert_eq!(
        refused(redefined.as_bytes()),
        expected(&[(
            "casework.dev-clients.reserved-claim",
            "/clients/0/claims/scope"
        )])
    );

    let unknown_member = one_staff(
        "directory:\n  - team: decisions-team\n    queue: decisions\n    staff: [absent]\n",
    );
    assert_eq!(
        refused(unknown_member.as_bytes()),
        expected(&[(
            "casework.dev-clients.unknown-client",
            "/directory/0/staff/0"
        )])
    );
}

#[test]
fn clients_file_names_its_format_and_refuses_the_retired_version_key() {
    let envelope = one_staff("");
    assert_eq!(accepted(envelope.as_bytes()).kind, config::DEV_CLIENTS_KIND);

    let retired = envelope.replace("clients:\n", "version: 1\nclients:\n");
    assert_eq!(
        refused(retired.as_bytes()),
        expected(&[("config.removed-key", "/version")])
    );

    let without_envelope = envelope.replace(CLIENTS_ENVELOPE, "version: 1\n");
    assert_eq!(
        refused(without_envelope.as_bytes())[0].0,
        "config.missing-envelope"
    );

    let other_kind = envelope.replace("kind: CaseworkDevClients", "kind: BregDevClients");
    assert_eq!(refused(other_kind.as_bytes())[0].0, "config.wrong-kind");
}

#[test]
fn clients_file_refuses_null_and_substitution() {
    let null = one_staff("directory:\n");
    assert_eq!(refused(null.as_bytes())[0].0, "config.null-value");

    // The file is read as written; it holds no secret to substitute.
    let substituted = one_staff("    claims:\n      registry_principal: ${PRINCIPAL}\n");
    assert_eq!(
        refused(substituted.as_bytes())[0].0,
        "config.substitution-not-allowed"
    );
}

#[test]
fn clients_file_findings_name_no_value() {
    let secretive = "Sup3r-Secret-Value";
    let checked = one_staff(&format!(
        "    claims:\n      aud: {secretive}\n  - id: second\n    accessProfile: staff\n    scopes: ['{secretive}', '{secretive}']\n"
    ));
    let decoded = one_staff("").replace("id: staff", &format!("id: '{secretive}'"));
    for (text, at_least) in [(checked, 3), (decoded, 1)] {
        let report = config::read("dev-clients.yaml", text.as_bytes()).unwrap_err();
        assert!(
            report.diagnostics().len() >= at_least,
            "{:?}",
            refused(text.as_bytes())
        );
        for diagnostic in report.diagnostics() {
            assert!(!diagnostic.message.contains(secretive), "{diagnostic:?}");
            assert!(
                !diagnostic.suggested_action.contains(secretive),
                "{diagnostic:?}"
            );
        }
    }
}

#[test]
fn client_ids_are_local_identifiers() {
    for valid in [
        "staff-1".to_owned(),
        "staff_review".to_owned(),
        "x".repeat(64),
    ] {
        accepted(
            one_staff("")
                .replace("id: staff", &format!("id: '{valid}'"))
                .as_bytes(),
        );
    }

    for invalid in [
        String::new(),
        "x".repeat(65),
        "1staff".to_owned(),
        "Staff".to_owned(),
        "staff.review".to_owned(),
        "staff:review".to_owned(),
    ] {
        let text = one_staff("").replace("id: staff", &format!("id: '{invalid}'"));
        assert_eq!(
            refused(text.as_bytes()),
            expected(&[("config.invalid-value", "/clients/0/id")]),
            "{invalid:?}"
        );
    }
}

#[test]
fn integrations_read_identifiers_and_urls_through_shared_types() {
    let integrations = |rest: &str| {
        one_staff(&format!(
            "integrations:\n  resource: urn:example:local-review\n{rest}"
        ))
    };
    accepted(
        integrations(
            "  serviceClients:\n    - id: source_reader\n      scopes: [records:get]\n      claims:\n        tenant: north\n",
        )
        .as_bytes(),
    );
    for (rest, pointer) in [
        (
            "  serviceClients:\n    - id: 1reader\n      scopes: [records:get]\n",
            "/integrations/serviceClients/0/id",
        ),
        (
            // The reader places a refused key at the key.
            "  secretFiles:\n    Source-Key: /absolute/key\n",
            "/integrations/secretFiles/Source-Key",
        ),
        (
            "  taskAuthority:\n    issuer: casework.local.example\n    jwksPort: 8094\n    statusClients: {}\n",
            "/integrations/taskAuthority/issuer",
        ),
        (
            "  taskAuthority:\n    issuer: https://casework.local.example\n    jwksPort: 0\n    statusClients: {}\n",
            "/integrations/taskAuthority/jwksPort",
        ),
    ] {
        let refusals = refused(integrations(rest).as_bytes());
        assert_eq!(refusals.len(), 1, "{refusals:?}");
        assert_eq!(refusals[0].1, pointer, "{refusals:?}");
    }
    // A service client's claim is text, as a teaching client's is.
    let structured = refused(
        integrations(
            "  serviceClients:\n    - id: reader\n      scopes: [records:get]\n      claims:\n        tenant: [north]\n",
        )
        .as_bytes(),
    );
    assert_eq!(
        structured[0].1,
        "/integrations/serviceClients/0/claims/tenant"
    );
    // The session leaves a source's timeouts and reconciliation interval at
    // the runtime's defaults; a retained key is a removed key, not an unknown
    // one.
    for key in [
        "requestTimeoutMilliseconds",
        "connectTimeoutMilliseconds",
        "reconciliationIntervalMilliseconds",
    ] {
        let retained = refused(
            integrations(&format!(
                "  sources:\n    source:\n      baseUrl: http://127.0.0.1:8080\n      readerProfile: casework-reader\n      tokenEndpoint: http://127.0.0.1:8093/oauth2/token\n      clientIdRef: secret:file/service-reader-id\n      clientAssertionKeyRef: secret:file/service-reader-key\n      webhookSecretRef: secret:file/source-webhook\n      eventSource: urn:example:source\n      {key}: 5000\n"
            ))
            .as_bytes(),
        );
        assert_eq!(
            retained,
            expected(&[(
                "config.removed-key",
                &format!("/integrations/sources/source/{key}")
            )])
        );
    }
    // The runtime's current name for the attempt timeout was never a key of
    // this file, so it is an unknown key.
    let timeout = refused(
        integrations(
            "  sources:\n    source:\n      baseUrl: http://127.0.0.1:8080\n      readerProfile: casework-reader\n      tokenEndpoint: http://127.0.0.1:8093/oauth2/token\n      clientIdRef: secret:file/service-reader-id\n      clientAssertionKeyRef: secret:file/service-reader-key\n      webhookSecretRef: secret:file/source-webhook\n      eventSource: urn:example:source\n      attemptTimeoutMilliseconds: 5000\n",
        )
        .as_bytes(),
    );
    assert_eq!(
        timeout,
        expected(&[(
            "config.unknown-key",
            "/integrations/sources/source/attemptTimeoutMilliseconds"
        )])
    );
}

#[test]
fn access_profile_references_match_the_casework_profile_contract() {
    for valid in [
        "staff_review".to_owned(),
        "staff.review".to_owned(),
        "staff:review".to_owned(),
        "staff.review:v1_2-3".to_owned(),
        "x".repeat(128),
    ] {
        let text =
            one_staff("").replace("accessProfile: staff", &format!("accessProfile: '{valid}'"));
        accepted(text.as_bytes());
    }

    for invalid in [
        String::new(),
        "x".repeat(129),
        "staff/review".to_owned(),
        "staff review".to_owned(),
        "stáff".to_owned(),
    ] {
        let text = one_staff("").replace(
            "accessProfile: staff",
            &format!("accessProfile: '{invalid}'"),
        );
        assert_eq!(
            refused(text.as_bytes()),
            expected(&[(
                "casework.dev-clients.invalid-access-profile",
                "/clients/0/accessProfile"
            )]),
            "{invalid:?}"
        );
    }
}

#[test]
fn queue_references_match_the_directory_identifier_contract() {
    let team = |queue: &str| {
        one_staff(&format!(
            "directory:\n  - team: review-team\n    queue: '{queue}'\n    staff: [staff]\n"
        ))
    };
    for valid in [
        "review_queue".to_owned(),
        "review.queue".to_owned(),
        "review.queue_1-2".to_owned(),
        "x".repeat(128),
    ] {
        accepted(team(&valid).as_bytes());
    }

    for invalid in [
        String::new(),
        "x".repeat(129),
        "review:queue".to_owned(),
        "review/queue".to_owned(),
        "review queue".to_owned(),
        "réview".to_owned(),
    ] {
        assert_eq!(
            refused(team(&invalid).as_bytes()),
            expected(&[("casework.dev-clients.invalid-queue", "/directory/0/queue")]),
            "{invalid:?}"
        );
    }
}

#[test]
fn clients_file_refuses_duplicate_and_non_rfc6749_scopes() {
    for (scopes, code, pointer) in [
        (
            "[casework:staff, casework:staff]",
            "casework.dev-clients.duplicate-scope",
            "/clients/2/scopes/1",
        ),
        (
            "['casework:\"staff']",
            "casework.dev-clients.invalid-scope",
            "/clients/2/scopes/0",
        ),
        (
            r"['casework:\staff']",
            "casework.dev-clients.invalid-scope",
            "/clients/2/scopes/0",
        ),
        (
            "[casework:stáff]",
            "casework.dev-clients.invalid-scope",
            "/clients/2/scopes/0",
        ),
    ] {
        let invalid = STANDALONE_DEV_CLIENTS
            .replace("scopes: [casework:staff]", &format!("scopes: {scopes}"));
        assert_ne!(invalid, STANDALONE_DEV_CLIENTS);
        assert_eq!(
            refused(invalid.as_bytes()),
            expected(&[(code, pointer)]),
            "{scopes}"
        );
    }
}

#[test]
fn clients_file_refuses_invalid_and_reserved_claim_names() {
    // The template's header comment names the claim too; replace the first
    // client's entry only.
    let invalid_name = STANDALONE_DEV_CLIENTS.replacen(
        "\n      registry_actor_kind: human",
        "\n      'registry\\actor_kind': human",
        1,
    );
    assert_ne!(invalid_name, STANDALONE_DEV_CLIENTS);
    assert_eq!(
        refused(invalid_name.as_bytes()),
        expected(&[(
            "casework.dev-clients.invalid-claim-name",
            "/clients/0/claims/registry\\actor_kind"
        )])
    );

    // Registered claims belong to the issuer, not authored client claims.
    let reserved = STANDALONE_DEV_CLIENTS.replacen(
        "\n      registry_actor_kind: human",
        "\n      aud: human",
        1,
    );
    assert_ne!(reserved, STANDALONE_DEV_CLIENTS);
    assert_eq!(
        refused(reserved.as_bytes()),
        expected(&[(
            "casework.dev-clients.reserved-claim",
            "/clients/0/claims/aud"
        )])
    );
}

#[test]
fn clients_file_refuses_repeated_members_within_each_team_role() {
    for (members, repeated, pointer) in [
        (
            "staff: [staff]",
            "staff: [staff, staff]",
            "/directory/0/staff/1",
        ),
        (
            "supervisors: [supervisor]",
            "supervisors: [supervisor, supervisor]",
            "/directory/0/supervisors/1",
        ),
    ] {
        let invalid = STANDALONE_DEV_CLIENTS.replace(members, repeated);
        assert_ne!(invalid, STANDALONE_DEV_CLIENTS);
        assert_eq!(
            refused(invalid.as_bytes()),
            expected(&[("casework.dev-clients.duplicate-member", pointer)])
        );
    }
}

#[test]
fn clients_file_refuses_two_teams_assigned_to_one_queue() {
    let duplicate_queue = STANDALONE_DEV_CLIENTS.replace(
        "  - team: decisions-team\n",
        "  - team: intake-team\n    queue: decisions\n    staff: [staff]\n    supervisors: [supervisor]\n  - team: decisions-team\n",
    );
    assert_ne!(duplicate_queue, STANDALONE_DEV_CLIENTS);
    assert_eq!(
        refused(duplicate_queue.as_bytes()),
        expected(&[("casework.dev-clients.duplicate-queue", "/directory/1/queue")])
    );
}

#[test]
fn binding_refuses_a_requester_with_a_human_claim() {
    let root = crate::canonical_tempdir();
    let project = standalone(root.path());
    let policy = crate::project::load_and_check_policy(&project).unwrap();
    let text = STANDALONE_DEV_CLIENTS.replace(
        "  - id: requester\n    accessProfile: requester\n    scopes: [casework:request]\n",
        "  - id: requester\n    accessProfile: requester\n    scopes: [casework:request]\n    claims:\n      registry_actor_kind: human\n",
    );
    assert_ne!(text, STANDALONE_DEV_CLIENTS);
    let clients = accepted(text.as_bytes());
    assert_eq!(
        unbound(&clients, &policy),
        expected(&[(
            "casework.dev-clients.requester-human-claim",
            "/clients/3/claims/registry_actor_kind"
        )])
    );
}

#[test]
fn binding_accepts_a_client_with_every_required_profile_scope() {
    let root = crate::canonical_tempdir();
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
    let clients = accepted(text.as_bytes());

    config::bind(&clients, &policy).unwrap();
}

#[test]
fn binding_refuses_a_client_missing_one_required_profile_scope() {
    let root = crate::canonical_tempdir();
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
    let clients = accepted(STANDALONE_DEV_CLIENTS.as_bytes());

    assert_eq!(
        unbound(&clients, &policy),
        expected(&[(
            "casework.dev-clients.missing-required-scope",
            "/clients/2/scopes"
        )])
    );
}

#[test]
fn binding_accepts_directory_members_with_matching_roles() {
    let root = crate::canonical_tempdir();
    let project = standalone(root.path());
    let policy = crate::project::load_and_check_policy(&project).unwrap();
    let clients = accepted(STANDALONE_DEV_CLIENTS.as_bytes());

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
    let root = crate::canonical_tempdir();
    let project = standalone(root.path());

    for (role, existing_id, second_id, pointer) in [
        (
            CaseworkRole::Staff,
            "staff",
            "second-staff",
            "/directory/0/staff/1",
        ),
        (
            CaseworkRole::Supervisor,
            "supervisor",
            "second-supervisor",
            "/directory/0/supervisors/1",
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

        let mut clients = accepted(STANDALONE_DEV_CLIENTS.as_bytes());
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

        assert_eq!(
            unbound(&clients, &policy),
            expected(&[("casework.dev-clients.repeated-principal", pointer)])
        );
    }
}

#[test]
fn binding_accepts_one_resolved_principal_in_each_membership_kind() {
    let root = crate::canonical_tempdir();
    let project = standalone(root.path());
    let mut policy = crate::project::load_and_check_policy(&project).unwrap();
    for profile in &mut policy.access_profiles {
        if matches!(profile.role, CaseworkRole::Staff | CaseworkRole::Supervisor) {
            profile.principal_claim = "registry_principal".to_owned();
        }
    }
    let mut clients = accepted(STANDALONE_DEV_CLIENTS.as_bytes());
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
    let root = crate::canonical_tempdir();
    let project = standalone(root.path());
    let policy = crate::project::load_and_check_policy(&project).unwrap();

    for (from, to, code, pointer) in [
        (
            "staff: [staff]",
            "staff: [supervisor]",
            "casework.dev-clients.member-role-mismatch",
            "/directory/0/staff/0",
        ),
        (
            "supervisors: [supervisor]",
            "supervisors: [staff]",
            "casework.dev-clients.member-role-mismatch",
            "/directory/0/supervisors/0",
        ),
        (
            "staff: [staff]",
            "staff: [requester]",
            "casework.dev-clients.requester-member",
            "/directory/0/staff/0",
        ),
    ] {
        let text = STANDALONE_DEV_CLIENTS.replace(from, to);
        assert_ne!(text, STANDALONE_DEV_CLIENTS);
        let clients = accepted(text.as_bytes());
        assert_eq!(unbound(&clients, &policy), expected(&[(code, pointer)]));
    }
}

#[test]
fn binding_refuses_an_unserved_queue_and_a_missing_administrator() {
    let root = crate::canonical_tempdir();
    let project = standalone(root.path());
    let policy = crate::project::load_and_check_policy(&project).unwrap();

    let unserved = STANDALONE_DEV_CLIENTS
        .split("directory:")
        .next()
        .unwrap()
        .to_owned();
    let clients = accepted(unserved.as_bytes());
    assert_eq!(
        unbound(&clients, &policy),
        expected(&[("casework.dev-clients.unserved-queue", "/directory")])
    );

    let without_administrator = one_staff(
        "    claims:\n      registry_actor_kind: human\ndirectory:\n  - team: decisions-team\n    queue: decisions\n    staff: [staff]\n",
    );
    let clients = accepted(without_administrator.as_bytes());
    assert_eq!(
        unbound(&clients, &policy),
        expected(&[("casework.dev-clients.missing-administrator", "/clients")])
    );

    let unknown_queue = format!("{CLIENTS_ENVELOPE}clients:\n  - id: administrator\n    accessProfile: administrator\n    scopes: [casework:admin]\n    claims:\n      registry_actor_kind: human\ndirectory:\n  - team: other-team\n    queue: corrections\n    staff: [administrator]\n");
    let clients = accepted(unknown_queue.as_bytes());
    assert_eq!(
        unbound(&clients, &policy),
        expected(&[
            ("casework.dev-clients.unknown-queue", "/directory/0/queue"),
            (
                "casework.dev-clients.member-role-mismatch",
                "/directory/0/staff/0"
            ),
            ("casework.dev-clients.unserved-queue", "/directory"),
        ])
    );
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
fn each_start_packages_the_authored_project_the_runtime_verifies() {
    let root = crate::canonical_tempdir();
    let project = standalone(root.path());
    let state = session(&project);
    let session_root = state.root();
    fs::create_dir_all(&session_root).unwrap();
    fs::set_permissions(project.join(".casework"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&session_root, fs::Permissions::from_mode(0o700)).unwrap();
    let path = session_root.join("operator.yaml");
    config::write_yaml(&path, &config::operator(&state)).unwrap();

    // The session never serves the authored project directly.
    let error = RuntimeConfig::load(&path).expect_err("an unpackaged session is refused");
    assert!(error.to_string().contains("caseworkctl package"), "{error}");

    // A staging directory an interrupted start left behind is replaced.
    fs::create_dir(session_root.join(".package-staged")).unwrap();
    package_session(&session_root, &project).unwrap();
    assert!(!session_root.join(".package-staged").exists());
    assert!(!session_root.join(".package-retired").exists());
    let first = RuntimeConfig::load(&path)
        .unwrap()
        .package_digest()
        .unwrap();
    let package = session_root.join(SESSION_PACKAGE);
    assert_eq!(
        fs::read(package.join("casework.yaml")).unwrap(),
        STANDALONE_YAML.as_bytes()
    );

    // An edit to the authored project reaches the runtime only through the
    // next start's package, and a package changed in place is refused.
    fs::write(
        project.join("casework.yaml"),
        format!("{STANDALONE_YAML}\n# edited\n"),
    )
    .unwrap();
    assert_eq!(
        RuntimeConfig::load(&path)
            .unwrap()
            .package_digest()
            .unwrap(),
        first
    );
    fs::write(
        package.join("casework.yaml"),
        format!("{STANDALONE_YAML}\n# edited\n"),
    )
    .unwrap();
    let error = RuntimeConfig::load(&path).expect_err("a changed package is refused");
    assert!(
        error.to_string().contains("changed: casework.yaml"),
        "{error}"
    );

    package_session(&session_root, &project).unwrap();
    let second = RuntimeConfig::load(&path)
        .unwrap()
        .package_digest()
        .unwrap();
    assert_ne!(first, second);
}

#[test]
fn a_session_connects_the_runtime_and_apply_with_one_database_credential() {
    let root = crate::canonical_tempdir();
    let project = standalone(root.path());
    let state = session(&project);
    let session_root = state.root();
    fs::create_dir_all(session_root.join("database")).unwrap();
    fs::create_dir_all(session_root.join("secrets")).unwrap();
    for directory in [
        project.join(".casework"),
        session_root.clone(),
        session_root.join("database"),
        session_root.join("secrets"),
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    config::database_credentials(&session_root, &state).unwrap();

    let runtime = fs::read_to_string(session_root.join("secrets/runtime-database-url")).unwrap();
    let migration =
        fs::read_to_string(session_root.join("secrets/migration-database-url")).unwrap();
    assert_eq!(runtime, migration);
    assert!(
        runtime.starts_with(&format!("postgresql://{MIGRATION_ROLE}:")),
        "the session connects as its one database role"
    );
    assert!(!session_root.join("database/runtime-password").exists());
    assert!(!split_roles(&session_root));
    fs::write(session_root.join("database/runtime-password"), "retained").unwrap();
    assert!(
        split_roles(&session_root),
        "a retained split session keeps its roles"
    );
}

#[test]
fn generated_operator_config_loads_through_the_runtime_contract() {
    let root = crate::canonical_tempdir();
    let project = standalone(root.path());
    let state = session(&project);
    let session_root = state.root();
    fs::create_dir_all(&session_root).unwrap();
    fs::set_permissions(project.join(".casework"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&session_root, fs::Permissions::from_mode(0o700)).unwrap();
    let path = session_root.join("operator.yaml");
    config::write_yaml(&path, &config::operator(&state)).unwrap();
    package_session(&session_root, &project).unwrap();

    let config = RuntimeConfig::load(&path).unwrap();
    assert_eq!(
        config.api_version,
        registry_casework::RUNTIME_CONFIG_API_VERSION
    );
    assert_eq!(config.kind, registry_casework::RUNTIME_CONFIG_KIND);
    assert_eq!(config.package.root, session_root.join(SESSION_PACKAGE));
    assert_eq!(config.listener.bind, "127.0.0.1:8092".parse().unwrap());
    // The local issuer emits one space-delimited `scope` claim.
    assert_eq!(config.authentication.oidc.scope_claim, "scope");
    assert!(matches!(
        config.authentication.oidc.provider.jwks_source,
        registry_casework::JwksSource::Static { ref document_ref }
            if document_ref == "secret:file/issuer-jwks"
    ));
    assert_eq!(
        config.listener.tls_termination,
        registry_casework::TlsTermination::DevelopmentLoopback
    );
    assert_eq!(
        config.listener.network_exposure,
        registry_casework::ListenerNetworkExposure::PrivateAddress
    );
    assert_eq!(
        config
            .secret_providers
            .file
            .as_ref()
            .map(|provider| provider.root.as_path()),
        Some(session_root.join("secrets").as_path())
    );
    assert!(config.secret_providers.environment.is_none());
    assert_eq!(
        config.audit.key.hash_key_ref.as_str(),
        "secret:file/casework-audit-key"
    );
    assert_eq!(
        config.database.runtime_url_ref,
        "secret:file/runtime-database-url"
    );
    assert_eq!(
        config.database.migration_url_ref,
        "secret:file/migration-database-url"
    );
    assert_eq!(
        config.database.trusted_root_certificate_ref.as_deref(),
        Some("secret:file/database-root.pem")
    );
    assert!(config.sources.is_empty());
    assert_eq!(
        config.authentication.oidc.provider.issuer,
        state.issuer_origin()
    );
    assert_eq!(
        config.authentication.oidc.provider.audience,
        state.audience()
    );
}

#[test]
fn a_retained_session_config_is_rewritten_with_every_key_the_runtime_reads() {
    let root = crate::canonical_tempdir();
    let project = standalone(root.path());
    let state = session(&project);
    let session_root = state.root();
    fs::create_dir_all(&session_root).unwrap();
    fs::set_permissions(project.join(".casework"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&session_root, fs::Permissions::from_mode(0o700)).unwrap();
    package_session(&session_root, &project).unwrap();
    // A session an earlier release created wrote no identity block.
    let path = session_root.join("operator.yaml");
    let mut retained = config::operator(&state);
    retained.as_object_mut().unwrap().remove("identity");
    config::write_yaml(&path, &retained).unwrap();
    assert!(RuntimeConfig::load(&path).is_err());

    let clients = accepted(STANDALONE_DEV_CLIENTS.as_bytes());
    config::refresh_operator(&session_root, &state, &clients).unwrap();

    let config = RuntimeConfig::load(&path).expect("the rewritten config loads");
    assert_eq!(config.database_id(), "casework-local-session");
    assert_eq!(config.package.root, session_root.join(SESSION_PACKAGE));
}

#[test]
fn a_project_declaring_sources_is_refused_before_anything_starts() {
    let root = crate::canonical_tempdir();
    let project = root.path().join("project");
    crate::project::init(&project, "professional-review").unwrap();
    let clients = fs::read(project.join("dev-clients.yaml")).unwrap();
    let refusal = format!("{:#}", capture(&project, &clients).unwrap_err());
    assert!(refusal.contains("source"), "{refusal}");
}

#[test]
fn borrowed_source_mode_is_explicit_pinned_and_refuses_session_qualified_subjects() {
    let root = crate::canonical_tempdir();
    let project = root.path().join("project");
    crate::project::init(&project, "professional-review").unwrap();
    let policy = crate::project::load_and_check_policy(&project).unwrap();
    let description = project.join(&policy.sources[0].description);
    fs::create_dir_all(description.parent().unwrap()).unwrap();
    fs::write(&description, b"synthetic source description").unwrap();
    let registry = root.path().join("registry");
    fs::create_dir(&registry).unwrap();
    let clients = fs::read(project.join("dev-clients.yaml")).unwrap();
    let source = [registry.display().to_string()];
    let first = capture_with_sources(
        &project,
        "dev-clients.yaml",
        &clients,
        &source,
        &BTreeMap::new(),
    )
    .unwrap();
    let other = root.path().join("other-registry");
    fs::create_dir(&other).unwrap();
    let moved = [other.display().to_string()];
    assert_ne!(
        first.digest,
        capture_with_sources(
            &project,
            "dev-clients.yaml",
            &clients,
            &moved,
            &BTreeMap::new()
        )
        .unwrap()
        .digest
    );
    let policy_path = project.join("casework.yaml");
    let changed = fs::read_to_string(&policy_path)
        .unwrap()
        .replace("principalClaim: registry_principal", "principalClaim: sub");
    fs::write(policy_path, changed).unwrap();
    let refusal = capture_with_sources(
        &project,
        "dev-clients.yaml",
        &clients,
        &source,
        &BTreeMap::new(),
    )
    .unwrap_err();
    let (exit, diagnostic) = crate::classify_failure(crate::CommandKind::Operational, &refusal);
    assert_eq!(exit, crate::DOMAIN_REFUSAL_EXIT);
    assert_eq!(
        diagnostic["code"],
        "caseworkctl.dev.borrowed-principal-invalid"
    );
    assert_eq!(
        diagnostic["path"],
        "casework.yaml:/accessProfiles/principalClaim"
    );
}

#[test]
fn task_templates_cannot_use_the_borrowed_source_issuer() {
    let refusal = validate_source_mode(true, false, true)
        .unwrap_err()
        .to_string();
    assert!(
        refusal.contains("task templates require explicit integrations"),
        "{refusal}"
    );
    assert!(validate_source_mode(true, true, false).is_ok());
}

#[test]
fn the_source_digest_pins_the_project_and_its_clients() {
    let root = crate::canonical_tempdir();
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
fn default_ports_lie_below_the_source_port_range() {
    for port in [
        DEFAULT_CASEWORK_PORT,
        DEFAULT_ISSUER_PORT,
        DEFAULT_DATABASE_PORT,
    ] {
        assert!(
            port < FIRST_SOURCE_PORT,
            "an outgoing connection can take default port {port} as its source port"
        );
    }
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
    let issuer_var = "CASEWORKCTL_DEV_ISSUER_PORT";
    let database_var = "CASEWORKCTL_DEV_DATABASE_PORT";
    std::env::set_var(casework_var, "19092");
    std::env::set_var(issuer_var, "19093");
    std::env::set_var(database_var, "19099");

    let parsed =
        crate::Cli::try_parse_from(["caseworkctl", "dev", "start", "/tmp/casework-project"])
            .unwrap();
    std::env::remove_var(casework_var);
    std::env::remove_var(issuer_var);
    std::env::remove_var(database_var);

    let crate::Command::Dev(dev) = parsed.command else {
        panic!("expected dev start");
    };
    let DevArgs {
        action: Some(DevAction::Start(start)),
        ..
    } = *dev
    else {
        panic!("expected dev start");
    };
    assert_eq!(start.casework_port, Some(19092));
    assert_eq!(start.issuer_port, Some(19093));
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

    let crate::Command::Dev(dev) = parsed.command else {
        panic!("expected dev start");
    };
    let DevArgs {
        action: Some(DevAction::Start(start)),
        ..
    } = *dev
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

    let crate::Command::Dev(dev) = parsed.command else {
        panic!("expected dev");
    };
    let DevArgs { start, .. } = *dev;
    assert_eq!(start.database_port, Some(19099));
}

#[test]
fn start_names_its_clients_only_with_clients_file() {
    for form in [
        vec!["caseworkctl", "dev", "start", "/tmp/casework-project"],
        vec!["caseworkctl", "dev", "/tmp/casework-project"],
    ] {
        let named = |flag: &'static str| {
            let mut arguments = form.clone();
            arguments.extend([flag, "clients.yaml"]);
            crate::Cli::try_parse_from(arguments)
        };
        assert!(named("--clients-file").is_ok(), "{form:?}");
        assert!(named("--clients").is_err(), "{form:?}");
    }
}

#[test]
fn events_reports_only_the_bounded_journal_tail() {
    let root = crate::canonical_tempdir();
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
    let root = crate::canonical_tempdir();
    let project = standalone(root.path());
    let refusal = format!("{:#}", stop(&project, false, None).unwrap_err());
    assert!(refusal.contains("nothing was stopped"), "{refusal}");
    let refusal = format!("{:#}", events(&project).unwrap_err());
    assert!(refusal.contains("nothing was stopped"), "{refusal}");
}

#[test]
fn a_first_start_without_a_clients_file_names_the_flag() {
    let root = crate::canonical_tempdir();
    let project = root.path().join("project");
    fs::create_dir(&project).unwrap();
    let refusal = format!("{:#}", clients_file(None, None, &project).unwrap_err());
    assert!(refusal.contains("--clients-file"), "{refusal}");
    assert!(refusal.contains("dev-clients.yaml"), "{refusal}");
}

#[test]
fn a_stopped_session_retains_an_explicit_equivalent_clients_file() {
    let root = crate::canonical_tempdir();
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
    record_seeded(&mut state.seeded, "decisions-team");
    state.directory_revision = 7;
    state.directory_teams = 1;
    parent_directory(&project).unwrap();
    initialize(&state.root(), &state, &captured.clients).unwrap();

    // Stop after retained-state selection, before prerequisite or service work.
    assert!(start(StartArgs {
        project: project.clone(),
        clients_file: Some(replacement.clone()),
        casework_port: None,
        issuer_port: None,
        issuer_project: None,
        database_port: None,
        source_project: Vec::new(),
        casework_bin: Some(project.join("missing-casework")),
        docker_bin: None,
        bregctl_bin: None,
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
fn an_active_session_refuses_an_equivalent_clients_file_at_a_new_path() {
    let root = crate::canonical_tempdir();
    let project = fs::canonicalize(standalone(root.path())).unwrap();
    let original_clients = fs::read(project.join("dev-clients.yaml")).unwrap();
    let replacement = project.join("replacement-clients.yaml");
    fs::write(&replacement, &original_clients).unwrap();
    let captured = capture(&project, &original_clients).unwrap();
    let mut state = session(&project);
    state.status = Status::Ready;
    state.source_digest = captured.digest;
    state.clients = captured.reported;
    parent_directory(&project).unwrap();
    initialize(&state.root(), &state, &captured.clients).unwrap();
    let control_root = control_directory(&state.root()).unwrap();
    private::directory(&control_root).unwrap();
    let socket = control_root.join("control.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 7];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"status\n");
        stream.write_all(b"ready\n").unwrap();
    });

    let refusal = format!(
        "{:#}",
        start(StartArgs {
            project: project.clone(),
            clients_file: Some(replacement),
            casework_port: None,
            issuer_port: None,
            issuer_project: None,
            database_port: None,
            source_project: Vec::new(),
            casework_bin: None,
            docker_bin: None,
            bregctl_bin: None,
        })
        .unwrap_err()
    );
    server.join().unwrap();

    assert!(
        refusal.contains("active local development session"),
        "{refusal}"
    );
    assert!(refusal.contains("stop it"), "{refusal}");
    assert!(refusal.contains("--clients-file"), "{refusal}");
    assert_eq!(
        read_state(&state.root()).unwrap().clients_file,
        state.clients_file
    );
    remove_socket(&state.root()).unwrap();
}

#[test]
fn the_report_names_every_local_credential_without_a_secret() {
    let root = crate::canonical_tempdir();
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
    assert_eq!(
        report["tokenEndpoint"],
        "http://127.0.0.1:8093/oauth2/token"
    );
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
        let root = crate::canonical_tempdir();
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
    let workspace = crate::canonical_tempdir();
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
    let workspace = crate::canonical_tempdir();
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
    let root = crate::canonical_tempdir();
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
fn retained_database_inspection_accepts_only_verified_image_aliases() {
    let root = crate::canonical_tempdir();
    let project = standalone(root.path());
    let mut state = session(&project);
    state.container_id = Some("retained-container-id".to_owned());
    let container = json!({
        "Id": "retained-container-id",
        "Name": format!("/{}", state.container_name()),
        "Config": { "Labels": { (LABEL): state.owner }, "Image": IMAGE },
    });
    for image in [CANONICAL_IMAGE, IMAGE] {
        let mut owned = container.clone();
        owned["Config"]["Image"] = json!(image);
        verified_container(&state, &owned).unwrap();
        for (pointer, replacement) in [
            ("/Name", "different-container"),
            ("/Id", "different-container-id"),
            (
                "/Config/Labels/org.registrystack.caseworkctl.dev-owner",
                "different-owner",
            ),
        ] {
            let mut changed = owned.clone();
            *changed.pointer_mut(pointer).unwrap() = json!(replacement);
            assert!(verified_container(&state, &changed).is_err());
        }
    }
    for image in [
        IMAGE.replace("67f41722", "07f41722"),
        CANONICAL_IMAGE.replace("67f41722", "07f41722"),
        format!("untrusted.example/{CANONICAL_IMAGE}"),
        "postgres:17.11".to_owned(),
        "public.ecr.aws/docker/library/postgres:17.11".to_owned(),
    ] {
        let mut changed = container.clone();
        changed["Config"]["Image"] = json!(image);
        assert!(verified_container(&state, &changed).is_err());
    }
}

#[test]
fn legacy_unlabeled_volume_requires_the_exact_retained_container_and_mount() {
    let root = crate::canonical_tempdir();
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
    let workspace = crate::canonical_tempdir();
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
    let workspace = crate::canonical_tempdir();
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
    // A supervisor that outlived its release grace would be killed instead.
    assert!(elapsed < SUPERVISOR_RELEASE_GRACE, "elapsed: {elapsed:?}");
}

fn refusal(code: &str) -> registry_casework::ActivationRefusal {
    registry_casework::ActivationRefusal {
        code: format!("casework.activation.{code}"),
        path: "database".to_owned(),
        message: format!("the {code} refusal"),
    }
}

#[test]
fn a_start_on_a_database_already_running_the_session_package_is_not_a_refusal() {
    let root = crate::canonical_tempdir();
    let already_active =
        anyhow::Error::new(registry_casework::ActivationError::Refused(vec![refusal(
            "already-active",
        )]))
        .context("applying the Casework package");
    activation_outcome(Err(already_active), root.path()).unwrap();
    activation_outcome(Ok(json!({"ok": true})), root.path()).unwrap();
}

#[test]
fn an_activation_refusal_names_its_first_code_and_the_retained_diagnostics() {
    let root = crate::canonical_tempdir();
    let refused = anyhow::Error::new(registry_casework::ActivationError::Refused(vec![
        refusal("already-active"),
        refusal("stranded-work"),
    ]))
    .context("applying the Casework package");
    let message = format!(
        "{:#}",
        activation_outcome(Err(refused), root.path()).unwrap_err()
    );
    assert!(
        message.starts_with(
            "native activation refused: casework.activation.stranded-work: the stranded-work refusal."
        ),
        "{message}"
    );
    assert!(
        message.contains("caseworkctl plan --runtime-config"),
        "{message}"
    );
    assert!(
        message.contains(&root.path().join("logs").display().to_string()),
        "{message}"
    );

    let failed = anyhow::anyhow!("the Casework migration database configuration is invalid");
    let message = format!(
        "{:#}",
        activation_outcome(Err(failed), root.path()).unwrap_err()
    );
    assert!(
        message.starts_with("native activation failed:"),
        "{message}"
    );
}

#[test]
fn database_readiness_commands_stop_at_the_aggregate_deadline() {
    let root = crate::canonical_tempdir();
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
    // Ignoring the aggregate deadline would run to the child's own
    // CHILD_DEADLINE instead.
    assert!(started.elapsed() < CHILD_DEADLINE / 2);
}

#[test]
fn interrupted_native_prerequisite_is_killed_and_reaped() {
    let root = crate::canonical_tempdir();
    private::directory(&root.path().join("logs")).unwrap();
    let marker = root.path().join("prerequisite.pid");
    let terminate = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&terminate);
    let marker_for_signal = marker.clone();
    let interrupter = thread::spawn(move || {
        let pid = announced_pid(&marker_for_signal);
        // A missed PID still interrupts, so the prerequisite is reaped
        // before the assertion below reports it.
        signal.store(true, Ordering::Relaxed);
        pid
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
    let pid = interrupter
        .join()
        .unwrap()
        .expect("prerequisite did not start");

    assert!(refusal.contains("interrupted"), "{refusal}");
    // The prerequisite never exits by itself, so only the interruption ends
    // it long before its own CHILD_DEADLINE.
    assert!(started.elapsed() < CHILD_DEADLINE / 2);
    assert!(rustix::process::test_kill_process(pid).is_err());
}

#[test]
fn native_pump_setup_failures_reap_the_child_and_join_started_pumps() {
    let root = crate::canonical_tempdir();
    private::directory(&root.path().join("logs")).unwrap();
    for fail_on in [1, 2] {
        // The child outlasts every wait below, so only cleanup can end it.
        let child = Command::new("/bin/sleep")
            .arg("180")
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
        assert!(started.elapsed() < TEST_EVENT_BOUND);
        assert_eq!(joined.load(Ordering::Relaxed), fail_on == 2);
        assert!(rustix::process::test_kill_process(pid).is_err());
    }
}

#[test]
fn failed_native_stdin_write_reaps_the_child_and_joins_pumps() {
    let root = crate::canonical_tempdir();
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
    // The child loops forever, so waiting on it would reach CHILD_DEADLINE.
    assert!(started.elapsed() < CHILD_DEADLINE / 2);
    assert!(stdout_joined.load(Ordering::Relaxed));
    assert!(stderr_joined.load(Ordering::Relaxed));
    assert!(rustix::process::test_kill_process(pid).is_err());
}

#[test]
fn active_http_prerequisite_stops_promptly_when_interrupted() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let terminate = Arc::new(AtomicBool::new(false));
    let (release, released) = mpsc::channel::<()>();
    let signal = Arc::clone(&terminate);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(TEST_EVENT_BOUND)).unwrap();
        let mut request = [0u8; 1];
        assert_eq!(stream.read(&mut request).unwrap(), 1);
        signal.store(true, Ordering::Relaxed);
        // Hold the connection open, never responding, until the client is done.
        let _ = released.recv_timeout(TEST_EVENT_BOUND);
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
    drop(release);
    server.join().unwrap();
    let refusal = format!("{:#}", result.unwrap_err());

    assert!(refusal.contains("interrupted"), "{refusal}");
    // The request timeout reports the prerequisite unavailable, not
    // interrupted, so the refusal above already shows the terminate flag won.
    // The window also covers building a fresh runtime and reqwest client,
    // which loads the system root store and slows under load, so the only
    // bound on it is the one the flag had to beat.
    assert!(elapsed < HTTP_TIMEOUT, "elapsed: {elapsed:?}");
}

#[test]
fn service_http_readiness_stops_at_the_phase_deadline() {
    let child = Command::new("/bin/sleep")
        .arg("180")
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
    // A probe handed the full request timeout would sleep through it.
    assert!(elapsed < HTTP_TIMEOUT, "elapsed: {elapsed:?}");
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
    let root = crate::canonical_tempdir();
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

    let unsafe_root = crate::canonical_tempdir();
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
    let root = crate::canonical_tempdir();
    let logs = root.path().join("logs");
    private::directory(&logs).unwrap();
    for index in 0..MAX_PREREQUISITE_LOGS {
        let mut log = log_file(root.path(), "probe").unwrap();
        writeln!(log, "diagnostic-{index}").unwrap();
    }
    let redirected = crate::canonical_tempdir();
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
    let root = crate::canonical_tempdir();
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
    let root = crate::canonical_tempdir();
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

    let swap_root = crate::canonical_tempdir();
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

    let hardlink_root = crate::canonical_tempdir();
    let hardlink_logs = hardlink_root.path().join("logs");
    private::directory(&hardlink_logs).unwrap();
    let target = hardlink_logs.join("target.log");
    private::create(&target, b"preserve me").unwrap();
    let linked = hardlink_logs.join("supervisor.log");
    fs::hard_link(&target, &linked).unwrap();
    let refusal = format!("{:#}", supervisor_log(hardlink_root.path()).unwrap_err());
    assert!(refusal.contains("single-link"), "{refusal}");
    assert_eq!(fs::read(&target).unwrap(), b"preserve me");

    let symlink_root = crate::canonical_tempdir();
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
    let root = crate::canonical_tempdir();
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
    // A graceful service's shutdown must fit inside this grace even on a
    // starved runner; a stubborn service spends all of it before forced KILL.
    let forced = guard_service_command(
        command,
        std::io::stdin(),
        Arc::clone(&interruption.requested),
        Duration::from_secs(5),
        Duration::from_secs(5),
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
    assert!(
        eventually(|| file_has_bytes(&service_pid_file)),
        "service did not become ready"
    );
    std::process::exit(23);
}

#[test]
fn guarded_service_stops_after_its_supervisor_is_killed() {
    let root = crate::canonical_tempdir();
    let binary = root.path().join("service.sh");
    fs::write(
        &binary,
        b"#!/bin/sh\nprintf '%s' \"$$\" > \"$1\"\nwhile :; do sleep 0.02; done\n",
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let service_pid_file = root.path().join("service.pid");
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
    let Some(service_pid) = announced_pid(&service_pid_file) else {
        supervisor.kill().unwrap();
        supervisor.wait().unwrap();
        panic!("guarded service did not start");
    };

    // SIGKILL skips every supervisor destructor. The kernel still closes the
    // supervisor's liveness writer, which must stop the exact guarded child.
    // The service loops forever by itself, so only that path can end it.
    supervisor.kill().unwrap();
    supervisor.wait().unwrap();
    let stopped = wait_for_process_exit(service_pid);
    if !stopped {
        rustix::process::kill_process(service_pid, rustix::process::Signal::KILL).unwrap();
    }

    assert!(stopped, "guarded service survived supervisor death");
}

#[test]
fn service_guard_owns_a_stubborn_child_during_startup_interruption() {
    let root = crate::canonical_tempdir();
    let binary = root.path().join("stubborn.sh");
    fs::write(
        &binary,
        b"#!/bin/sh\ntrap '' TERM\nprintf '%s' \"$$\" > \"$1\"\nwhile :; do sleep 0.02; done\n",
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let service_pid_file = root.path().join("service.pid");
    let marker = service_pid_file.clone();
    let (reader, writer) = UnixStream::pair().unwrap();
    let terminate = Arc::new(AtomicBool::new(false));
    let request = Arc::clone(&terminate);
    let requester = thread::spawn(move || {
        let ready = announced_pid(&marker);
        if ready.is_some() {
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
    let service_pid = requester
        .join()
        .unwrap()
        .expect("stubborn service did not reach its startup handshake");

    assert!(forced);
    assert!(wait_for_process_exit(service_pid));
}

#[test]
fn service_guard_does_not_force_kill_after_a_fast_term_exit() {
    let (reader, writer) = UnixStream::pair().unwrap();
    drop(writer);
    let mut command = Command::new("/bin/sleep");
    command.arg("180").stdin(Stdio::null());

    // `sleep` exits at once on TERM. A grace far longer than any scheduling
    // delay leaves forced KILL as the result only of ignoring that exit.
    let forced = guard_service_command(
        command,
        reader,
        Arc::new(AtomicBool::new(false)),
        TEST_EVENT_BOUND,
        TEST_EVENT_BOUND,
    )
    .unwrap();

    assert!(!forced);
}

#[test]
fn established_service_keeps_its_graceful_shutdown_window() {
    let root = crate::canonical_tempdir();
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
    if announced_pid(&service_pid_file).is_none() {
        let _ = service.stop();
        panic!("service did not reach its startup handshake");
    }

    let started = Instant::now();
    service.stop().unwrap();

    assert!(graceful.exists(), "guardian truncated graceful shutdown");
    assert!(started.elapsed() >= Duration::from_millis(150));
    // Returning early means stop followed the service's own exit rather than
    // spending its whole signal grace.
    assert!(started.elapsed() < SERVICE_SIGNAL_GRACE);
}

#[test]
fn established_stubborn_service_reports_forced_shutdown() {
    let root = crate::canonical_tempdir();
    private::directory(&root.path().join("logs")).unwrap();
    let binary = root.path().join("stubborn.sh");
    fs::write(
        &binary,
        b"#!/bin/sh\ntrap '' TERM\nprintf '%s' \"$$\" > \"$1\"\nwhile :; do sleep 0.02; done\n",
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let service_pid_file = root.path().join("service.pid");
    let mut service =
        service(&binary, &[], &service_pid_file, &[], root.path(), "guarded").unwrap();
    let Some(service_pid) = announced_pid(&service_pid_file) else {
        let _ = service.stop();
        panic!("stubborn service did not reach its startup handshake");
    };

    let refusal = format!("{:#}", service.stop().unwrap_err());

    assert!(refusal.contains("required forced shutdown"), "{refusal}");
    assert!(wait_for_process_exit(service_pid));
}

#[test]
fn killed_guard_leaves_the_supervisor_to_clean_its_exact_service_group() {
    let root = crate::canonical_tempdir();
    private::directory(&root.path().join("logs")).unwrap();
    let binary = root.path().join("stubborn.sh");
    fs::write(
        &binary,
        b"#!/bin/sh\ntrap '' TERM\nprintf '%s' \"$$\" > \"$1\"\nwhile :; do sleep 0.02; done\n",
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let service_pid_file = root.path().join("service.pid");
    let mut service =
        service(&binary, &[], &service_pid_file, &[], root.path(), "guarded").unwrap();
    let service_pid = announced_pid(&service_pid_file).expect("guarded service did not start");
    assert_eq!(
        rustix::process::getpgid(Some(service_pid)).unwrap(),
        service.guard_pgid,
        "the actual service must inherit the guard's pinned group"
    );

    rustix::process::kill_process(service.guard_pid, rustix::process::Signal::KILL).unwrap();
    assert!(
        eventually(|| service.guard_exit().unwrap().is_some()),
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
    assert!(wait_for_process_exit(service_pid));
}

#[test]
fn nonzero_guard_exit_is_detected_without_waiting_for_pump_eof() {
    let root = crate::canonical_tempdir();
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
    // The helper exits only after its service has written its PID.
    assert!(
        eventually(|| service.guard_exit().unwrap().is_some()),
        "nonzero guard did not become waitable"
    );
    let service_pid = rustix::process::Pid::from_raw(
        fs::read_to_string(&service_pid_file)
            .expect("guard did not create its service")
            .parse::<i32>()
            .unwrap(),
    )
    .unwrap();
    assert!(rustix::process::test_kill_process(service_pid).is_ok());

    // The service ignores HUP and TERM and holds the pump pipes open, so
    // waiting for pump EOF before group cleanup would never return.
    let refusal = format!(
        "{:#}",
        service
            .stop_with_grace(Duration::from_millis(50), Duration::from_millis(10))
            .unwrap_err()
    );

    assert!(refusal.contains("guard exited abnormally"), "{refusal}");
    assert!(wait_for_process_exit(service_pid));
}

#[test]
fn live_guard_timeout_kills_the_pinned_group_before_reaping() {
    let root = crate::canonical_tempdir();
    private::directory(&root.path().join("logs")).unwrap();
    let guard_binary = root.path().join("guard.sh");
    let service_pid_file = root.path().join("service.pid");
    // Publish the descendant PID from the guard that created it. This proves
    // the group member exists without depending on when that child is scheduled.
    // Both sleeps outlast every wait below, so only the group KILL ends them.
    fs::write(
        &guard_binary,
        b"#!/bin/sh\ntrap '' TERM\n/bin/sleep 180 &\nprintf '%s' \"$!\" > \"$1\"\nexec /bin/sleep 180\n",
    )
    .unwrap();
    fs::set_permissions(&guard_binary, fs::Permissions::from_mode(0o700)).unwrap();
    let mut guard = Command::new(&guard_binary);
    guard.arg(&service_pid_file);
    let mut service = service_with_guard_command(guard, root.path(), "guarded").unwrap();
    let Some(service_pid) = announced_pid(&service_pid_file) else {
        let _ = service.stop_with_grace(Duration::from_millis(75), Duration::from_millis(10));
        panic!("guarded service did not start");
    };
    assert!(rustix::process::test_kill_process(service_pid).is_ok());
    assert_eq!(
        rustix::process::getpgid(Some(service_pid)).unwrap(),
        service.guard_pgid,
        "the descendant must join the guard's pinned group"
    );
    let started = Instant::now();

    let refusal = format!(
        "{:#}",
        service
            .stop_with_grace(Duration::from_millis(75), Duration::from_millis(10))
            .unwrap_err()
    );

    assert!(refusal.contains("required forced shutdown"), "{refusal}");
    assert!(started.elapsed() >= Duration::from_millis(70));
    // Reaping before the KILL would block on the guard's own three-minute sleep.
    assert!(started.elapsed() < TEST_EVENT_BOUND);
    assert!(wait_for_process_exit(service_pid));
}

#[test]
fn post_kill_wait_is_bounded_when_a_guard_does_not_become_waitable() {
    let mut guard = Command::new("/bin/sleep")
        .arg("180")
        .process_group(0)
        .spawn()
        .unwrap();
    let guard_pid = rustix::process::Pid::from_raw(guard.id() as i32).unwrap();
    let started = Instant::now();

    // Model a kernel reporting successful group KILL without making the guard
    // waitable. Cleanup must return at its own bound instead of entering a
    // blocking Child::wait, which would last the guard's three-minute sleep.
    let refusal = format!(
        "{:#}",
        kill_guard_group_and_reap_with(&mut guard, guard_pid, Duration::from_millis(40), |_pgid| {
            Ok(())
        },)
        .unwrap_err()
    );

    assert!(refusal.contains("bounded cleanup wait"), "{refusal}");
    assert!(started.elapsed() >= Duration::from_millis(35));
    assert!(started.elapsed() < TEST_EVENT_BOUND);
    assert!(guard_exit(guard_pid).unwrap().is_none());
    rustix::process::kill_process(guard_pid, rustix::process::Signal::KILL).unwrap();
    guard.wait().unwrap();
}

#[test]
fn failed_group_kill_never_enters_a_blocking_guard_wait() {
    let mut guard = Command::new("/bin/sleep")
        .arg("180")
        .process_group(0)
        .spawn()
        .unwrap();
    let guard_pid = rustix::process::Pid::from_raw(guard.id() as i32).unwrap();
    let started = Instant::now();

    // A failed KILL must return at once. Waiting for the guard instead would
    // spend the whole post-kill grace, or the guard's three-minute sleep.
    let refusal = format!(
        "{:#}",
        kill_guard_group_and_reap_with(&mut guard, guard_pid, TEST_EVENT_BOUND, |_pgid| Err(
            anyhow::anyhow!("injected group KILL failure")
        ),)
        .unwrap_err()
    );

    assert!(refusal.contains("cannot KILL"), "{refusal}");
    assert!(refusal.contains("injected group KILL failure"), "{refusal}");
    assert!(started.elapsed() < TEST_EVENT_BOUND / 2);
    assert!(guard_exit(guard_pid).unwrap().is_none());
    rustix::process::kill_process(guard_pid, rustix::process::Signal::KILL).unwrap();
    guard.wait().unwrap();
}

#[test]
fn service_pump_setup_failures_reap_the_child_and_join_started_pumps() {
    let root = crate::canonical_tempdir();
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
        // The child waits on stdin forever, so only cleanup can end it.
        assert!(started.elapsed() < TEST_EVENT_BOUND);
        assert_eq!(joined.load(Ordering::Relaxed), fail_on == 2);
        assert!(rustix::process::test_kill_process(pid).is_err());
    }
}

#[test]
fn guardian_pump_setup_failure_reaps_a_stubborn_owned_service() {
    let root = crate::canonical_tempdir();
    let logs = root.path().join("logs");
    private::directory(&logs).unwrap();
    let binary = root.path().join("stubborn.sh");
    fs::write(
        &binary,
        b"#!/bin/sh\ntrap '' TERM\nprintf '%s' \"$$\" > \"$1\"\nwhile :; do sleep 0.02; done\n",
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let service_pid_file = root.path().join("service.pid");
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
    let mut service_pid = None;

    let refusal = format!(
        "{:#}",
        service_with_pump_spawner(child, journal, |_stream, _task| {
            service_pid = announced_pid(&service_pid_file);
            Err(std::io::Error::other("injected pump spawn failure"))
        })
        .err()
        .expect("injected guardian pump spawn must fail")
    );
    let service_pid = service_pid.expect("stubborn service did not reach its startup handshake");

    assert!(refusal.contains("output reader"), "{refusal}");
    // The service ignores TERM and loops forever, so it is gone only because
    // setup cleanup killed its group.
    assert!(rustix::process::test_kill_process(service_pid).is_err());
}

#[test]
fn seeding_administrator_token_is_issued_after_every_other_client() {
    let root = crate::canonical_tempdir();
    let project = standalone(root.path());
    let mut state = session(&project);
    let clients = Clients {
        api_version: config::DEV_CLIENTS_API_VERSION.to_owned(),
        kind: config::DEV_CLIENTS_KIND.to_owned(),
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
        integrations: None,
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
    let root = crate::canonical_tempdir();
    let project = standalone(root.path());
    let mut state = session(&project);
    let clients = Clients {
        api_version: config::DEV_CLIENTS_API_VERSION.to_owned(),
        kind: config::DEV_CLIENTS_KIND.to_owned(),
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
        integrations: None,
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
    };
    assert!(
        eventually(|| children.exited().unwrap()),
        "guard did not become waitable"
    );

    children.stop().unwrap();
    assert!(joined.load(Ordering::Relaxed));
}

#[test]
fn retained_state_of_another_shape_is_invalid_without_mutation() {
    let root = crate::canonical_tempdir();
    let project = standalone(root.path());
    let state = session(&project);
    private::directory(&project.join(".casework")).unwrap();
    private::directory(&state.root()).unwrap();
    let state_file = state.root().join("state.json");
    let current = serde_json::to_value(&state).unwrap();
    private::create(&state_file, &serde_json::to_vec(&current).unwrap()).unwrap();
    assert_eq!(read_state(&state.root()).unwrap().owner, state.owner);

    // A state an earlier caseworkctl wrote, before the envelope.
    let mut earlier_release = current.clone();
    let object = earlier_release.as_object_mut().unwrap();
    object.remove("apiVersion").unwrap();
    object.remove("kind").unwrap();
    object.insert("version".to_owned(), json!(2));
    let mut removed_version = current.clone();
    removed_version["version"] = json!(2);
    let mut later_version = current.clone();
    later_version["apiVersion"] = json!("id.registrystack.org/formats/casework/dev-state/v1alpha2");
    let mut unknown_field = current.clone();
    unknown_field["mintPort"] = json!(8081);
    let mut repeated_team = current.clone();
    repeated_team["seeded"] = json!(["decisions-team", "decisions-team"]);
    let mut null_failure = current.clone();
    null_failure["failure"] = Value::Null;
    let mut foreign_owner = current.clone();
    foreign_owner["owner"] = json!("not-an-owner");
    let mut shared_port = current.clone();
    shared_port["databasePort"] = current["caseworkPort"].clone();
    let mut cases = vec![
        (earlier_release, INVALID_STATE),
        (removed_version, INVALID_STATE),
        (later_version, INVALID_STATE),
        (unknown_field, INVALID_STATE),
        (repeated_team, INVALID_STATE),
        (null_failure, INVALID_STATE),
        (foreign_owner, STATE_OWNERSHIP),
        (shared_port, STATE_OWNERSHIP),
    ];
    for field in ["binaries", "sources", "borrowedScopes"] {
        let mut missing = current.clone();
        missing.as_object_mut().unwrap().remove(field).unwrap();
        cases.push((missing, INVALID_STATE));
    }
    for (retained, refusal) in cases {
        let bytes = serde_json::to_vec(&retained).unwrap();
        private::replace(&state_file, &bytes).unwrap();
        assert_eq!(
            read_state(&state.root()).unwrap_err().to_string(),
            refusal,
            "{retained}"
        );
        assert_eq!(fs::read(&state_file).unwrap(), bytes);
    }
}

/// `caseworkctl check` reads the session state a project retains through
/// the shared reader and holds it to the rules that hold wherever the state
/// is kept (CFG-CHECK-1, CFG-CHECK-2).
#[test]
fn check_reads_the_retained_session_state() {
    let root = crate::canonical_tempdir();
    let project = standalone(root.path());
    let mut state = session(&project);
    state.failure = Some("${NOT_SUBSTITUTED}".to_owned());
    record_seeded(&mut state.seeded, "decisions-team");
    private::directory(&project.join(".casework")).unwrap();
    private::directory(&state.root()).unwrap();
    let without_state = crate::project::check(&project, false, false).unwrap();
    state.save().unwrap();
    let state_file = state.root().join("state.json");
    let written: Value = serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
    assert_eq!(written["apiVersion"], DEV_STATE_API_VERSION);
    assert_eq!(written["kind"], DEV_STATE_KIND);
    assert!(written.get("issuerProject").is_none(), "{written}");

    let checked = crate::project::check(&project, false, false).unwrap();
    assert_eq!(
        checked["filesChecked"],
        without_state["filesChecked"].as_u64().unwrap() + 1
    );
    assert_eq!(checked["diagnostics"], json!([]));

    let refusal = |document: &Value| {
        private::replace(&state_file, &serde_json::to_vec_pretty(document).unwrap()).unwrap();
        let error = crate::project::check(&project, false, false).unwrap_err();
        crate::configuration_report(&error)
            .expect("a positioned refusal")
            .diagnostics()
            .to_vec()
    };
    let mut unknown_field = written.clone();
    unknown_field["mintPort"] = json!(8081);
    let refused = refusal(&unknown_field);
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0].code, "config.unknown-key");
    assert_eq!(refused[0].path, "/mintPort");
    let source = refused[0].source.as_ref().unwrap();
    assert_eq!(source.file, state_file.display().to_string());
    assert!(source.line.is_some() && source.column.is_some());

    let mut foreign_owner = written.clone();
    foreign_owner["owner"] = json!("foreign-owner-marker");
    let refused = refusal(&foreign_owner);
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0].code, "casework.dev-state.invalid-ownership");
    assert_eq!(refused[0].path, "");
    assert!(!format!("{refused:?}").contains("foreign-owner-marker"));
}

#[test]
fn unsafe_token_clients_are_refused_without_effects() {
    let root = crate::canonical_tempdir();
    let project = standalone(root.path());
    for id in ["../staff", "/staff", "", "staff/header"] {
        assert!(fresh_token(&project, id)
            .unwrap_err()
            .to_string()
            .contains("bounded local client"));
    }
}

#[test]
fn a_token_header_file_carries_the_bearer_and_the_registered_profile() {
    assert_eq!(
        header_file(b"header.payload.signature", Some("staff")).as_slice(),
        b"Authorization: Bearer header.payload.signature\nRegistry-Casework-Profile: staff\n"
    );
    // An integration client carries no Casework profile.
    assert_eq!(
        header_file(b"header.payload.signature", None).as_slice(),
        b"Authorization: Bearer header.payload.signature\n"
    );
}

#[test]
fn dev_token_writes_a_profile_line_only_for_a_client_bound_to_an_access_profile() {
    let temp = crate::canonical_tempdir();
    let project = fs::canonicalize(standalone(temp.path())).unwrap();

    // A local token endpoint that answers each client-assertion grant.
    let issuer = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let issuer_port = issuer.local_addr().unwrap().port();
    let token_server = thread::spawn(move || {
        let mut forms = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = issuer.accept().unwrap();
            stream.set_read_timeout(Some(TEST_EVENT_BOUND)).unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                assert!(head.len() < 32 * 1024);
                stream.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            let length = String::from_utf8(head)
                .unwrap()
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            forms.push(String::from_utf8(body).unwrap());
            let token = r#"{"access_token":"header.payload.signature","token_type":"Bearer","expires_in":300}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{token}",
                token.len()
            )
            .unwrap();
        }
        forms
    });

    // A ready session retaining one access-profile client and one
    // integration client.
    let mut state = session(&project);
    state.status = Status::Ready;
    state.issuer_port = issuer_port;
    state.clients = vec![ReportedClient {
        id: "staff".to_owned(),
        profile: "staff".to_owned(),
        role: CaseworkRole::Staff,
        principal: config::principal("staff"),
    }];
    let root = state.root();
    private::directory(&project.join(".casework")).unwrap();
    private::directory(&root).unwrap();
    private::directory(&root.join("secrets")).unwrap();
    private::directory(&root.join("credentials")).unwrap();
    state.save().unwrap();
    let mut clients = accepted(STANDALONE_DEV_CLIENTS.as_bytes());
    clients.integrations = Some(
        serde_json::from_value(json!({
            "resource":"urn:casework:source-group",
            "serviceClients":[{"id":"seed","scopes":["casework:reviews:request"]}]
        }))
        .unwrap(),
    );
    private::create(
        &root.join("clients.json"),
        &serde_json::to_vec(&clients).unwrap(),
    )
    .unwrap();
    for id in ["staff", "seed"] {
        config::keypair(&root.join("credentials").join(id)).unwrap();
    }
    let control_root = control_directory(&root).unwrap();
    private::directory(&control_root).unwrap();
    let socket = control_root.join("control.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let control_server = thread::spawn(move || {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 7];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"status\n");
            stream.write_all(b"ready\n").unwrap();
        }
    });
    let dev_token = |client: &str| {
        let crate::Command::Dev(dev) = crate::Cli::try_parse_from([
            "caseworkctl",
            "dev",
            "token",
            client,
            project.to_str().unwrap(),
        ])
        .unwrap()
        .command
        else {
            panic!("expected dev token");
        };
        run(*dev)
    };
    let header = |report: &Value| {
        let path = PathBuf::from(report["headerFile"].as_str().unwrap());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::read_to_string(path).unwrap()
    };

    let staff = dev_token("staff").unwrap();
    assert_eq!(staff["command"], "dev token");
    assert_eq!(
        header(&staff),
        "Authorization: Bearer header.payload.signature\nRegistry-Casework-Profile: staff\n"
    );

    let seed = dev_token("seed").unwrap();
    assert_eq!(
        header(&seed),
        "Authorization: Bearer header.payload.signature\n"
    );

    let refusal = format!("{:#}", dev_token("unregistered").unwrap_err());
    assert!(refusal.contains("not registered"), "{refusal}");
    assert!(!root.join("secrets/unregistered.header").exists());

    control_server.join().unwrap();
    let forms = token_server.join().unwrap();
    assert!(forms[0].contains("client_id=staff"), "{}", forms[0]);
    assert!(forms[1].contains("client_id=seed"), "{}", forms[1]);
    // The integration client is issued its own service-client scopes.
    assert!(
        forms[1].contains("scope=casework%3Areviews%3Arequest&"),
        "{}",
        forms[1]
    );
    remove_socket(&root).unwrap();
}

#[test]
fn approved_grant_requires_explicit_connection_and_refuses_policy_fields() {
    let args = [
        "caseworkctl",
        "dev",
        "grant",
        "task-agent",
        "--grant",
        "01970000-0000-7000-8000-000000000001",
        "--connection",
        "/tmp/task-connection.yaml",
        "/tmp/project",
    ];
    assert!(<crate::Cli as clap::Parser>::try_parse_from(args).is_ok());
    assert!(<crate::Cli as clap::Parser>::try_parse_from([
        "caseworkctl",
        "dev",
        "grant",
        "task-agent",
        "--grant",
        "01970000-0000-7000-8000-000000000001"
    ])
    .is_err());
    let mut arbitrary = args.to_vec();
    arbitrary.extend(["--purpose", "invented"]);
    assert!(<crate::Cli as clap::Parser>::try_parse_from(arbitrary).is_err());
}

#[test]
fn the_grant_report_carries_an_empty_diagnostics_list() {
    let report = super::grant_report("/tmp/agent.header", "2026-10-09T00:00:00Z");
    assert_eq!(report["diagnostics"], serde_json::json!([]));
    assert_eq!(report["headerFile"], "/tmp/agent.header");
}

#[test]
fn a_borrowed_session_admits_only_the_clients_its_project_declares() {
    // A borrowed session authenticates against the shared BReg owner's
    // issuer, which holds every other local project's clients as well. The
    // admitted-client list is what keeps them out of this Casework runtime,
    // and an omitted list admits all of them, so it is stated whenever the
    // project declares integrations rather than only when it adds clients of
    // its own beyond the ones it borrows.
    let workspace = crate::canonical_tempdir();
    let project = standalone(workspace.path());
    let mut policy = crate::project::load_and_check_policy(&project).unwrap();
    policy.sources.push(serde_json::from_value(json!({"id":"source","adapter":"breg","description":"source.json","requests":[{"entity":"correction","queue":"decisions"}]})).unwrap());
    let mut clients = accepted(STANDALONE_DEV_CLIENTS.as_bytes());
    let integrations: integrations::Integrations = serde_json::from_value(json!({
        "resource":"urn:casework:source-group",
        "sources":{"source":{"baseUrl":"http://127.0.0.1:8800","readerProfile":"reader",
            "tokenEndpoint":"http://127.0.0.1:8093/oauth2/token","clientAssertionAudience":"http://127.0.0.1:8093",
            "resource":"urn:casework:source-group","scopes":["records:get"],
            "clientIdRef":"secret:file/service-reader-id","clientAssertionKeyRef":"secret:file/service-reader-key",
            "webhookSecretRef":"secret:file/source-webhook","eventSource":"urn:registrystack:registry:source:instance:local"}}
    })).unwrap();
    clients.integrations = Some(integrations.clone());
    integrations.validate(&clients, &policy).unwrap();
    let mut state = session(&project);
    state.resource = Some(integrations.resource.clone());
    let mut operator = config::operator(&state);
    integrations
        .operator(&state, &clients, &mut operator)
        .unwrap();
    assert_eq!(
        operator["authentication"]["oidc"]["allowedClients"],
        json!(clients
            .clients
            .iter()
            .map(|client| client.id.clone())
            .collect::<Vec<_>>())
    );
    assert!(!operator["authentication"]["oidc"]["allowedClients"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn explicit_local_integrations_render_only_governed_authority_and_bind_the_source() {
    let workspace = crate::canonical_tempdir();
    let project = standalone(workspace.path());
    let mut policy = crate::project::load_and_check_policy(&project).unwrap();
    policy.sources.push(serde_json::from_value(json!({"id":"source","adapter":"breg","description":"source.json","requests":[{"entity":"correction","queue":"decisions"}]})).unwrap());
    let mut clients = accepted(STANDALONE_DEV_CLIENTS.as_bytes());
    let integrations: integrations::Integrations = serde_json::from_value(json!({
        "resource":"urn:casework:source-group",
        "sources":{"source":{"baseUrl":"http://127.0.0.1:8800","readerProfile":"reader",
            "tokenEndpoint":"http://127.0.0.1:8093/oauth2/token","clientAssertionAudience":"http://127.0.0.1:8093",
            "resource":"urn:casework:source-group","scopes":["records:get"],
            "clientIdRef":"secret:file/service-reader-id","clientAssertionKeyRef":"secret:file/service-reader-key",
            "webhookSecretRef":"secret:file/source-webhook","eventSource":"urn:registrystack:registry:source:instance:local"}},
        "serviceClients":[
            {"id":"reader","scopes":["records:get"]},
            {"id":"task-agent","scopes":["casework:grants:assert"],"taskExchange":true},
            {"id":"status","scopes":["casework:grants:status"]}],
        "taskAuthority":{"issuer":"https://casework.local.example","jwksPort":8801,"statusClients":{"status":"urn:casework:source-group"}}
    })).unwrap();
    clients.integrations = Some(integrations.clone());
    integrations.validate(&clients, &policy).unwrap();
    let mut state = session(&project);
    state.resource = Some(integrations.resource.clone());
    integrations.validate_session(&state, &policy).unwrap();
    let root = project.join("private");
    private::directory(&root).unwrap();
    for name in ["issuer", "secrets", "credentials"] {
        private::directory(&root.join(name)).unwrap();
    }
    let key = config::keypair(&root.join("human")).unwrap();
    let mut description = registry_thunderid_tooling::local::local_description(
        registry_thunderid_tooling::description::SessionIdentity {
            label: "source-unit".into(),
            id: "casework-local".into(),
        },
        state.issuer_port,
        root.join("issuer"),
        state.audience(),
        vec![registry_thunderid_tooling::local::LocalClient {
            client_id: "staff".into(),
            public_jwks: json!({"keys":[key]}).to_string(),
            claims: BTreeMap::new(),
            scopes: vec!["casework:staff".into()],
            allow_human_fixture: true,
        }],
    )
    .unwrap();
    integrations
        .prepare(&root, &state, Some(&mut description), &policy)
        .unwrap();
    let agent = description
        .machine_clients
        .iter()
        .find(|client| client.client_id == "task-agent")
        .unwrap();
    assert_eq!(agent.agent_id, config::principal("task-agent"));
    assert!(agent.token_exchange.is_some());
    assert_eq!(agent.attributes["registry_actor_kind"], "agent");
    assert!(!agent
        .attributes
        .keys()
        .any(|name| name.starts_with("registry_grant_")));
    let mut operator = config::operator(&state);
    integrations
        .operator(&state, &clients, &mut operator)
        .unwrap();
    assert_eq!(
        operator["taskAuthority"]["issuer"],
        "https://casework.local.example"
    );
    assert!(operator["taskAuthority"].get("id").is_none());
    // A task exchange client may present only the task authority's assertion.
    // The borrowed issuer trusts other authorities for other clients, so this
    // is what refuses their assertions here.
    assert_eq!(
        operator["authentication"]["oidc"]["assertionIssuers"],
        json!({"task-agent": ["https://casework.local.example"]})
    );
    assert_eq!(operator["sources"]["source"]["resource"], state.audience());
    assert_eq!(description.exchange_issuers.len(), 1);
    let mut wrong = integrations.clone();
    wrong.resource = "private-preflight-canary".into();
    let findings = wrong.validate(&clients, &policy).unwrap_err();
    let finding = findings
        .iter()
        .find(|finding| finding.code == "casework.dev-clients.invalid-resource")
        .expect("the resource refusal is field-addressed");
    assert_eq!(finding.pointer, "/integrations/resource");
    assert!(!format!("{findings:?}").contains("private-preflight-canary"));
    let mut wrong = integrations.clone();
    wrong.sources.get_mut("source").unwrap().resource = Some("urn:other".into());
    assert!(wrong.validate_session(&state, &policy).is_err());
    let mut wrong = integrations.clone();
    wrong
        .sources
        .get_mut("source")
        .unwrap()
        .client_assertion_audience = Some("https://other.example".into());
    assert!(wrong.validate_session(&state, &policy).is_err());
    let mut wrong = integrations.clone();
    wrong.service_clients[1].scopes.push("records:get".into());
    assert!(wrong.validate(&clients, &policy).is_err());
    let mut wrong = integrations.clone();
    wrong.service_clients[0]
        .claims
        .insert("registry_actor_kind".into(), "human".into());
    assert!(wrong.validate(&clients, &policy).is_err());
    let mut wrong = integrations.clone();
    wrong
        .sources
        .get_mut("source")
        .unwrap()
        .client_assertion_key_ref = "secret:file/service-status-key".into();
    assert!(wrong.validate_session(&state, &policy).is_err());
    let mut wrong = integrations.clone();
    wrong.service_clients[0].scopes.push("records:patch".into());
    assert!(wrong.validate_session(&state, &policy).is_err());
    // Invalid binding input never installs a partially initialized session.
    fs::write(
        project.join("casework.yaml"),
        serde_norway::to_string(&policy).unwrap(),
    )
    .unwrap();
    fs::write(project.join("source.json"), serde_json::to_vec(&json!({
        "apiVersion":"id.registrystack.org/formats/casework/breg-source-description/v1alpha1",
        "kind":"CaseworkBregSourceDescription","origin":"bregctl explain change-requests","authority":"none",
        "sourceId":"source","sourceRevision":"sha256:source",
        "requests":[{"requestEntity":"correction","requestRoute":"corrections",
            "fields":[],"contractFingerprint":"sha256:contract",
            "review":{"type":"required","authority":"casework-main","policyId":"registry-correction"},
            "onApproved":{"mode":"manual"},"application":{}}]
    })).unwrap()).unwrap();
    let client_bytes = serde_norway::to_string(&clients).unwrap();
    assert!(capture_with_sources(
        &project,
        "dev-clients.yaml",
        client_bytes.as_bytes(),
        &[],
        &BTreeMap::new()
    )
    .is_ok());
    assert!(capture_with_sources(
        &project,
        "dev-clients.yaml",
        client_bytes.as_bytes(),
        &["source=/tmp/registry".into()],
        &BTreeMap::new()
    )
    .unwrap_err()
    .to_string()
    .contains("explicit integrations"));
    let webhook = root.join("webhook-input");
    private::create(&webhook, b"synthetic-webhook-secret-at-least-32-bytes").unwrap();
    let mut staged_integrations = integrations.clone();
    staged_integrations
        .secret_files
        .insert("source-webhook".into(), webhook);
    staged_integrations
        .sources
        .get_mut("source")
        .unwrap()
        .event_source = "urn:invalid:event".into();
    clients.integrations = Some(staged_integrations);
    parent_directory(&project).unwrap();
    assert!(initialize(&state.root(), &state, &clients).is_err());
    assert!(!state.root().exists());
    clients
        .integrations
        .as_mut()
        .unwrap()
        .sources
        .get_mut("source")
        .unwrap()
        .event_source = "urn:registrystack:registry:source:instance:local".into();
    initialize(&state.root(), &state, &clients).unwrap();
    assert!(state.root().join("operator.yaml").exists());
    let mut wrong = integrations;
    wrong.sources.clear();
    assert!(wrong.validate(&clients, &policy).is_err());
}

/// The committed example `bregctl check` reads stands for the state a
/// current `bregctl dev` retains; a borrowed issuer owner it describes is
/// accepted, and the headerless state an earlier bregctl wrote is not.
#[test]
fn a_current_bregctl_dev_state_names_the_borrowed_issuer_owner() {
    let project_temp = crate::canonical_tempdir();
    let project = fs::canonicalize(project_temp.path()).unwrap();
    let owner_temp = crate::canonical_tempdir();
    let owner_project = fs::canonicalize(owner_temp.path()).unwrap();
    fs::set_permissions(&owner_project, fs::Permissions::from_mode(0o700)).unwrap();
    let owner_root = owner_project.join(".breg/dev");
    private::directory(&owner_project.join(".breg")).unwrap();
    private::directory(&owner_root).unwrap();
    let mut owner: Value = serde_json::from_str(include_str!(
        "../../../../products/breg/examples/formats/dev-session/.breg/dev/state.json"
    ))
    .unwrap();
    owner["project"] = json!(owner_project);
    let owner_id = owner["owner"].as_str().unwrap().to_owned();
    let mut state = session(&project);
    state.issuer_project = Some(owner_project.clone());
    state.issuer_owner = Some(owner_id);
    state.issuer_port = u16::try_from(owner["issuerPort"].as_u64().unwrap()).unwrap();
    private::create(
        &owner_root.join("state.json"),
        &serde_json::to_vec(&owner).unwrap(),
    )
    .unwrap();
    assert_eq!(borrowed_issuer(&state).unwrap(), Some(owner_root.clone()));

    let fields = owner.as_object_mut().unwrap();
    fields.remove("apiVersion").unwrap();
    fields.remove("kind").unwrap();
    fields.insert("version".to_owned(), json!(2));
    private::replace(
        &owner_root.join("state.json"),
        &serde_json::to_vec(&owner).unwrap(),
    )
    .unwrap();
    assert!(borrowed_issuer(&state).is_err());
}

#[test]
fn borrowed_casework_client_requires_exact_owner_claims_scopes_and_resource() {
    let project_temp = crate::canonical_tempdir();
    let project = fs::canonicalize(project_temp.path()).unwrap();
    fs::set_permissions(&project, fs::Permissions::from_mode(0o700)).unwrap();
    let owner_temp = crate::canonical_tempdir();
    let owner_project = fs::canonicalize(owner_temp.path()).unwrap();
    fs::set_permissions(&owner_project, fs::Permissions::from_mode(0o700)).unwrap();
    let owner_root = owner_project.join(".breg/dev");
    private::directory(&owner_project.join(".breg")).unwrap();
    private::directory(&owner_root).unwrap();
    private::directory(&owner_root.join("credentials")).unwrap();
    let owner_id = uuid::Uuid::new_v4().to_string();
    private::create(
        &owner_root.join("state.json"),
        &serde_json::to_vec(&json!({
            "apiVersion":"id.registrystack.org/formats/breg/dev-state/v1alpha1",
            "kind":"BRegDevState","project":owner_project,"owner":owner_id,
            "status":"ready","issuerPort":8093,"issuerProject":null
        }))
        .unwrap(),
    )
    .unwrap();
    let resource = format!("urn:breg:dev:{owner_id}");
    let scopes = vec!["casework:staff".to_owned()];
    let claims = json!({"registry_actor_kind":"human"});
    private::create(
        &owner_root.join("clients.json"),
        &serde_json::to_vec(&json!({
            "clients":[{"id":"staff","scopes":scopes,"claims":claims}],
            "issuer":{"clientResources":{}}
        }))
        .unwrap(),
    )
    .unwrap();
    let source = owner_root.join("credentials/staff");
    config::keypair(&source).unwrap();
    private::create(&source.join("client-id"), b"staff").unwrap();
    let mut state = session(&project);
    state.issuer_project = Some(owner_project);
    state.issuer_owner = Some(owner_id);
    state.resource = Some(resource.clone());
    let target = project.join("client");
    private::directory(&target).unwrap();
    config::borrow_client(&target, &state, "staff", &scopes, &claims, &resource, false).unwrap();
    assert_eq!(
        private::read(&target.join("assertion-key.jwk"), MAX_BYTES).unwrap(),
        private::read(&source.join("assertion-key.jwk"), MAX_BYTES).unwrap()
    );
    let error = config::borrow_client(
        &project.join("other"),
        &state,
        "staff",
        &scopes,
        &json!({"registry_actor_kind":"service", "private":"private-preflight-canary"}),
        &resource,
        false,
    )
    .unwrap_err();
    let (exit, diagnostic) = crate::classify_failure(crate::CommandKind::Operational, &error);
    assert_eq!(exit, crate::DOMAIN_REFUSAL_EXIT);
    assert_eq!(diagnostic["code"], "caseworkctl.dev.shared-client-mismatch");
    assert!(diagnostic["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("explicit actor"));
    assert!(!diagnostic.to_string().contains("private-preflight-canary"));
}

#[test]
fn a_borrowed_client_the_owner_registered_for_exchange_must_declare_it() {
    // An exchange client may present any assertion authority the shared
    // issuer trusts, and Casework states its per-client pairing only for the
    // task exchange clients it declares. A borrowed client the owner
    // registered for exchange without this project declaring it would be
    // admitted with no pairing to refuse the other authorities with, so the
    // two declarations must agree exactly.
    let project_temp = crate::canonical_tempdir();
    let project = fs::canonicalize(project_temp.path()).unwrap();
    fs::set_permissions(&project, fs::Permissions::from_mode(0o700)).unwrap();
    let owner_temp = crate::canonical_tempdir();
    let owner_project = fs::canonicalize(owner_temp.path()).unwrap();
    fs::set_permissions(&owner_project, fs::Permissions::from_mode(0o700)).unwrap();
    let owner_root = owner_project.join(".breg/dev");
    private::directory(&owner_project.join(".breg")).unwrap();
    private::directory(&owner_root).unwrap();
    private::directory(&owner_root.join("credentials")).unwrap();
    let owner_id = uuid::Uuid::new_v4().to_string();
    private::create(
        &owner_root.join("state.json"),
        &serde_json::to_vec(&json!({
            "apiVersion":"id.registrystack.org/formats/breg/dev-state/v1alpha1",
            "kind":"BRegDevState","project":owner_project,"owner":owner_id,
            "status":"ready","issuerPort":8093,"issuerProject":null
        }))
        .unwrap(),
    )
    .unwrap();
    let resource = format!("urn:breg:dev:{owner_id}");
    let scopes = vec!["casework:grants:assert".to_owned()];
    let claims = json!({"registry_actor_kind":"agent"});
    private::create(
        &owner_root.join("clients.json"),
        &serde_json::to_vec(&json!({
            "clients":[{"id":"task-agent","scopes":scopes,"claims":claims}],
            "issuer":{"clientResources":{},"exchangeClients":["task-agent"]}
        }))
        .unwrap(),
    )
    .unwrap();
    let source = owner_root.join("credentials/task-agent");
    config::keypair(&source).unwrap();
    private::create(&source.join("client-id"), b"task-agent").unwrap();
    let mut state = session(&project);
    state.issuer_project = Some(owner_project);
    state.issuer_owner = Some(owner_id);
    state.resource = Some(resource.clone());
    private::directory(&project.join("undeclared")).unwrap();
    let refusal = config::borrow_client(
        &project.join("undeclared"),
        &state,
        "task-agent",
        &scopes,
        &claims,
        &resource,
        false,
    )
    .unwrap_err();
    assert!(format!("{refusal:#}").contains("exchange client"));
    let (exit, diagnostic) = crate::classify_failure(crate::CommandKind::Operational, &refusal);
    assert_eq!(exit, crate::DOMAIN_REFUSAL_EXIT);
    assert_eq!(diagnostic["code"], "caseworkctl.dev.shared-client-mismatch");

    let declared = project.join("declared");
    private::directory(&declared).unwrap();
    config::borrow_client(
        &declared,
        &state,
        "task-agent",
        &scopes,
        &claims,
        &resource,
        true,
    )
    .unwrap();
}

#[test]
fn task_template_subject_follows_the_actual_local_issuer_owner() {
    let workspace = crate::canonical_tempdir();
    let project = standalone(workspace.path());
    let mut policy = crate::project::load_and_check_policy(&project).unwrap();
    let client = "task-agent";
    let owner_instance = "seed-demo-growers-local";
    policy.task_templates.push(
        serde_json::from_value(json!({
            "id":"task","version":"1","label":"Task","eligibleTeams":[],
            "eligibleProfiles":[],"source":"source","itemKinds":[],"itemStates":["claimed"],
            "agent":{"issuer":"http://127.0.0.1:8093",
                "subject":registry_thunderid_tooling::local::agent_id(owner_instance, client)},
            "client":client,"resource":"urn:casework:source-group","scopes":["records:get"],
            "purpose":"review","bounds":{"type":"breg","permissions":[
                {"collection":"records","operations":["get"]}]},
            "subjects":{},"lifetimeSeconds":900
        }))
        .unwrap(),
    );
    for profile in &mut policy.access_profiles {
        profile.principal_claim = "registry_principal".to_owned();
    }
    let clients = accepted(STANDALONE_DEV_CLIENTS.as_bytes());
    let integrations: integrations::Integrations = serde_json::from_value(json!({
        "resource":"urn:casework:source-group",
        "serviceClients":[{"id":client,"scopes":["casework:grants:assert"],"taskExchange":true}],
        "taskAuthority":{"issuer":"https://casework.local.example","jwksPort":8801,
            "statusClients":{}}
    }))
    .unwrap();
    integrations.validate(&clients, &policy).unwrap();
    let mut no_exchange = integrations.clone();
    no_exchange.service_clients[0].task_exchange = false;
    assert!(no_exchange.validate(&clients, &policy).is_err());

    let owner_temp = crate::canonical_tempdir();
    let owner_project = fs::canonicalize(owner_temp.path()).unwrap();
    fs::set_permissions(&owner_project, fs::Permissions::from_mode(0o700)).unwrap();
    let owner_root = owner_project.join(".breg/dev");
    private::directory(&owner_project.join(".breg")).unwrap();
    private::directory(&owner_root).unwrap();
    let owner_id = uuid::Uuid::new_v4().to_string();
    private::create(
        &owner_root.join("state.json"),
        &serde_json::to_vec(&json!({
            "apiVersion":"id.registrystack.org/formats/breg/dev-state/v1alpha1",
            "kind":"BRegDevState","project":owner_project,"owner":owner_id,
            "status":"ready","issuerPort":8093,"issuerProject":null,
            "instanceId":owner_instance
        }))
        .unwrap(),
    )
    .unwrap();
    let inventory = json!({
        "clients":[{"id":"owner-client","scopes":["records:get"]}],
        "issuer":{"resources":[{"audience":"urn:casework:source-group",
            "scopes":["records:get"]}],"clientResources":{}}
    });
    private::create(
        &owner_root.join("clients.json"),
        &serde_json::to_vec(&inventory).unwrap(),
    )
    .unwrap();
    let mut borrowed = session(&project);
    borrowed.issuer_project = Some(owner_project);
    borrowed.issuer_owner = Some(owner_id.clone());
    integrations.validate_session(&borrowed, &policy).unwrap();

    let mut wrong_resource = policy.clone();
    wrong_resource.task_templates[0].resource = "urn:other:resource".to_owned();
    let refusal = integrations
        .validate_session(&borrowed, &wrong_resource)
        .unwrap_err()
        .to_string();
    assert!(refusal.contains("destination resource"), "{refusal}");
    let mut default_resource = policy.clone();
    default_resource.task_templates[0].resource = format!("urn:breg:dev:{owner_id}");
    integrations
        .validate_session(&borrowed, &default_resource)
        .unwrap();
    let mut wrong_scopes = policy.clone();
    wrong_scopes.task_templates[0].scopes = vec!["records:write".to_owned()];
    let refusal = integrations
        .validate_session(&borrowed, &wrong_scopes)
        .unwrap_err()
        .to_string();
    assert!(refusal.contains("destination scopes"), "{refusal}");
    let mut sub_profile = policy.clone();
    sub_profile.access_profiles[0].principal_claim = "sub".to_owned();
    let refusal = integrations
        .validate_session(&borrowed, &sub_profile)
        .unwrap_err();
    let (exit, diagnostic) = crate::classify_failure(crate::CommandKind::Operational, &refusal);
    assert_eq!(exit, crate::DOMAIN_REFUSAL_EXIT);
    assert_eq!(
        diagnostic["code"],
        "caseworkctl.dev.borrowed-principal-invalid"
    );
    assert_eq!(
        diagnostic["path"],
        "casework.yaml:/accessProfiles/principalClaim"
    );

    let standalone = session(&project);
    assert!(integrations.validate_session(&standalone, &policy).is_err());
    policy.task_templates[0].agent.subject = config::principal(client);
    integrations.validate_session(&standalone, &policy).unwrap();
    assert!(integrations.validate_session(&borrowed, &policy).is_err());
}

#[test]
fn borrowed_browser_admission_requires_exact_owner_resource() {
    let workspace = crate::canonical_tempdir();
    let project = standalone(workspace.path());
    let mut policy = crate::project::load_and_check_policy(&project).unwrap();
    for profile in &mut policy.access_profiles {
        profile.principal_claim = "registry_principal".to_owned();
    }
    let owner_temp = crate::canonical_tempdir();
    let owner_project = fs::canonicalize(owner_temp.path()).unwrap();
    fs::set_permissions(&owner_project, fs::Permissions::from_mode(0o700)).unwrap();
    let owner_root = owner_project.join(".breg/dev");
    private::directory(&owner_project.join(".breg")).unwrap();
    private::directory(&owner_root).unwrap();
    let owner_id = uuid::Uuid::new_v4().to_string();
    private::create(
        &owner_root.join("state.json"),
        &serde_json::to_vec(&json!({
            "apiVersion":"id.registrystack.org/formats/breg/dev-state/v1alpha1",
            "kind":"BRegDevState","project":owner_project,"owner":owner_id,
            "status":"ready","issuerPort":8093,"issuerProject":null
        }))
        .unwrap(),
    )
    .unwrap();
    let resource = format!("urn:breg:dev:{owner_id}");
    let inventory = json!({
        "issuer":{"interactiveApplications":[
            {"id":"app-kit","audience":null},
            {"id":"evidence-app","audience":"urn:evidence:other"}
        ]}
    });
    private::create(
        &owner_root.join("clients.json"),
        &serde_json::to_vec(&inventory).unwrap(),
    )
    .unwrap();
    let mut state = session(&project);
    state.issuer_project = Some(owner_project);
    state.issuer_owner = Some(owner_id);
    state.resource = Some(resource.clone());
    let clients = accepted(STANDALONE_DEV_CLIENTS.as_bytes());
    let integrations: integrations::Integrations = serde_json::from_value(json!({
        "resource":resource,"browserClients":["app-kit"]
    }))
    .unwrap();
    integrations.validate(&clients, &policy).unwrap();
    let root = project.join("private");
    private::directory(&root).unwrap();
    integrations.prepare(&root, &state, None, &policy).unwrap();
    let mut operator = config::operator(&state);
    integrations
        .operator(&state, &clients, &mut operator)
        .unwrap();
    assert!(operator["authentication"]["oidc"]["allowedClients"]
        .as_array()
        .unwrap()
        .iter()
        .any(|id| id == "app-kit"));
    let mut wrong = integrations;
    wrong.browser_clients = vec!["evidence-app".into()];
    assert!(wrong.prepare(&root, &state, None, &policy).is_err());
}

#[test]
fn a_borrowed_task_authority_connection_pairs_the_task_exchange_clients() {
    // The owner derives each exchange client's allowed assertion authority
    // from the connection it is paired with. A task client the owner paired
    // with one of its other connections would reach the owner's resource
    // servers as that authority's, so the pairing is read here and not only
    // the connection itself.
    let workspace = crate::canonical_tempdir();
    let project = standalone(workspace.path());
    let mut policy = crate::project::load_and_check_policy(&project).unwrap();
    for profile in &mut policy.access_profiles {
        profile.principal_claim = "registry_principal".to_owned();
    }
    let owner_temp = crate::canonical_tempdir();
    let owner_project = fs::canonicalize(owner_temp.path()).unwrap();
    fs::set_permissions(&owner_project, fs::Permissions::from_mode(0o700)).unwrap();
    let owner_root = owner_project.join(".breg/dev");
    private::directory(&owner_project.join(".breg")).unwrap();
    private::directory(&owner_root).unwrap();
    let owner_id = uuid::Uuid::new_v4().to_string();
    private::create(
        &owner_root.join("state.json"),
        &serde_json::to_vec(&json!({
            "apiVersion":"id.registrystack.org/formats/breg/dev-state/v1alpha1",
            "kind":"BRegDevState","project":owner_project,"owner":owner_id,
            "status":"ready","issuerPort":8093,"issuerProject":null
        }))
        .unwrap(),
    )
    .unwrap();
    let resource = format!("urn:breg:dev:{owner_id}");
    let mut state = session(&project);
    state.issuer_project = Some(owner_project);
    state.issuer_owner = Some(owner_id);
    state.resource = Some(resource.clone());
    let clients = accepted(STANDALONE_DEV_CLIENTS.as_bytes());
    let integrations: integrations::Integrations = serde_json::from_value(json!({
        "resource":resource,
        "serviceClients":[
            {"id":"task-agent","scopes":["casework:grants:assert"],"taskExchange":true}],
        "taskAuthority":{"issuer":"https://casework.local.example","jwksPort":8801,
            "statusClients":{}}
    }))
    .unwrap();
    integrations.validate(&clients, &policy).unwrap();
    let root = project.join("private");
    private::directory(&root).unwrap();
    for name in ["issuer", "secrets", "credentials"] {
        private::directory(&root.join(name)).unwrap();
    }
    let inventory = owner_root.join("clients.json");
    for paired in [json!([]), json!(["other-agent"]), json!(["task-agent"])] {
        if inventory.exists() {
            fs::remove_file(&inventory).unwrap();
        }
        private::create(
            &inventory,
            &serde_json::to_vec(&json!({"issuer":{"exchangeIssuers":[{
                "issuer":"https://casework.local.example",
                "jwksEndpoint":"http://host.docker.internal:8801/oauth2/jwks",
                "mapping":"institutional-grant","clients":paired
            }]}}))
            .unwrap(),
        )
        .unwrap();
        let refusal = integrations
            .prepare(&root, &state, None, &policy)
            .unwrap_err();
        // The exact pairing passes this check and stops at the borrowed client
        // registration the owner has not written, which is the next check.
        let expected = if paired == json!(["task-agent"]) {
            "shared issuer owner has no registration for task-agent"
        } else {
            "shared issuer owner must pre-register the exact Casework task authority connection"
        };
        assert!(
            format!("{refusal:#}").contains(expected),
            "{paired}: {refusal}"
        );
        let (_, diagnostic) = crate::classify_failure(crate::CommandKind::Operational, &refusal);
        assert_eq!(
            diagnostic["code"],
            if paired == json!(["task-agent"]) {
                "caseworkctl.dev.shared-client-mismatch"
            } else {
                "caseworkctl.dev.shared-task-authority-mismatch"
            }
        );
    }
}

struct RegistrySession {
    _root: tempfile::TempDir,
    executable: PathBuf,
    project: PathBuf,
    calls: PathBuf,
}

impl RegistrySession {
    fn create_project(root: &Path, name: &str) -> PathBuf {
        let project = root.join(name);
        fs::create_dir(&project).unwrap();
        fs::write(
            project.join("registry.yaml"),
            serde_json::to_vec(&json!({
                "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
                "kind": "BRegProject",
                "project": {"id": "professional-licences"},
                "package": {}
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            project.join(".fixture-token-endpoint"),
            "http://127.0.0.1:8191/oauth2/token",
        )
        .unwrap();
        fs::write(project.join(".fixture-audience"), "urn:breg:dev:fixture").unwrap();
        fs::write(project.join(".fixture-credential"), "shared-key").unwrap();
        fs::canonicalize(project).unwrap()
    }

    fn new() -> Self {
        let root = crate::canonical_tempdir();
        let project = Self::create_project(root.path(), "registry");
        let executable = root.path().join("bregctl");
        fs::write(
            &executable,
            br#"#!/bin/sh
set -eu
fixture=$(dirname "$0")
printf '%s
' "$*" >> "$fixture/calls"
project=""
client=""
id_file=""
key_file=""
while [ $# -gt 0 ]; do
    case "$1" in
        export-client) project=$2; shift 2;;
        --client) client=$2; shift 2;;
        --client-id-file) id_file=$2; shift 2;;
        --assertion-key-file) key_file=$2; shift 2;;
        *) shift;;
    esac
done
audience=$(cat "$project/.fixture-audience")
token_endpoint=$(cat "$project/.fixture-token-endpoint")
credential=$(cat "$project/.fixture-credential")
case "$client" in
  casework-reader) scopes='["casework:source-reader"]';;
  administrator) scopes='["casework:admin"]';;
  supervisor) scopes='["casework:supervisor","starter:reviewer"]';;
  staff) scopes='["casework:staff","starter:reviewer"]';;
  requester) scopes='["casework:request"]';;
  integration-requester) scopes='["casework:reviews:request"]';;
  *) scopes='["casework:fixture"]';;
esac
umask 077
printf '%s' "$client" > "$id_file"
printf '{"kty":"EC","fixture":"%s"}' "$credential" > "$key_file"
issuer=${token_endpoint%/oauth2/token}
printf '{"ok":true,"command":"dev export-client","client":"%s","bregUrl":"http://127.0.0.1:8090","tokenEndpoint":"%s","clientAssertionAudience":"%s","resource":"%s","audience":"%s","scopes":%s}
' "$client" "$token_endpoint" "$issuer" "$audience" "$audience" "$scopes"
"#,
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            calls: root.path().join("calls"),
            _root: root,
            executable,
            project,
        }
    }

    fn add_project(&self, name: &str) -> PathBuf {
        Self::create_project(self._root.path(), name)
    }

    fn calls(&self) -> Vec<String> {
        fs::read_to_string(&self.calls)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn set_audience(project: &Path, audience: &str) {
        fs::write(project.join(".fixture-audience"), audience).unwrap();
    }

    fn set_credentials(project: &Path, credential: &str) {
        fs::write(project.join(".fixture-credential"), credential).unwrap();
    }
}

fn prepare_source_export_destinations(state: &State, clients: &Clients) {
    let root = state.root();
    for directory in ["credentials", "secrets"] {
        private::directory(&root.join(directory)).unwrap();
    }
    for client in &clients.clients {
        private::directory(&root.join("credentials").join(&client.id)).unwrap();
    }
}

fn retained_credential_canaries(state: &State, clients: &Clients) -> BTreeMap<PathBuf, Vec<u8>> {
    let root = state.root();
    let mut canaries = BTreeMap::new();
    for client in &clients.clients {
        let directory = root.join("credentials").join(&client.id);
        for (name, bytes) in [
            ("client-id", b"RETAINED-CLIENT-ID".as_slice()),
            (
                "assertion-key.jwk",
                b"RETAINED-CLIENT-ASSERTION-KEY".as_slice(),
            ),
        ] {
            let path = directory.join(name);
            private::create(&path, bytes).unwrap();
            canaries.insert(path, bytes.to_vec());
        }
    }
    for id in state.sources.keys() {
        for (suffix, bytes) in [
            ("reader-client-id", b"RETAINED-READER-ID".as_slice()),
            (
                "reader-assertion-key.jwk",
                b"RETAINED-READER-ASSERTION-KEY".as_slice(),
            ),
            ("webhook-key", b"RETAINED-WEBHOOK-KEY".as_slice()),
        ] {
            let path = root.join("secrets").join(format!("{id}-{suffix}"));
            private::create(&path, bytes).unwrap();
            canaries.insert(path, bytes.to_vec());
        }
    }
    canaries
}

#[test]
fn binding_a_source_exports_the_reader_and_every_person_from_the_registry_session() {
    let workspace = crate::canonical_tempdir();
    let project = workspace.path().join("project");
    crate::project::init(&project, "professional-review").unwrap();
    let registry = RegistrySession::new();
    let mut state = persisted_session(&project);
    let root = state.root();
    let clients = accepted(&fs::read(project.join("dev-clients.yaml")).unwrap());
    for directory in ["credentials", "secrets"] {
        private::directory(&root.join(directory)).unwrap();
    }
    for client in &clients.clients {
        private::directory(&root.join("credentials").join(&client.id)).unwrap();
    }
    state.sources.insert(
        "professional-licences".into(),
        SourceSession {
            project: registry.project.clone(),
            binding: None,
        },
    );

    export_sources(&registry.executable, &mut state, &clients).unwrap();

    let binding = state.sources["professional-licences"]
        .binding
        .as_ref()
        .unwrap();
    assert_eq!(binding.breg_url, "http://127.0.0.1:8090");
    assert_eq!(binding.token_endpoint, "http://127.0.0.1:8191/oauth2/token");
    assert_eq!(binding.audience, "urn:breg:dev:fixture");
    assert_eq!(
        binding.event_source,
        "urn:registrystack:registry:professional-licences:instance:professional-licences"
    );
    assert_eq!(
        fs::read_to_string(root.join("secrets/professional-licences-reader-client-id")).unwrap(),
        "casework-reader"
    );
    assert!(file_has_bytes(
        &root.join("secrets/professional-licences-reader-assertion-key.jwk")
    ));
    let webhook =
        fs::read_to_string(root.join("secrets/professional-licences-webhook-key")).unwrap();
    assert_eq!(webhook.len(), 64);
    for client in &clients.clients {
        let directory = root.join("credentials").join(&client.id);
        assert_eq!(
            fs::read_to_string(directory.join("client-id")).unwrap(),
            client.id
        );
        assert!(file_has_bytes(&directory.join("assertion-key.jwk")));
    }
    let calls = registry.calls();
    assert_eq!(calls.len(), 1 + clients.clients.len(), "{calls:?}");
    let prefix = format!(
        "--format json dev export-client {} --client ",
        registry.project.display()
    );
    assert!(
        calls[0].starts_with(&format!("{prefix}casework-reader ")),
        "{}",
        calls[0]
    );
    for client in &clients.clients {
        assert!(
            calls
                .iter()
                .any(|call| call.starts_with(&format!("{prefix}{} ", client.id))),
            "{calls:?}"
        );
    }
    // The retained state carries the binding across restarts.
    assert_eq!(
        read_state(&root).unwrap().sources["professional-licences"].binding,
        state.sources["professional-licences"].binding
    );

    // A restart exports the pairs again instead of refusing the retained copies.
    export_sources(&registry.executable, &mut state, &clients).unwrap();
    assert_eq!(registry.calls().len(), 2 * (1 + clients.clients.len()));
    assert_eq!(
        webhook,
        fs::read_to_string(root.join("secrets/professional-licences-webhook-key")).unwrap()
    );
}

#[test]
fn incompatible_source_issuers_leave_retained_credentials_unchanged() {
    let workspace = crate::canonical_tempdir();
    let project = workspace.path().join("project");
    crate::project::init(&project, "professional-review").unwrap();
    let registry = RegistrySession::new();
    let other_registry = registry.add_project("other-registry");
    RegistrySession::set_audience(&other_registry, "urn:breg:dev:other");
    let mut state = persisted_session(&project);
    let clients = accepted(&fs::read(project.join("dev-clients.yaml")).unwrap());
    state.sources.insert(
        "alpha".into(),
        SourceSession {
            project: registry.project.clone(),
            binding: None,
        },
    );
    state.sources.insert(
        "beta".into(),
        SourceSession {
            project: other_registry,
            binding: None,
        },
    );
    state.save().unwrap();
    prepare_source_export_destinations(&state, &clients);
    let canaries = retained_credential_canaries(&state, &clients);
    let retained_state = fs::read(state.root().join("state.json")).unwrap();

    let refusal = format!(
        "{:#}",
        export_sources(&registry.executable, &mut state, &clients).unwrap_err()
    );

    assert!(refusal.contains("different local issuers"), "{refusal}");
    assert_eq!(
        fs::read(state.root().join("state.json")).unwrap(),
        retained_state
    );
    for (path, bytes) in canaries {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    assert!(state
        .sources
        .values()
        .all(|source| source.binding.is_none()));
}

#[test]
fn sources_need_the_same_shared_casework_client_credentials() {
    let workspace = crate::canonical_tempdir();
    let project = workspace.path().join("project");
    crate::project::init(&project, "professional-review").unwrap();
    let registry = RegistrySession::new();
    let other_registry = registry.add_project("other-registry");
    RegistrySession::set_credentials(&other_registry, "other-key");
    let mut state = persisted_session(&project);
    let clients = accepted(&fs::read(project.join("dev-clients.yaml")).unwrap());
    state.sources.insert(
        "alpha".into(),
        SourceSession {
            project: registry.project.clone(),
            binding: None,
        },
    );
    state.sources.insert(
        "beta".into(),
        SourceSession {
            project: other_registry,
            binding: None,
        },
    );
    state.save().unwrap();
    prepare_source_export_destinations(&state, &clients);
    let canaries = retained_credential_canaries(&state, &clients);
    let retained_state = fs::read(state.root().join("state.json")).unwrap();

    let refusal = format!(
        "{:#}",
        export_sources(&registry.executable, &mut state, &clients).unwrap_err()
    );

    assert!(refusal.contains("sources alpha and beta"), "{refusal}");
    assert!(
        refusal.contains("different credentials for Casework client"),
        "{refusal}"
    );
    assert_eq!(
        fs::read(state.root().join("state.json")).unwrap(),
        retained_state
    );
    for (path, bytes) in canaries {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    assert!(state
        .sources
        .values()
        .all(|source| source.binding.is_none()));
}

#[test]
fn two_sources_can_share_one_registry_client_registration() {
    let workspace = crate::canonical_tempdir();
    let project = workspace.path().join("project");
    crate::project::init(&project, "professional-review").unwrap();
    let registry = RegistrySession::new();
    let mut state = persisted_session(&project);
    let clients = accepted(&fs::read(project.join("dev-clients.yaml")).unwrap());
    for id in ["alpha", "beta"] {
        state.sources.insert(
            id.into(),
            SourceSession {
                project: registry.project.clone(),
                binding: None,
            },
        );
    }
    state.save().unwrap();
    prepare_source_export_destinations(&state, &clients);

    export_sources(&registry.executable, &mut state, &clients).unwrap();

    assert!(state
        .sources
        .values()
        .all(|source| source.binding.is_some()));
    for id in state.sources.keys() {
        assert_eq!(
            fs::read_to_string(
                state
                    .root()
                    .join("secrets")
                    .join(format!("{id}-reader-client-id"))
            )
            .unwrap(),
            "casework-reader"
        );
    }
    for client in &clients.clients {
        let directory = state.root().join("credentials").join(&client.id);
        assert_eq!(
            fs::read_to_string(directory.join("client-id")).unwrap(),
            client.id
        );
        assert_eq!(
            fs::read_to_string(directory.join("assertion-key.jwk")).unwrap(),
            r#"{"kty":"EC","fixture":"shared-key"}"#
        );
    }
    assert_eq!(registry.calls().len(), 2 * (1 + clients.clients.len()));
    assert_eq!(read_state(&state.root()).unwrap().sources, state.sources);
}

#[test]
fn active_source_revalidation_refuses_rotated_credentials_without_replacement() {
    let workspace = crate::canonical_tempdir();
    let project = workspace.path().join("project");
    crate::project::init(&project, "professional-review").unwrap();
    let registry = RegistrySession::new();
    let mut state = persisted_session(&project);
    let clients = accepted(&fs::read(project.join("dev-clients.yaml")).unwrap());
    state.sources.insert(
        "professional-licences".into(),
        SourceSession {
            project: registry.project.clone(),
            binding: None,
        },
    );
    state.save().unwrap();
    prepare_source_export_destinations(&state, &clients);
    private::create(
        &state.root().join("clients.json"),
        &serde_json::to_vec(&clients).unwrap(),
    )
    .unwrap();
    export_sources(&registry.executable, &mut state, &clients).unwrap();
    let mut retained = BTreeMap::new();
    for client in &clients.clients {
        for name in ["client-id", "assertion-key.jwk"] {
            let path = state.root().join("credentials").join(&client.id).join(name);
            retained.insert(path.clone(), fs::read(path).unwrap());
        }
    }
    for suffix in ["reader-client-id", "reader-assertion-key.jwk"] {
        let path = state
            .root()
            .join("secrets")
            .join(format!("professional-licences-{suffix}"));
        retained.insert(path.clone(), fs::read(path).unwrap());
    }

    RegistrySession::set_credentials(&registry.project, "rotated-key");
    let refusal = require_active_source_bindings(&registry.executable, &state)
        .unwrap_err()
        .to_string();

    assert!(
        refusal.contains("earlier BREG reader registration"),
        "{refusal}"
    );
    for (path, bytes) in retained {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}

#[test]
fn a_start_stops_waiting_on_in_process_work_once_termination_is_requested() {
    let terminate = AtomicBool::new(false);
    assert_eq!(until_finished(|| 7, &terminate).unwrap(), 7);

    // Work blocked as an apply waiting on a database lock is: only a
    // released channel would ever let it finish.
    let (release, blocked) = mpsc::channel::<()>();
    let started = Instant::now();
    let error = thread::scope(|scope| {
        scope.spawn(|| {
            thread::sleep(Duration::from_millis(50));
            terminate.store(true, Ordering::Relaxed);
        });
        until_finished(move || blocked.recv(), &terminate).unwrap_err()
    });
    assert!(
        error.to_string().contains("local start interrupted"),
        "{error}"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(release);
}

/// Runs statements, or one query, against the dedicated test database.
#[cfg(feature = "postgres-test")]
fn in_test_database<T>(url: &str, work: impl AsyncFnOnce(&tokio_postgres::Client) -> T) -> T {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    runtime.block_on(async {
        let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
            .await
            .expect("connect dedicated test database");
        let connection = tokio::spawn(connection);
        let result = work(&client).await;
        drop(client);
        connection
            .await
            .expect("test connection task")
            .expect("test connection");
        result
    })
}

#[cfg(feature = "postgres-test")]
#[test]
fn a_retained_split_session_start_leaves_the_ledgers_read_only_to_the_runtime() {
    let base = std::env::var("CASEWORK_TEST_DATABASE_URL")
        .expect("CASEWORK_TEST_DATABASE_URL is required for the real PostgreSQL test");
    // A schema and a runtime role of its own, so this test never races a
    // suite that resets the public schema of the same database.
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let schema = format!("caseworkctl_split_{suffix}");
    let role = format!("caseworkctl_split_{suffix}");
    let password = uuid::Uuid::new_v4().simple().to_string();
    in_test_database(&base, async |client| {
        client
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; CREATE ROLE {role} LOGIN PASSWORD '{password}'"
            ))
            .await
            .expect("test schema and runtime role");
    });
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped = |url: &str| format!("{url}{separator}options=-csearch_path%3D{schema}");
    let (_, host) = base
        .split_once('@')
        .expect("test URL names its credentials");
    let migration_url = scoped(&base);
    let runtime_url = scoped(&format!("postgresql://{role}:{password}@{host}"));

    let root = crate::canonical_tempdir();
    let project = standalone(root.path());
    let state = session(&project);
    let session_root = state.root();
    for directory in [
        session_root.clone(),
        session_root.join("database"),
        session_root.join("secrets"),
        session_root.join("audit"),
    ] {
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::set_permissions(project.join(".casework"), fs::Permissions::from_mode(0o700)).unwrap();
    for (name, bytes) in [
        ("secrets/runtime-database-url", runtime_url.as_str()),
        ("secrets/migration-database-url", migration_url.as_str()),
        ("secrets/casework-audit-key", &"0".repeat(64)),
        // The marker a session retained from a split-role release keeps.
        ("database/runtime-password", password.as_str()),
    ] {
        private::create(&session_root.join(name), bytes.as_bytes()).unwrap();
    }
    let mut operator = config::operator(&state);
    operator["database"] = json!({
        "runtimeUrlRef": "secret:file/runtime-database-url",
        "migrationUrlRef": "secret:file/migration-database-url",
        "testOnlyPlaintext": true,
    });
    config::write_yaml(&session_root.join("operator.yaml"), &operator).unwrap();
    package_session(&session_root, &project).unwrap();
    // The first start activates the package, and a retained restart finds it
    // already active under the same role observation.
    for _ in 0..2 {
        activate_session(&session_root, &AtomicBool::new(false)).unwrap();
    }
    let writes: Vec<(String, bool)> = in_test_database(&base, async |client| {
        client
            .query(
                "SELECT t, has_any_column_privilege($1, format('%I.%I', $2::text, t), 'INSERT')
                   OR has_table_privilege($1, format('%I.%I', $2::text, t), 'UPDATE, DELETE, TRUNCATE')
                 FROM unnest(ARRAY['casework_activations', 'casework_schema_migrations']) AS t",
                &[&role, &schema],
            )
            .await
            .expect("ledger privileges")
            .into_iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect()
    });
    assert_eq!(
        writes,
        vec![
            ("casework_activations".to_owned(), false),
            ("casework_schema_migrations".to_owned(), false),
        ]
    );
}

/// Run `caseworkctl --format json dev start` through the command entry point
/// and return its exit code, its parsed report, and the raw report text.
fn json_dev_start(project: &Path, extra: &[&str]) -> (std::process::ExitCode, Value, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let arguments = ["caseworkctl", "--format", "json", "dev", "start"]
        .into_iter()
        .map(OsString::from)
        .chain(std::iter::once(project.as_os_str().to_owned()))
        .chain(extra.iter().map(OsString::from));
    let exit = crate::main_entry_from(arguments, &mut stdout, &mut stderr);
    let text = String::from_utf8(stdout).unwrap();
    let report = serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{error}: {text}{}", String::from_utf8_lossy(&stderr)));
    (exit, report, text)
}

/// A free loopback port, released before it is returned.
fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A stopped retained session whose inputs match the authored project, as a
/// first start leaves it.
fn retained_session(project: &Path) -> State {
    let clients = fs::read(project.join("dev-clients.yaml")).unwrap();
    let captured = capture(project, &clients).unwrap();
    let mut state = session(project);
    state.source_digest = captured.digest.clone();
    state.clients = captured.reported;
    parent_directory(project).unwrap();
    initialize(&state.root(), &state, &captured.clients).unwrap();
    state
}

#[test]
fn a_start_on_an_occupied_port_names_the_port() {
    let root = crate::canonical_tempdir();
    let project = fs::canonicalize(standalone(root.path())).unwrap();
    let occupied = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = occupied.local_addr().unwrap().port();
    let (issuer, database) = (free_port(), free_port());

    let (exit, report, _) = json_dev_start(
        &project,
        &[
            "--casework-port",
            &port.to_string(),
            "--issuer-port",
            &issuer.to_string(),
            "--database-port",
            &database.to_string(),
        ],
    );

    assert_eq!(exit, std::process::ExitCode::from(3), "{report}");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(
        diagnostic["code"], "caseworkctl.dev.port-occupied",
        "{report}"
    );
    assert_eq!(diagnostic["artifact"], "dev-session");
    assert_eq!(diagnostic["path"], format!("dev:/ports/{port}"));
    assert_eq!(
        diagnostic["message"],
        format!("Local port {port} is already in use by another process.")
    );
    assert!(
        diagnostic["suggestedAction"]
            .as_str()
            .unwrap()
            .contains("--casework-port"),
        "{report}"
    );
    drop(occupied);
}

#[test]
fn an_edited_project_over_retained_records_names_dev_stop_remove() {
    let root = crate::canonical_tempdir();
    let project = fs::canonicalize(standalone(root.path())).unwrap();
    let mut state = retained_session(&project);
    state.container_id = Some("a".repeat(64));
    state.save().unwrap();
    fs::write(
        project.join("casework.yaml"),
        format!("{STANDALONE_YAML}# edited after the first start\n"),
    )
    .unwrap();

    let (exit, report, _) = json_dev_start(&project, &[]);

    assert_eq!(exit, std::process::ExitCode::from(3), "{report}");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(
        diagnostic["code"], "caseworkctl.dev.inputs-changed",
        "{report}"
    );
    assert_eq!(diagnostic["artifact"], "dev-session");
    assert_eq!(diagnostic["path"], ".casework/dev");
    assert!(
        diagnostic["message"]
            .as_str()
            .unwrap()
            .contains("differ from the retained development session"),
        "{report}"
    );
    assert!(
        diagnostic["suggestedAction"]
            .as_str()
            .unwrap()
            .contains("caseworkctl dev stop --remove"),
        "{report}"
    );
    assert_eq!(read_state(&state.root()).unwrap().owner, state.owner);
}

/// The first line a release before the shared JSONL audit streams wrote to
/// its hash-chained journal: `envelope_id`, `prev_hash`, and `record_hash`,
/// none of which the shared stream's envelope carries.
const EARLIER_RELEASE_AUDIT_LINE: &str = "{\"envelope_id\":\"01J000000000000000000000\",\
    \"timestamp_unix_ms\":0,\"prev_hash\":null,\"record\":{},\"record_hash\":\"sha256:00\"}\n";

#[test]
fn a_retained_audit_stream_from_an_earlier_release_names_the_directory_to_move() {
    let root = crate::canonical_tempdir();
    let project = fs::canonicalize(standalone(root.path())).unwrap();
    let state = retained_session(&project);
    let audit = state.root().join("audit/casework.ndjson");
    private::create(&audit, EARLIER_RELEASE_AUDIT_LINE.as_bytes()).unwrap();
    let missing = project.join("missing-casework");

    let (exit, report, text) =
        json_dev_start(&project, &["--casework-bin", missing.to_str().unwrap()]);

    assert_eq!(exit, std::process::ExitCode::from(3), "{report}");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(
        diagnostic["code"], "caseworkctl.dev.audit-format-unsupported",
        "{report}"
    );
    assert_eq!(diagnostic["artifact"], "dev-session");
    assert_eq!(diagnostic["path"], ".casework/dev/audit");
    let message = diagnostic["message"].as_str().unwrap();
    assert!(message.contains(".casework/dev/audit"), "{report}");
    assert!(message.contains("earlier caseworkctl release"), "{report}");
    let action = diagnostic["suggestedAction"].as_str().unwrap();
    assert!(action.contains("Move .casework/dev/audit"), "{report}");
    assert!(action.contains("dev stop --remove to discard"), "{report}");
    assert!(!text.contains(root.path().to_str().unwrap()), "{text}");
    // Naming the cause changes nothing retained.
    assert_eq!(
        fs::read(&audit).unwrap(),
        EARLIER_RELEASE_AUDIT_LINE.as_bytes()
    );
}

#[test]
fn a_retained_audit_directory_the_runtime_cannot_open_is_named() {
    let root = crate::canonical_tempdir();
    let project = fs::canonicalize(standalone(root.path())).unwrap();
    let state = retained_session(&project);
    let audit = state.root().join("audit");
    fs::set_permissions(&audit, fs::Permissions::from_mode(0o777)).unwrap();
    let missing = project.join("missing-casework");

    let (exit, report, text) =
        json_dev_start(&project, &["--casework-bin", missing.to_str().unwrap()]);

    assert_eq!(exit, std::process::ExitCode::from(3), "{report}");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(
        diagnostic["code"], "caseworkctl.dev.audit-unavailable",
        "{report}"
    );
    assert_eq!(diagnostic["path"], ".casework/dev/audit");
    assert!(!text.contains(root.path().to_str().unwrap()), "{text}");
}

#[test]
fn dev_stop_remove_clears_the_retained_audit_directory() {
    let root = crate::canonical_tempdir();
    let project = fs::canonicalize(standalone(root.path())).unwrap();
    let state = retained_session(&project);
    let audit = state.root().join("audit");
    private::create(
        &audit.join("casework.ndjson"),
        EARLIER_RELEASE_AUDIT_LINE.as_bytes(),
    )
    .unwrap();
    let docker = DockerInventory::new(&state);

    stop(&project, true, Some(&docker.executable)).unwrap();

    // The audit described records the removal discarded; an empty owner-only
    // directory is what the next start appends a fresh stream to.
    private::check(&audit, true).unwrap();
    assert_eq!(fs::read_dir(&audit).unwrap().count(), 0);
    retained_audit(&state).unwrap();
}

#[test]
fn dev_stop_keeps_the_retained_audit_directory() {
    let root = crate::canonical_tempdir();
    let project = fs::canonicalize(standalone(root.path())).unwrap();
    let state = retained_session(&project);
    let stream = state.root().join("audit/casework.ndjson");
    private::create(&stream, EARLIER_RELEASE_AUDIT_LINE.as_bytes()).unwrap();
    let docker = DockerInventory::new(&state);

    stop(&project, false, Some(&docker.executable)).unwrap();

    assert_eq!(
        fs::read(&stream).unwrap(),
        EARLIER_RELEASE_AUDIT_LINE.as_bytes()
    );
}

#[test]
fn dev_stop_remove_refuses_an_audit_directory_that_leaves_the_session() {
    let root = crate::canonical_tempdir();
    let project = fs::canonicalize(standalone(root.path())).unwrap();
    let state = retained_session(&project);
    let outside = root.path().join("outside");
    private::directory(&outside).unwrap();
    private::create(&outside.join("kept"), b"kept").unwrap();
    let audit = state.root().join("audit");
    fs::remove_dir(&audit).unwrap();
    std::os::unix::fs::symlink(&outside, &audit).unwrap();
    let docker = DockerInventory::new(&state);

    let refusal = format!(
        "{:#}",
        stop(&project, true, Some(&docker.executable)).unwrap_err()
    );

    assert!(refusal.contains("retained audit directory"), "{refusal}");
    assert!(fs::symlink_metadata(&audit).unwrap().is_symlink());
    assert_eq!(fs::read(outside.join("kept")).unwrap(), b"kept");
}

#[test]
fn a_failed_supervised_start_names_the_log_directory_without_its_cause() {
    let root = crate::canonical_tempdir();
    let dev_root = root.path().join("project/.casework/dev");
    let secret = "postgres://casework:hunter2-secret@127.0.0.1:55433/casework";
    let error = start_failure(
        Some(&format!("native activation failed: {secret}")),
        &dev_root,
    )
    .context("bearer eyJhbGciOiJub25lIn0.secret-token");
    assert!(format!("{error:#}").contains("hunter2"));

    let (exit, diagnostic) = crate::classify_failure(crate::CommandKind::Operational, &error);

    assert_eq!(exit, 3);
    assert_eq!(diagnostic["code"], "caseworkctl.dev.start-failed");
    assert_eq!(diagnostic["artifact"], "dev-session");
    assert_eq!(diagnostic["path"], ".casework/dev/logs");
    let rendered = diagnostic.to_string();
    assert!(
        rendered.contains(".casework/dev/logs/casework.log"),
        "{rendered}"
    );
    // A start that fails before the runtime launches (database, issuer, or
    // activation) records its cause only in the supervisor log.
    let action = diagnostic["suggestedAction"].as_str().unwrap();
    assert!(
        action.starts_with("Read .casework/dev/logs/supervisor.log"),
        "{action}"
    );
    for leaked in ["hunter2", "secret-token", root.path().to_str().unwrap()] {
        assert!(!rendered.contains(leaked), "{leaked} leaked: {rendered}");
    }
}

#[test]
fn a_first_bridged_source_start_checks_the_audit_before_the_bridge_writes_its_configuration() {
    let workspace = crate::canonical_tempdir();
    let project = workspace.path().join("project");
    crate::project::init(&project, "professional-review").unwrap();
    let project = fs::canonicalize(project).unwrap();
    let policy = crate::project::load_and_check_policy(&project).unwrap();
    let description = project.join(&policy.sources[0].description);
    fs::create_dir_all(description.parent().unwrap()).unwrap();
    fs::write(&description, b"synthetic source description").unwrap();
    let registry = RegistrySession::new();
    // A directory is refused by name as the casework executable, the first
    // prerequisite the start locates after its audit check.
    let not_executable = workspace.path().join("casework");
    fs::create_dir(&not_executable).unwrap();

    let refusal = start(StartArgs {
        project: project.clone(),
        clients_file: None,
        casework_port: Some(free_port()),
        issuer_port: None,
        issuer_project: None,
        database_port: Some(free_port()),
        source_project: vec![format!(
            "professional-licences={}",
            registry.project.display()
        )],
        casework_bin: Some(not_executable),
        docker_bin: None,
        bregctl_bin: Some(registry.executable.clone()),
    })
    .unwrap_err();

    // The bridge writes the operator configuration only after the start has
    // located its prerequisites, so the audit check must not need that file:
    // this start gets past it to the casework prerequisite.
    assert!(!project.join(".casework/dev/operator.yaml").exists());
    assert!(
        format!("{refusal:#}").contains("installed executable must be a regular file"),
        "{refusal:#}"
    );
}

/// The suggested action for a retained audit stream the writer refuses for
/// a reason other than its format, after `arrange` prepares the stream.
fn audit_unavailable_action(arrange: impl FnOnce(&Path)) -> String {
    let root = crate::canonical_tempdir();
    let project = fs::canonicalize(standalone(root.path())).unwrap();
    let state = retained_session(&project);
    arrange(&state.root().join("audit"));
    let missing = project.join("missing-casework");

    let (exit, report, text) =
        json_dev_start(&project, &["--casework-bin", missing.to_str().unwrap()]);

    assert_eq!(exit, std::process::ExitCode::from(3), "{report}");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(
        diagnostic["code"], "caseworkctl.dev.audit-unavailable",
        "{report}"
    );
    assert!(!text.contains(root.path().to_str().unwrap()), "{text}");
    diagnostic["suggestedAction"].as_str().unwrap().to_owned()
}

#[test]
fn a_retained_audit_refusal_permissions_cannot_repair_names_moving_the_directory() {
    // A torn final line whose side file already holds other bytes.
    let conflicting_side_file = audit_unavailable_action(|audit| {
        private::create(&audit.join("casework.ndjson"), b"{").unwrap();
        private::create(&audit.join("casework.ndjson.torn"), b"other").unwrap();
    });
    // An audit stream that is a symbolic link.
    let symlinked_stream = audit_unavailable_action(|audit| {
        let outside = audit.parent().unwrap().parent().unwrap().join("elsewhere");
        private::create(&outside, b"").unwrap();
        std::os::unix::fs::symlink(&outside, audit.join("casework.ndjson")).unwrap();
    });

    for action in [conflicting_side_file, symlinked_stream] {
        assert!(action.contains("regular files"), "{action}");
        assert!(
            action.contains("move .casework/dev/audit out of the project"),
            "{action}"
        );
    }
}

#[test]
fn an_interrupted_start_the_supervisor_did_not_record_is_reported_directly() {
    let root = crate::canonical_tempdir();
    let project = fs::canonicalize(standalone(root.path())).unwrap();
    let mut state = retained_session(&project);
    state.status = Status::Starting;
    state.save().unwrap();
    // A supervisor that ends on the signal without recording a cause.
    let mut supervisor = Command::new("sleep").arg("60").spawn().unwrap();

    let error = interrupted_start(&state.root(), &mut supervisor).unwrap_err();
    let (exit, diagnostic) = crate::classify_failure(crate::CommandKind::Operational, &error);

    assert_eq!(exit, 3);
    assert_eq!(diagnostic["code"], "caseworkctl.dev.start-failed");
    let rendered = diagnostic.to_string();
    assert!(rendered.contains("interrupted"), "{rendered}");
    // The interruption is this terminal's own record, never the supervisor's.
    assert!(!rendered.contains("supervisor.log"), "{rendered}");
    assert!(
        !rendered.contains(root.path().to_str().unwrap()),
        "{rendered}"
    );
}

#[test]
fn a_port_bind_refused_for_another_reason_is_not_reported_as_occupied() {
    let refused = bind_failure(8092, std::io::ErrorKind::PermissionDenied.into());
    let occupied = bind_failure(8092, std::io::ErrorKind::AddrInUse.into());

    let (exit, diagnostic) = crate::classify_failure(crate::CommandKind::Operational, &refused);

    assert_eq!(exit, 3);
    assert_eq!(diagnostic["code"], "caseworkctl.io-failure", "{diagnostic}");
    assert_eq!(
        crate::classify_failure(crate::CommandKind::Operational, &occupied).1["code"],
        "caseworkctl.dev.port-occupied"
    );
}

#[test]
fn borrowed_principals_and_invalid_source_bindings_have_specific_safe_diagnostics() {
    let workspace = crate::canonical_tempdir();
    let project = standalone(workspace.path());
    let mut policy = crate::project::load_and_check_policy(&project).unwrap();
    for profile in &mut policy.access_profiles {
        profile.principal_claim = "registry_principal".into();
    }
    config::require_stable_borrowed_principals(&policy).unwrap();
    policy.access_profiles[0].principal_claim = "sub".into();
    let error = config::require_stable_borrowed_principals(&policy).unwrap_err();
    let (exit, diagnostic) = crate::classify_failure(crate::CommandKind::Operational, &error);
    assert_eq!(exit, crate::DOMAIN_REFUSAL_EXIT);
    assert_eq!(
        diagnostic["code"],
        "caseworkctl.dev.borrowed-principal-invalid"
    );
    assert_eq!(
        diagnostic["path"],
        "casework.yaml:/accessProfiles/principalClaim"
    );
    assert!(diagnostic["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("Do not use sub"));

    let error =
        integrations::source_binding_failure(registry_casework_core::SourceAdapterError::Invalid);
    let (exit, diagnostic) = crate::classify_failure(crate::CommandKind::Operational, &error);
    assert_eq!(exit, crate::DOMAIN_REFUSAL_EXIT);
    assert_eq!(diagnostic["code"], "caseworkctl.dev.source-binding-invalid");
    assert_eq!(diagnostic["path"], "dev-clients.yaml:/integrations/sources");
    let error = integrations::source_binding_failure(
        registry_casework_core::SourceAdapterError::Unavailable,
    );
    assert!(error
        .downcast_ref::<registry_casework_core::SourceAdapterError>()
        .is_some());
    let (exit, diagnostic) = crate::classify_failure(crate::CommandKind::Operational, &error);
    assert_eq!(exit, crate::OPERATIONAL_FAILURE_EXIT);
    assert_eq!(diagnostic["code"], "caseworkctl.operational-failure");
}
