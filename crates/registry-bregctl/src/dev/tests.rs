#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]
// SPDX-License-Identifier: Apache-2.0
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_config::{FileSecretProviderConfig, SecretProvidersConfig, SecretReference};

#[test]
fn rehearsal_token_provider_omits_empty_scopes_and_preserves_explicit_scopes() {
    let endpoint = url::Url::parse("https://issuer.example.test/oauth2/token").unwrap();
    let key = registry_platform_crypto::generate_private_jwk(
        registry_platform_crypto::GeneratedKeyAlgorithm::Ed25519,
    )
    .unwrap();
    let resource = "https://registry.example.test";

    let unscoped = dev_token_provider(
        endpoint.clone(),
        "operator".to_owned(),
        key.clone(),
        "https://issuer.example.test",
        resource,
        Vec::new(),
    )
    .expect("an omitted optional scope parameter is valid");
    assert_eq!(
        unscoped.configured_resource_and_scopes(),
        (Some(resource), &[][..])
    );

    let requested = vec!["registry:records:read".to_owned()];
    let scoped = dev_token_provider(
        endpoint,
        "reader".to_owned(),
        key,
        "https://issuer.example.test",
        resource,
        requested.clone(),
    )
    .expect("an explicit nonempty scope remains configured");
    assert_eq!(
        scoped.configured_resource_and_scopes(),
        (Some(resource), requested.as_slice())
    );
}

pub(super) fn fixture() -> (tempfile::TempDir, State, Clients, BTreeMap<String, Vec<u8>>) {
    let temporary = tempfile::tempdir().expect("temporary");
    let project = fs::canonicalize(temporary.path()).expect("canonical");
    fs::set_permissions(&project, fs::Permissions::from_mode(0o700)).unwrap();
    let parent = project.join(".breg");
    private::directory(&parent).expect("private");
    let clients = config::clients(
        "dev-clients.yaml",
        br#"apiVersion: id.registrystack.org/formats/breg/dev-clients/v1alpha1
kind: BRegDevClients
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
        api_version: state_api_version(),
        kind: state_kind(),
        project: project.clone(),
        owner: uuid::Uuid::new_v4().to_string(),
        status: Status::Stopped,
        breg_port: 8094,
        issuer_port: 8095,
        issuer_project: None,
        issuer_owner: None,
        issuer_image: None,
        purpose_port: None,
        database_port: 55448,
        requires_postgis: false,
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
        package_digest: None,
        activated: false,
        seeded: UniqueList::default(),
        seed_import_authorities: BTreeMap::new(),
        seed_import_intents: BTreeMap::new(),
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

/// Enables a file secret provider rooted at a private directory inside
/// `project` and returns that root.
pub(super) fn secret_root(project: &Path, clients: &mut Clients) -> PathBuf {
    let root = project.join("secrets");
    private::directory(&root).unwrap();
    clients.secret_providers = Some(SecretProvidersConfig {
        file: Some(FileSecretProviderConfig { root: root.clone() }),
        environment: None,
    });
    root
}

/// Writes one owner-only secret file under `root` and returns its reference.
pub(super) fn file_secret(root: &Path, name: &str, bytes: &[u8]) -> SecretReference {
    private::create(&root.join(name), bytes).unwrap();
    SecretReference::parse(format!("secret:file/{name}")).unwrap()
}

#[test]
fn initialization_keeps_distinct_keys_and_private_state_without_service_dependencies() {
    let (_temp, state, clients, files) = fixture();
    initialize(&state.root(), &state, &clients, &files).expect("initialize");
    let root = state.root();
    private::validate_tree(&root).expect("all generated state is private");
    let issuer_state = fs::read_dir(root.join("issuer"))
        .expect("the upstream issuer session state exists")
        .count();
    assert!(issuer_state > 0);
    let server_file = fs::read_dir(root.join("issuer/resources/resource_servers"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let server: Value =
        serde_norway::from_slice(&private::read(&server_file, MAX_BYTES).unwrap()).unwrap();
    let resources = server["resources"].as_array().unwrap();
    assert!(
        resources.iter().any(|resource| {
            resource["handle"] == "registry"
                && resource["parent"].is_null()
                && resource["actions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|action| action["handle"] == "generic:operate")
        }),
        "three-segment authored scopes retain their exact permission under one resource"
    );
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
    assert!(operator.len() > 32);
    assert!(source != operator);
    assert!(source != operator);
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
fn the_dev_registry_serves_with_one_role_and_its_rehearsal_stays_split() {
    let (_temp, state, clients, files) = fixture();
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let root = state.root();
    private::directory(&root.join("build")).unwrap();
    private::directory(&root.join("build/package")).unwrap();
    config::runtime(&root, &state, &clients, false).unwrap();
    let served: Value =
        serde_norway::from_slice(&private::read(&root.join("runtime.yaml"), MAX_BYTES).unwrap())
            .unwrap();
    assert_eq!(served["database"]["roles"]["migration"], MIGRATION_ROLE);
    assert_eq!(served["database"]["roles"]["runtime"], MIGRATION_ROLE);
    assert_eq!(
        served["database"]["runtimeUrlRef"],
        "secret:file/migration-database-url"
    );
    assert_eq!(
        served["database"]["migrationUrlRef"],
        "secret:file/migration-database-url"
    );
    // The schema-test rehearsal computes the package fingerprint, which is
    // defined against a separate runtime role.
    let rehearsal: Value = serde_norway::from_slice(
        &private::read(&root.join("runtime-test.yaml"), MAX_BYTES).unwrap(),
    )
    .unwrap();
    assert_eq!(rehearsal["database"]["roles"]["runtime"], RUNTIME_ROLE);
    assert_eq!(
        rehearsal["database"]["runtimeUrlRef"],
        "secret:file/test-runtime-database-url"
    );
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
    // `bregctl dev` runs the local session as the registry's one instance and
    // needs one client per profile the journeys use, so the project `bregctl
    // init` writes must satisfy both with its own clients file: a reader's
    // first start needs no edit between the two commands.
    let (_temporary, project) = write_init_project();
    let client_bytes = fs::read(project.join("dev-clients.yaml")).expect("init writes clients");
    let clients =
        config::clients("dev-clients.yaml", &client_bytes).expect("the initialized clients parse");
    let captured = capture(&project, &client_bytes).expect("a fresh init project is a dev project");
    assert_eq!(captured.instance_id, "generic-registry");
    bind_journey_profiles(&captured.files["tests/journeys.yaml"], &clients)
        .expect("every journey profile has a client");
}

#[test]
fn the_professional_licences_submitter_is_a_person_a_paired_review_can_exclude() {
    // The paired `professional-review` Casework template excludes a change
    // request's initiator from its review, and BReg names an initiator only
    // for a human caller. A service submitter would have its review refused.
    let client_bytes = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/starters/professional-licences/core/dev-clients.yaml"),
    )
    .expect("the starter's clients");
    let clients =
        config::clients("dev-clients.yaml", &client_bytes).expect("the starter's clients parse");
    let submitter = clients
        .clients
        .iter()
        .find(|client| {
            client
                .access_profiles
                .iter()
                .any(|profile| profile == "editor")
        })
        .expect("the editor profile has a local client");
    assert_eq!(
        submitter.claims.get("registry_actor_kind"),
        Some(&serde_json::json!("human"))
    );
    assert!(submitter.allow_human_fixture);
}

#[test]
fn the_generated_clients_header_names_the_teaching_bindings_section() {
    // The header explains the one binding it generates and points at the
    // section that documents the explicit binding it does not generate, so a
    // reader who needs `testBindings` finds it without reading the source.
    let header = String::from_utf8_lossy(crate::INIT_DEV_CLIENTS).into_owned();
    for fact in ["testBindings", "'Explicit teaching clients'", "DEV.md"] {
        assert!(
            header.contains(fact),
            "dev-clients.yaml header omits {fact}"
        );
    }
}

#[test]
fn a_journey_profile_without_a_client_is_refused_before_any_service_starts() {
    let (_temporary, project) = write_init_project();
    let client_bytes = br#"apiVersion: id.registrystack.org/formats/breg/dev-clients/v1alpha1
kind: BRegDevClients
clients:
  - id: operator
    accessProfiles: [operator]
    scopes: [registry:generic:operate]
    claims:
      registry_principal: generic-registry-operator
      registry_purpose: registry-operations
"#;
    let clients = config::clients("dev-clients.yaml", client_bytes).expect("clients");
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
    assert!(config::clients("dev-clients.yaml", &serde_json::to_vec(&value).unwrap()).is_err());
    value["clients"][1]["accessProfiles"] = json!(["evidence-source"]);
    value["clients"][1]["secret"] = json!("must-not-be-accepted");
    assert!(config::clients("dev-clients.yaml", &serde_json::to_vec(&value).unwrap()).is_err());
}

/// A client may bind no access profile. Such a client still needs its own
/// unique ID and explicit scopes; it is provisioned at the dev token issuer but
/// excluded from BReg's `allowedClients`, and no journey or seed can resolve it.
#[test]
fn clients_accept_an_explicitly_unbound_profile_free_client() {
    let clients = config::clients(
        "dev-clients.yaml",
        br#"apiVersion: id.registrystack.org/formats/breg/dev-clients/v1alpha1
kind: BRegDevClients
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
    assert!(!guest.allow_breg_access);
}

#[test]
fn profile_free_clients_need_explicit_breg_access_to_authenticate() {
    let (_temp, state, mut clients, files) = fixture();
    clients.clients.push(config::Client {
        id: "guest".into(),
        access_profiles: vec![],
        allow_breg_access: false,
        allow_human_fixture: false,
        scopes: vec!["registry:generic:introspect".into()],
        claims: BTreeMap::new(),
        test_bindings: Vec::new(),
        assertion_key_ref: None,
    });
    clients.clients.push(config::Client {
        id: "casework-reviewer".into(),
        access_profiles: vec![],
        allow_breg_access: true,
        allow_human_fixture: false,
        scopes: vec!["registry:generic:review".into()],
        claims: BTreeMap::from([("registry_actor_kind".into(), json!("agent"))]),
        test_bindings: Vec::new(),
        assertion_key_ref: None,
    });
    clients.clients.push(config::Client {
        id: "casework-administrator".into(),
        access_profiles: vec![],
        allow_breg_access: false,
        allow_human_fixture: true,
        scopes: vec!["casework:admin".into()],
        claims: BTreeMap::from([("registry_actor_kind".into(), json!("human"))]),
        test_bindings: Vec::new(),
        assertion_key_ref: None,
    });
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let root = state.root();
    let issuer = config::issuer_description(&state, &clients, &root).unwrap();
    for (id, actor_kind) in [
        ("operator", "service"),
        ("guest", "service"),
        ("casework-reviewer", "agent"),
        ("casework-administrator", "human"),
    ] {
        let client = issuer
            .machine_clients
            .iter()
            .find(|client| client.client_id == id)
            .expect("each authored client is registered");
        assert_eq!(client.attributes["registry_actor_kind"], actor_kind);
    }
    let runtime: Value = serde_norway::from_slice(
        &private::read(&root.join("runtime-test.yaml"), MAX_BYTES).unwrap(),
    )
    .unwrap();
    let allowed = runtime["authentication"]["oidc"]["allowedClients"]
        .as_array()
        .expect("allowedClients is an array");
    assert!(
        !allowed.iter().any(|id| id == "guest"),
        "the unbound client must be absent from allowedClients: {allowed:?}"
    );
    assert!(
        allowed.iter().any(|id| id == "casework-reviewer"),
        "the explicitly admitted integration client must be allowed: {allowed:?}"
    );
    assert!(
        !allowed.iter().any(|id| id == "casework-administrator"),
        "a teaching-human flag must not confer BREG access: {allowed:?}"
    );
    assert!(
        clients
            .clients
            .iter()
            .filter(|client| !client.access_profiles.is_empty())
            .all(|client| allowed.iter().any(|id| id == &client.id)),
        "each profile-bound client remains in allowedClients: {allowed:?}"
    );
}

/// The runtime refuses an empty `allowedClients`. A session whose only
/// clients are outside BReg admission names no client, so its runtime file
/// carries the keyword the runtime reads as every client of the local issuer.
#[test]
fn a_session_naming_no_breg_client_writes_the_unrestricted_keyword() {
    let (_temp, state, mut clients, files) = fixture();
    for client in &mut clients.clients {
        client.access_profiles.clear();
        client.allow_breg_access = false;
    }
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let runtime: Value = serde_norway::from_slice(
        &private::read(&state.root().join("runtime-test.yaml"), MAX_BYTES).unwrap(),
    )
    .unwrap();
    assert_eq!(
        runtime["authentication"]["oidc"]["allowedClients"],
        "unrestricted"
    );
}

#[test]
fn multi_purpose_client_has_one_registration_and_one_bounded_exchange_connection() {
    let (_temp, mut state, mut clients, files) = fixture();
    state.purpose_port = Some(18_092);
    let operator = clients
        .clients
        .iter_mut()
        .find(|client| client.id == "operator")
        .unwrap();
    operator.claims.insert(
        "registry_purpose".into(),
        json!(["record-change", "record-read"]),
    );
    operator
        .claims
        .insert("registry_record_status".into(), json!("active"));
    let clients = config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap();
    initialize(&state.root(), &state, &clients, &files).unwrap();

    let description = config::issuer_description(&state, &clients, &state.root()).unwrap();
    assert_eq!(
        description
            .machine_clients
            .iter()
            .filter(|client| client.client_id == "operator")
            .count(),
        1
    );
    let operator = description
        .machine_clients
        .iter()
        .find(|client| client.client_id == "operator")
        .unwrap();
    assert_eq!(operator.attributes["registry_purpose"], "record-change");
    assert_eq!(operator.attributes["registry_actor_kind"], "service");
    assert!(operator.token_exchange.is_some());
    let purpose = description
        .exchange_issuers
        .iter()
        .find(|issuer| issuer.name == "Local purpose assertion authority")
        .unwrap();
    assert_eq!(purpose.clients, ["operator"]);
    assert_eq!(purpose.token_attributes.len(), 5);
    assert!(purpose.token_attributes.contains_key("registry_actor_kind"));
    assert!(purpose.token_attributes.contains_key("registry_principal"));
    assert!(purpose.token_attributes.contains_key("registry_purpose"));
    assert!(purpose
        .token_attributes
        .contains_key("registry_record_status"));
    assert!(purpose.token_attributes.contains_key("scope"));
    let runtime: Value = serde_norway::from_slice(
        &private::read(&state.root().join("runtime-test.yaml"), MAX_BYTES).unwrap(),
    )
    .unwrap();
    assert_eq!(
        runtime["authentication"]["oidc"]["allowedClients"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|id| *id == "operator")
            .count(),
        1
    );
    assert_eq!(
        runtime["authentication"]["oidc"]["assertionIssuers"]["operator"],
        json!(["http://127.0.0.1:18092"])
    );
}

#[test]
fn multi_purpose_claim_union_is_refused_above_the_issuer_attribute_limit() {
    // Every multi-purpose client shares one generated first-party connection,
    // which projects the union of their claim names plus the reserved
    // registry_purpose and scope. The issuer bounds that union, so each client
    // being within its own 32-claim bound is not enough.
    let (_temp, _state, base, _files) = fixture();
    let mut clients = base.clone();
    for client in &mut clients.clients {
        client.claims.insert(
            "registry_purpose".into(),
            json!(["record-change", "record-read"]),
        );
    }
    let (operator, source) = clients.clients.split_at_mut(1);
    for index in 0..7 {
        operator[0]
            .claims
            .insert(format!("operator_claim_{index}"), json!("value"));
    }
    for index in 0..5 {
        source[0]
            .claims
            .insert(format!("source_claim_{index}"), json!("value"));
    }
    // registry_actor_kind, registry_principal, registry_purpose, scope, and
    // twelve distinct authored claims: exactly the limit.
    config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap();
    clients.clients[1]
        .claims
        .insert("source_claim_5".into(), json!("value"));
    let refusal = config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap_err()
    .to_string();
    assert!(refusal.contains("at most 16"), "{refusal}");
    assert!(refusal.contains("multi-purpose"), "{refusal}");
}

#[test]
fn multi_purpose_client_is_refused_on_any_authored_exchange_connection() {
    // A multi-purpose client is always paired with the generated purpose
    // connection, and the issuer lets a first-party client select one signer.
    // That pairing makes the client a first-party client, so its exchanged
    // tokens carry only the purpose connection's claims: through an
    // institutional grant connection they would lack the registry_grant_*
    // claims the registry requires, and through another first-party
    // connection they would lack that connection's claims.
    let (_temp, _state, base, _files) = fixture();
    for mapping in [
        config::IssuerConnectionMapping::InstitutionalGrant,
        config::IssuerConnectionMapping::FirstParty,
    ] {
        let mut clients = pair_exchange_client(base.clone(), mapping);
        config::clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&clients).unwrap().into_bytes(),
        )
        .unwrap();
        clients
            .clients
            .iter_mut()
            .find(|client| client.id == "source")
            .unwrap()
            .claims
            .insert(
                "registry_purpose".into(),
                json!(["evidence-source-read", "evidence-source-audit"]),
            );
        let refusal = config::clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&clients).unwrap().into_bytes(),
        )
        .unwrap_err()
        .to_string();
        assert!(refusal.contains("client source"), "{refusal}");
        assert!(
            refusal.contains("exchange connection casework"),
            "{refusal}"
        );
        assert!(
            refusal.contains("more than one registry_purpose"),
            "{refusal}"
        );
    }
}

#[test]
fn owner_issuer_pre_registers_shared_resources_exchange_and_browser_identity() {
    let (_temp, state, mut clients, files) = fixture();
    let secrets = secret_root(&state.project, &mut clients);
    config::keypair(&secrets).unwrap();
    let source = clients
        .clients
        .iter_mut()
        .find(|client| client.id == "source")
        .unwrap();
    source.assertion_key_ref =
        Some(SecretReference::parse("secret:file/assertion-key.jwk").unwrap());
    source
        .claims
        .insert("evidence_tags".into(), json!(["policy-one"]));
    let app_secret = file_secret(
        &secrets,
        "portal-secret",
        b"synthetic-portal-secret-for-test",
    );
    let user_secret = file_secret(
        &secrets,
        "staff-password",
        b"synthetic-staff-password-for-test",
    );
    clients.issuer.resources.push(config::IssuerResource {
        audience: "urn:evidence:dev:synthetic".into(),
        scopes: vec!["registry:evidence:lookup".into()],
    });
    clients
        .issuer
        .client_resources
        .insert("source".into(), "urn:evidence:dev:synthetic".into());
    clients
        .issuer
        .exchange_issuers
        .push(config::IssuerConnection {
            id: "casework".into(),
            issuer: "https://casework.example.test".into(),
            jwks_endpoint: "https://casework.example.test/oauth2/jwks".into(),
            mapping: config::IssuerConnectionMapping::FirstParty,
            clients: vec!["source".into()],
            token_attributes: [(
                "registry_principal".into(),
                registry_thunderid_tooling::description::ExchangeAttributeKind::String,
            )]
            .into(),
        });
    clients.issuer.exchange_clients.push("source".into());
    clients
        .issuer
        .interactive_applications
        .push(config::BrowserApplication {
            id: "portal".into(),
            client_secret_ref: app_secret.clone(),
            origin: "http://127.0.0.1:3000".into(),
            redirect_uris: vec!["http://127.0.0.1:3000/callback".into()],
            audience: None,
            grants: vec![config::LocalPermissionGrant {
                audience: None,
                scopes: vec!["registry:generic:operate".into()],
            }],
            token_attributes: vec!["registry_actor_kind".into()],
        });
    clients
        .issuer
        .interactive_applications
        .push(config::BrowserApplication {
            id: "evidence-portal".into(),
            client_secret_ref: app_secret.clone(),
            origin: "http://127.0.0.1:3001".into(),
            redirect_uris: vec!["http://127.0.0.1:3001/callback".into()],
            audience: Some("urn:evidence:dev:synthetic".into()),
            grants: vec![config::LocalPermissionGrant {
                audience: Some("urn:evidence:dev:synthetic".into()),
                scopes: vec!["registry:evidence:lookup".into()],
            }],
            token_attributes: vec!["registry_actor_kind".into()],
        });
    clients.issuer.synthetic_users.push(config::BrowserUser {
        username: "staff".into(),
        email: "staff@example.test".into(),
        password_ref: user_secret,
        attributes: BTreeMap::from([("registry_actor_kind".into(), "human".into())]),
        grants: vec![config::LocalPermissionGrant {
            audience: None,
            scopes: vec!["registry:generic:operate".into()],
        }],
    });
    let mut ungranted = clients.clone();
    ungranted.issuer.interactive_applications[0].grants[0]
        .scopes
        .push("undeclared:permission".into());
    assert!(config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&ungranted).unwrap().into_bytes()
    )
    .is_err());
    config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap();
    let mut wrong_resource_scope = clients.clone();
    wrong_resource_scope
        .clients
        .iter_mut()
        .find(|client| client.id == "source")
        .unwrap()
        .scopes = vec!["registry:generic:operate".into()];
    let refusal = config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&wrong_resource_scope)
            .unwrap()
            .into_bytes(),
    )
    .unwrap_err()
    .to_string();
    assert!(refusal.contains("resource scopes"), "{refusal}");
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let description = config::issuer_description(&state, &clients, &state.root()).unwrap();
    let portal = &description.exchange_issuers[0];
    assert_eq!(portal.clients, vec!["source"]);
    assert_eq!(
        portal.token_attributes["registry_principal"],
        registry_thunderid_tooling::description::ExchangeAttributeKind::String
    );
    let evidence = description
        .resource_servers
        .iter()
        .find(|server| server.identifier == "urn:evidence:dev:synthetic")
        .unwrap();
    let source_role = description
        .roles
        .iter()
        .find(|role| {
            role.assigned_agents
                .contains(&registry_thunderid_tooling::local::agent_id(
                    &state.instance_id,
                    "source",
                ))
        })
        .unwrap();
    assert_eq!(source_role.permissions[0].0, evidence.id);
    assert!(description
        .machine_clients
        .iter()
        .find(|client| client.client_id == "source")
        .unwrap()
        .token_exchange
        .is_some());
    assert_eq!(
        description
            .machine_clients
            .iter()
            .find(|client| client.client_id == "source")
            .unwrap()
            .attributes["evidence_tags"],
        json!(["policy-one"])
    );
    assert_eq!(description.interactive_applications[0].client_id, "portal");
    assert!(description.roles.iter().any(|role| {
        role.assigned_applications
            .contains(&description.interactive_applications[0].id)
            && role.permissions[0].1 == ["registry:generic:operate"]
    }));
    assert!(description.roles.iter().any(|role| {
        role.assigned_users
            .contains(&description.synthetic_users[0].id)
            && role.permissions[0].1 == ["registry:generic:operate"]
    }));
    let runtime: Value = serde_norway::from_slice(
        &private::read(&state.root().join("runtime-test.yaml"), MAX_BYTES).unwrap(),
    )
    .unwrap();
    let allowed = runtime["authentication"]["oidc"]["allowedClients"]
        .as_array()
        .unwrap();
    assert!(allowed.iter().any(|id| id == "portal"));
    assert!(!allowed.iter().any(|id| id == "evidence-portal"));
    // The owner publishes the per-client assertion authority rule its resource
    // servers enforce, derived from the connections each client is registered
    // against. Every declared exchange client is registered against at least
    // one connection, so each one reaches this map.
    assert_eq!(
        runtime["authentication"]["oidc"]["assertionIssuers"],
        json!({"source": ["https://casework.example.test"]})
    );
    config::check_borrowed_browser_clients(
        &clients,
        &["portal".into()],
        &state.audience(),
        &state.audience(),
    )
    .unwrap();
    assert!(config::check_borrowed_browser_clients(
        &clients,
        &["evidence-portal".into()],
        &state.audience(),
        &state.audience(),
    )
    .is_err());
    assert!(config::check_borrowed_browser_clients(
        &clients,
        &["unknown".into()],
        &state.audience(),
        &state.audience(),
    )
    .is_err());
    assert_eq!(description.synthetic_users[0].username, "staff");
    assert_eq!(
        private::read(
            &state.root().join("credentials/source/assertion-key.jwk"),
            MAX_BYTES
        )
        .unwrap(),
        private::read(&secrets.join("assertion-key.jwk"), MAX_BYTES).unwrap()
    );
}

fn pair_exchange_client(mut clients: Clients, mapping: config::IssuerConnectionMapping) -> Clients {
    clients
        .issuer
        .exchange_issuers
        .push(config::IssuerConnection {
            id: "casework".into(),
            issuer: "https://casework.example.test".into(),
            jwks_endpoint: "https://casework.example.test/oauth2/jwks".into(),
            mapping,
            clients: vec!["source".into()],
            token_attributes: BTreeMap::new(),
        });
    clients.issuer.exchange_clients.push("source".into());
    clients
}

#[test]
fn exchange_clients_and_connections_name_each_other() {
    // The resource server's per-client assertion-issuer rule is derived from
    // these connection client lists alone, and an empty derived map is no rule
    // at all. A topology where the two lists disagree is refused here, so the
    // rule cannot be switched off by an omission no reader would notice.
    let (_temp, _state, base, _files) = fixture();
    for mapping in [
        config::IssuerConnectionMapping::InstitutionalGrant,
        config::IssuerConnectionMapping::FirstParty,
    ] {
        let clients = pair_exchange_client(base.clone(), mapping);
        config::clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&clients).unwrap().into_bytes(),
        )
        .unwrap();
        let mut unregistered = clients.clone();
        unregistered.issuer.exchange_issuers[0].clients.clear();
        let refusal = config::clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&unregistered).unwrap().into_bytes(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            refusal.contains("registering exchange connection"),
            "{refusal}"
        );
        let mut undeclared = clients.clone();
        undeclared.issuer.exchange_issuers[0]
            .clients
            .push("unlisted".into());
        let refusal = config::clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&undeclared).unwrap().into_bytes(),
        )
        .unwrap_err()
        .to_string();
        assert!(refusal.contains("declared exchange clients"), "{refusal}");
    }
}

#[test]
fn an_institutional_grant_connection_pairs_clients_without_projecting_their_claims() {
    // A described connection lists clients to select the first-party claims it
    // projects, so an institutional grant connection describes none. The same
    // declared pairing still decides which assertion authority that client may
    // present, which is a rule the resource server applies and the issuer does
    // not.
    let (_temp, state, clients, files) = fixture();
    let clients =
        pair_exchange_client(clients, config::IssuerConnectionMapping::InstitutionalGrant);
    let clients = config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap();
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let description = config::issuer_description(&state, &clients, &state.root()).unwrap();
    assert!(description.exchange_issuers[0].clients.is_empty());
    description.validate().unwrap();
    let runtime: Value = serde_norway::from_slice(
        &private::read(&state.root().join("runtime-test.yaml"), MAX_BYTES).unwrap(),
    )
    .unwrap();
    assert_eq!(
        runtime["authentication"]["oidc"]["assertionIssuers"],
        json!({"source": ["https://casework.example.test"]})
    );
}

#[test]
fn a_borrowed_runtime_carries_the_owners_assertion_authority_pairing() {
    // A borrowed session answers on the owner's BREG audience and declares no
    // connection of its own, so without the owner's pairing it would accept
    // exactly the tokens the owner's own runtime refuses. The pairing is read
    // from the owner's retained registration, which is present whether or not
    // the owner session is currently serving.
    let (_temp, mut state, base, _files) = fixture();
    assert!(config::assertion_issuers(&state, &base).unwrap().is_empty());

    let owner_project = state.project.join("issuer-owner");
    private::directory(&owner_project).unwrap();
    private::directory(&owner_project.join(".breg")).unwrap();
    private::directory(&owner_project.join(".breg/dev")).unwrap();
    let owner = pair_exchange_client(base.clone(), config::IssuerConnectionMapping::FirstParty);
    private::create(
        &owner_project.join(".breg/dev/clients.json"),
        &serde_json::to_vec(&owner).unwrap(),
    )
    .unwrap();

    state.issuer_project = Some(owner_project);
    assert_eq!(
        config::assertion_issuers(&state, &base).unwrap(),
        BTreeMap::from([(
            "source".to_owned(),
            vec!["https://casework.example.test".to_owned()]
        )]),
        "the borrower applies the owner's pairing rather than its own empty composition"
    );
}

#[test]
fn borrowed_issuer_refuses_owner_only_declarations_before_preparation() {
    let (_temp, mut state, clients, files) = fixture();
    state.issuer_project = Some(state.project.join("missing-owner"));
    for declaration in [
        json!({"resources": [{"audience": "urn:example:resource", "scopes": ["example:read"]}]}),
        json!({"exchangeIssuers": [{"id": "example", "issuer": "https://issuer.example", "jwksEndpoint": "http://127.0.0.1/jwks", "mapping": "first-party"}]}),
        json!({"interactiveApplications": [{"id": "example", "clientSecretRef": "secret:file/example", "origin": "http://127.0.0.1:3000", "redirectUris": ["http://127.0.0.1:3000/callback"], "audience": null, "tokenAttributes": []}]}),
        json!({"syntheticUsers": [{"username": "example", "email": "example@example.test", "passwordRef": "secret:env/EXAMPLE", "attributes": {}}]}),
        json!({"clientResources": {"example": "urn:example:resource"}}),
        json!({"exchangeClients": ["example"]}),
    ] {
        let mut borrower = clients.clone();
        borrower.issuer = serde_json::from_value(declaration).unwrap();
        let error = initialize(&state.root(), &state, &borrower, &files)
            .unwrap_err()
            .to_string();
        assert!(error.contains("owner-only"), "{error}");
    }
}

#[test]
fn human_teaching_clients_require_the_exact_explicit_fixture_flag() {
    let without_flag = br#"apiVersion: id.registrystack.org/formats/breg/dev-clients/v1alpha1
kind: BRegDevClients
clients:
  - id: administrator
    accessProfiles: []
    scopes: [casework:admin]
    claims: {registry_actor_kind: human}
"#;
    assert!(config::clients("dev-clients.yaml", without_flag).is_err());

    let without_marker = br#"apiVersion: id.registrystack.org/formats/breg/dev-clients/v1alpha1
kind: BRegDevClients
clients:
  - id: administrator
    accessProfiles: []
    allowHumanFixture: true
    scopes: [casework:admin]
    claims: {}
"#;
    assert!(config::clients("dev-clients.yaml", without_marker).is_err());

    let exact = br#"apiVersion: id.registrystack.org/formats/breg/dev-clients/v1alpha1
kind: BRegDevClients
clients:
  - id: administrator
    accessProfiles: []
    allowHumanFixture: true
    scopes: [casework:admin]
    claims: {registry_actor_kind: human}
"#;
    assert!(config::clients("dev-clients.yaml", exact).is_ok());
}

/// A client with no bound access profile never interferes with rehearsal
/// binding: every journey step still resolves to the client that actually
/// binds its profile.
#[test]
fn rehearsal_binding_still_resolves_each_journey_step_despite_an_unbound_client() {
    let (_temporary, project) = write_init_project();
    let client_bytes = fs::read(project.join("dev-clients.yaml")).expect("init writes clients");
    let mut clients =
        config::clients("dev-clients.yaml", &client_bytes).expect("the initialized clients parse");
    clients.clients.push(config::Client {
        id: "guest".into(),
        access_profiles: vec![],
        allow_breg_access: false,
        allow_human_fixture: false,
        scopes: vec!["registry:generic:introspect".into()],
        claims: BTreeMap::new(),
        test_bindings: Vec::new(),
        assertion_key_ref: None,
    });
    let captured = capture(&project, &client_bytes).expect("a fresh init project is a dev project");
    bind_journey_profiles(&captured.files["tests/journeys.yaml"], &clients)
        .expect("every journey profile still has its bound client");
}

#[test]
fn a_seed_referencing_the_unbound_client_is_refused() {
    let error = config::clients(
        "dev-clients.yaml",
        br#"apiVersion: id.registrystack.org/formats/breg/dev-clients/v1alpha1
kind: BRegDevClients
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
fn clients_allow_only_explicit_unambiguous_shared_profile_variants() {
    let bytes = r#"apiVersion: id.registrystack.org/formats/breg/dev-clients/v1alpha1
kind: BRegDevClients
clients:
  - id: operator
    accessProfiles: [operator]
    scopes: [registry:records:write]
    claims: {registry_principal: operator, registry_purpose: administration}
  - id: operator-without-purpose
    accessProfiles: [operator]
    scopes: [registry:records:write]
    claims: {registry_principal: operator}
    testBindings:
      - {journeyId: record-lifecycle, stepId: without-purpose-is-concealed}
"#;
    let parsed = config::clients("dev-clients.yaml", bytes.as_bytes())
        .expect("one default plus an exact test variant");
    assert_eq!(
        parsed.clients[1].test_bindings[0].step_id,
        "without-purpose-is-concealed"
    );

    let duplicate = bytes.replace(
        "    testBindings:\n      - {journeyId: record-lifecycle, stepId: without-purpose-is-concealed}\n",
        "",
    );
    assert!(config::clients("dev-clients.yaml", duplicate.as_bytes())
        .unwrap_err()
        .to_string()
        .contains("at most one default"));

    let duplicate_binding = format!("{bytes}  - id: another-variant\n    accessProfiles: [operator]\n    scopes: [registry:records:write]\n    claims: {{registry_principal: operator}}\n    testBindings:\n      - {{journeyId: record-lifecycle, stepId: without-purpose-is-concealed}}\n");
    assert!(
        config::clients("dev-clients.yaml", duplicate_binding.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("unique exact")
    );
}

#[test]
fn journey_bindings_select_exact_claim_variant_and_reject_stale_entries() {
    let client_bytes = br#"apiVersion: id.registrystack.org/formats/breg/dev-clients/v1alpha1
kind: BRegDevClients
clients:
  - id: operator
    accessProfiles: [operator]
    scopes: [registry:records:write]
    claims: {registry_principal: operator, registry_purpose: administration}
  - id: operator-without-purpose
    accessProfiles: [operator]
    scopes: [registry:records:write]
    claims: {registry_principal: operator}
    testBindings:
      - {journeyId: record-lifecycle, stepId: without-purpose-is-concealed}
"#;
    let clients = config::clients("dev-clients.yaml", client_bytes).unwrap();
    assert_eq!(
        journey_client(
            &clients,
            "record-lifecycle",
            "without-purpose-is-concealed",
            "operator"
        )
        .unwrap()
        .id,
        "operator-without-purpose"
    );
    assert_eq!(
        journey_client(&clients, "record-lifecycle", "create-record", "operator")
            .unwrap()
            .id,
        "operator"
    );
    let journeys = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: record-lifecycle
    steps:
      - id: create-record
        accessProfile: operator
        claims: {principal: operator, purpose: administration}
        request: {type: list}
        expect: {outcome: success, status: 200}
"#;
    assert!(bind_journey_profiles(journeys, &clients)
        .unwrap_err()
        .to_string()
        .contains("unknown or profile-mismatched"));
}

#[test]
fn every_journey_step_needs_an_issuer_client() {
    let clients = config::clients(
        "dev-clients.yaml",
        br#"apiVersion: id.registrystack.org/formats/breg/dev-clients/v1alpha1
kind: BRegDevClients
clients:
  - id: operator
    accessProfiles: [operator]
    scopes: [registry:records:write]
    claims: {registry_principal: operator, registry_purpose: administration}
"#,
    )
    .unwrap();
    let journeys = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: public-read
    steps:
      - id: list-public
        accessProfile: public-reader
        claims: {}
        request: {type: list}
        expect: {outcome: success, status: 200}
"#;
    assert!(bind_journey_profiles(journeys, &clients)
        .unwrap_err()
        .to_string()
        .contains("needs one unambiguous local client for access profile public-reader"));
}

#[test]
fn explicit_binding_wins_and_a_profile_mismatch_is_refused() {
    let clients = config::clients(
        "dev-clients.yaml",
        br#"apiVersion: id.registrystack.org/formats/breg/dev-clients/v1alpha1
kind: BRegDevClients
clients:
  - id: authenticated-public-reader
    accessProfiles: [public-reader]
    scopes: [registry:records:read]
    claims: {registry_principal: reader}
    testBindings:
      - {journeyId: public-read, stepId: list-public}
"#,
    )
    .unwrap();
    let exact = exact_journey_client(&clients, "public-read", "list-public", "public-reader")
        .unwrap()
        .expect("the explicit binding names the client for this step");
    assert_eq!(exact.id, "authenticated-public-reader");
    let journey = r#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: public-read
    steps:
      - id: list-public
        accessProfile: public-reader
        claims: {principal: reader, scopes: [registry:records:read]}
        request: {type: list}
        expect: {outcome: success, status: 200}
"#;
    bind_journey_profiles(journey.as_bytes(), &clients).unwrap();

    let mismatched = journey.replace(
        "accessProfile: public-reader",
        "accessProfile: other-reader",
    );
    assert!(bind_journey_profiles(mismatched.as_bytes(), &clients)
        .unwrap_err()
        .to_string()
        .contains("needs one unambiguous local client for access profile other-reader"));
}

fn journey_step(
    scopes: &[&str],
    purpose: Option<&str>,
) -> registry_breg::fixtures::JourneyStepProfile {
    registry_breg::fixtures::JourneyStepProfile {
        journey_id: "journey".into(),
        step_id: "step".into(),
        access_profile: "reviewer".into(),
        scopes: Some(scopes.iter().map(|scope| (*scope).to_owned()).collect()),
        purpose: purpose.map(str::to_owned),
    }
}

#[test]
fn rehearsal_tokens_request_only_the_exact_fixture_scope_subset() {
    let client = config::Client {
        id: "supervisor".into(),
        access_profiles: vec!["reviewer".into()],
        allow_breg_access: true,
        allow_human_fixture: true,
        scopes: vec!["casework:supervisor".into(), "starter:reviewer".into()],
        claims: BTreeMap::new(),
        test_bindings: Vec::new(),
        assertion_key_ref: None,
    };
    let step = journey_step(&["starter:reviewer"], None);
    let token = rehearsal_token(&client, &step).unwrap();

    assert_eq!(token.scopes, ["starter:reviewer"]);
    assert_eq!(token.logical_client_id, "supervisor");
    let widened = journey_step(&["unregistered"], None);
    assert!(rehearsal_token(&client, &widened).is_err());
}

#[test]
fn rehearsal_tokens_select_distinct_declared_purposes_on_one_logical_client() {
    let client = config::Client {
        id: "officer".into(),
        access_profiles: vec!["requester".into(), "reader".into()],
        allow_breg_access: false,
        allow_human_fixture: false,
        scopes: vec!["registry:request".into(), "registry:read".into()],
        claims: BTreeMap::from([
            ("registry_principal".into(), json!("fixture-officer")),
            (
                "registry_purpose".into(),
                json!(["record-change", "record-read"]),
            ),
        ]),
        test_bindings: Vec::new(),
        assertion_key_ref: None,
    };
    let change = rehearsal_token(
        &client,
        &journey_step(&["registry:request"], Some("record-change")),
    )
    .unwrap();
    let read = rehearsal_token(
        &client,
        &journey_step(&["registry:read"], Some("record-read")),
    )
    .unwrap();

    assert_eq!(change.logical_client_id, "officer");
    assert_eq!(read.logical_client_id, "officer");
    assert_eq!(
        config::client_token_claims(&client)["registry_actor_kind"],
        "service"
    );
    assert_ne!(change.output_id, read.output_id);
    assert_eq!(change.purpose.as_deref(), Some("record-change"));
    assert_eq!(read.purpose.as_deref(), Some("record-read"));
    assert!(rehearsal_token(
        &client,
        &journey_step(&["registry:read"], Some("undeclared")),
    )
    .is_err());
}

#[test]
fn seed_operation_defaults_to_create_and_accepts_explicit_import() {
    let create: config::Seed = serde_norway::from_str(
        "id: create-reference\nclient: operator\nentity: reference\naccessProfile: operator\ndata: {code: AA}\n",
    )
    .unwrap();
    assert_eq!(create.operation, config::SeedOperation::Create);
    let imported: config::Seed = serde_norway::from_str(
        "id: import-reference\nclient: operator\nentity: reference\naccessProfile: operator\noperation: import\ndata: {code: AA}\n",
    )
    .unwrap();
    assert_eq!(imported.operation, config::SeedOperation::Import);
}

fn seed_authority_fixture(
    digest: &str,
    opened_at: chrono::DateTime<chrono::Utc>,
) -> registry_breg::import_authority::ImportAuthority {
    use registry_breg::import_authority::{ImportAuthority, ImportAuthorityStatus};

    ImportAuthority {
        authority_id: uuid::Uuid::new_v4(),
        entity_id: "reference".into(),
        profile_id: "loader".into(),
        operation: "create".into(),
        max_items: 1,
        committed_items: 0,
        input_digests: vec![digest.to_owned()],
        activation_id: uuid::Uuid::new_v4(),
        opened_at,
        expires_at: opened_at + chrono::Duration::minutes(10),
        status: ImportAuthorityStatus::Open,
        closed_at: None,
    }
}

#[test]
fn only_the_exact_unjournaled_seed_authority_is_recovered() {
    use registry_breg::import_authority::{ImportAuthority, ImportAuthorityStatus};

    let digest = "a".repeat(64);
    let intent = seed_import_intent_now();
    let orphan = seed_authority_fixture(&digest, intent);
    let orphan_id = orphan.authority_id;
    assert_eq!(
        unjournaled_seed_authority(
            std::slice::from_ref(&orphan),
            "reference",
            "loader",
            &digest,
            Some(intent),
        ),
        Some(orphan_id)
    );
    // Anything this seed would not have opened, or that already did work,
    // is an operator's authority and is never closed on its behalf.
    let variants: [fn(&mut ImportAuthority); 8] = [
        |a| a.status = ImportAuthorityStatus::Closed,
        |a| a.entity_id = "other".into(),
        |a| a.profile_id = "other".into(),
        |a| a.operation = "update".into(),
        |a| a.max_items = 2,
        |a| a.committed_items = 1,
        |a| a.input_digests = vec!["b".repeat(64)],
        |a| a.input_digests.push("b".repeat(64)),
    ];
    for (index, change) in variants.iter().enumerate() {
        let mut other = orphan.clone();
        change(&mut other);
        assert_eq!(
            unjournaled_seed_authority(&[other], "reference", "loader", &digest, Some(intent)),
            None,
            "variant {index}"
        );
    }
    assert_eq!(
        unjournaled_seed_authority(&[], "reference", "loader", &digest, Some(intent)),
        None
    );
}

#[test]
fn an_unjournaled_seed_authority_is_recovered_only_after_this_seeds_intent() {
    // The exact request tuple cannot tell this seed's authority from an
    // identical one an operator opened. Only an authority opened no earlier
    // than the intent this seed journaled before opening is its own.
    let digest = "a".repeat(64);
    let intent = seed_import_intent_now();

    let after = seed_authority_fixture(&digest, intent + chrono::Duration::milliseconds(40));
    assert_eq!(
        unjournaled_seed_authority(
            std::slice::from_ref(&after),
            "reference",
            "loader",
            &digest,
            Some(intent),
        ),
        Some(after.authority_id),
        "an authority opened after the intent is this seed's"
    );
    let same_instant = seed_authority_fixture(&digest, intent);
    assert_eq!(
        unjournaled_seed_authority(
            std::slice::from_ref(&same_instant),
            "reference",
            "loader",
            &digest,
            Some(intent),
        ),
        Some(same_instant.authority_id),
        "an authority opened in the intent's own microsecond is this seed's"
    );

    assert_eq!(
        unjournaled_seed_authority(
            std::slice::from_ref(&after),
            "reference",
            "loader",
            &digest,
            None,
        ),
        None,
        "without an intent no open authority is this seed's"
    );

    let before = seed_authority_fixture(&digest, intent - chrono::Duration::microseconds(1));
    assert_eq!(
        unjournaled_seed_authority(
            std::slice::from_ref(&before),
            "reference",
            "loader",
            &digest,
            Some(intent),
        ),
        None,
        "an authority opened before the intent is an operator's"
    );
}

#[test]
fn a_seed_import_intent_has_the_database_timestamp_resolution() {
    // PostgreSQL keeps `opened_at` to the microsecond. A finer intent could
    // fall after an authority opened in the same microsecond on the same clock.
    let intent = seed_import_intent_now();
    assert_eq!(intent.timestamp_subsec_nanos() % 1_000, 0);
}

#[test]
fn retained_state_missing_a_recorded_field_is_invalid() {
    let (_temp, state, _clients, _files) = fixture();
    for field in [
        "requiresPostgis",
        "seedImportAuthorities",
        "seedImportIntents",
        "binaries",
    ] {
        let mut document = serde_json::to_value(&state).unwrap();
        assert!(
            document.as_object_mut().unwrap().remove(field).is_some(),
            "{field}"
        );
        let report = decode_state(&serde_json::to_vec(&document).unwrap()).unwrap_err();
        assert_eq!(
            report.diagnostics()[0].code,
            "config.missing-key",
            "{field}"
        );
    }
}

/// Decode state bytes the way `read_state` does, without its file checks.
fn decode_state(bytes: &[u8]) -> std::result::Result<State, registry_platform_yaml::Report> {
    Reader::new("state.json")
        .decode::<State>(bytes, &Expect::one(&DEV_STATE_FORMAT))
        .map(|decoded| decoded.value)
}

#[test]
fn only_a_closed_authority_on_an_incomplete_atomic_seed_run_may_restart() {
    use crate::data_lifecycle::DataLifecycleError;
    use registry_breg_client::BRegIngestionBlockedReason;

    assert!(expired_empty_seed_run(
        &DataLifecycleError::ImportRunBlocked(Some(
            BRegIngestionBlockedReason::ImportAuthorityClosed
        ))
    ));
    for error in [
        DataLifecycleError::ImportRunBlocked(Some(
            BRegIngestionBlockedReason::ActivePackageChanged,
        )),
        DataLifecycleError::ImportRunBlocked(None),
        DataLifecycleError::ImportRunCancelled,
        DataLifecycleError::Transport,
    ] {
        assert!(!expired_empty_seed_run(&error), "{error:?}");
    }
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
fn a_retained_v1_state_is_invalid_without_mutation() {
    let (_temp, state, clients, files) = fixture();
    let root = state.root();
    initialize(&root, &state, &clients, &files).unwrap();
    let state_file = root.join("state.json");
    let mut old: Value =
        serde_json::from_slice(&private::read(&state_file, MAX_BYTES).unwrap()).unwrap();
    old["version"] = json!(1);
    let fields = old.as_object_mut().unwrap();
    let port = fields.remove("issuerPort").unwrap();
    fields.insert("mintPort".to_owned(), port);
    let bytes = serde_json::to_vec(&old).unwrap();
    private::replace(&state_file, &bytes).unwrap();

    let refusal = read_state(&root).unwrap_err().to_string();
    assert_eq!(refusal, INVALID_STATE);
    assert_eq!(private::read(&state_file, MAX_BYTES).unwrap(), bytes);
}

/// The state an earlier bregctl wrote carries `version: 2` and no header.
/// It is refused unchanged, and the refusal names the earlier bregctl as the
/// one that can still stop and remove what it started.
#[test]
fn a_retained_headerless_state_is_invalid_without_mutation() {
    let (_temp, state, clients, files) = fixture();
    let root = state.root();
    initialize(&root, &state, &clients, &files).unwrap();
    let state_file = root.join("state.json");
    let mut old: Value =
        serde_json::from_slice(&private::read(&state_file, MAX_BYTES).unwrap()).unwrap();
    let fields = old.as_object_mut().unwrap();
    fields.remove("apiVersion").unwrap();
    fields.remove("kind").unwrap();
    fields.insert("version".to_owned(), json!(2));
    let bytes = serde_json::to_vec(&old).unwrap();
    private::replace(&state_file, &bytes).unwrap();

    let refusal = read_state(&root).unwrap_err().to_string();
    assert_eq!(refusal, INVALID_STATE);
    assert!(refusal.contains("run bregctl dev stop --remove with that bregctl"));
    assert_eq!(private::read(&state_file, MAX_BYTES).unwrap(), bytes);
}

#[test]
fn a_retained_state_of_another_version_is_invalid_without_mutation() {
    let (_temp, state, clients, files) = fixture();
    let root = state.root();
    initialize(&root, &state, &clients, &files).unwrap();
    let state_file = root.join("state.json");
    let original = private::read(&state_file, MAX_BYTES).unwrap();
    for (member, value) in [
        (
            "apiVersion",
            json!("id.registrystack.org/formats/breg/dev-state/v1alpha2"),
        ),
        ("kind", json!("BRegDevClients")),
        ("version", json!(2)),
    ] {
        let mut other: Value = serde_json::from_slice(&original).unwrap();
        other[member] = value;
        let bytes = serde_json::to_vec(&other).unwrap();
        private::replace(&state_file, &bytes).unwrap();

        let refusal = read_state(&root).unwrap_err().to_string();
        assert_eq!(refusal, INVALID_STATE, "{member}");
        assert_eq!(private::read(&state_file, MAX_BYTES).unwrap(), bytes);
    }
}

/// State is written with its header and without null members, the shape the
/// shared reader reads back.
#[test]
fn saved_state_carries_its_header_and_reads_back() {
    let (_temp, mut state, clients, files) = fixture();
    let root = state.root();
    initialize(&root, &state, &clients, &files).unwrap();
    state.mark_seeded("first-record").unwrap();
    state.mark_seeded("second-record").unwrap();
    state.mark_seeded("first-record").unwrap();
    state.save().unwrap();

    let written: Value =
        serde_json::from_slice(&private::read(&root.join("state.json"), MAX_BYTES).unwrap())
            .unwrap();
    assert_eq!(written["apiVersion"], STATE_API_VERSION);
    assert_eq!(written["kind"], STATE_KIND);
    assert!(written.get("version").is_none());
    assert!(written.get("containerId").is_none());
    assert!(written
        .as_object()
        .unwrap()
        .values()
        .all(|value| !value.is_null()));
    assert_eq!(written["seeded"], json!(["first-record", "second-record"]));

    let read = read_state(&root).unwrap();
    assert_eq!(&*read.seeded, ["first-record", "second-record"]);
    assert_eq!(read.api_version, STATE_API_VERSION);
}

/// A seed named twice in the retained journal is refused, never collapsed
/// into one completed seed (CFG-ID-6).
#[test]
fn a_retained_state_naming_a_seed_twice_is_invalid() {
    let (_temp, state, clients, files) = fixture();
    let root = state.root();
    initialize(&root, &state, &clients, &files).unwrap();
    let state_file = root.join("state.json");
    let mut repeated: Value =
        serde_json::from_slice(&private::read(&state_file, MAX_BYTES).unwrap()).unwrap();
    repeated["seeded"] = json!(["first-record", "first-record"]);
    private::replace(&state_file, &serde_json::to_vec(&repeated).unwrap()).unwrap();

    assert_eq!(read_state(&root).unwrap_err().to_string(), INVALID_STATE);
    let report = decode_state(&private::read(&state_file, MAX_BYTES).unwrap()).unwrap_err();
    let diagnostics = report.diagnostics();
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].code, "config.duplicate-item");
    assert_eq!(diagnostics[0].path, "/seeded/1");
}

#[test]
fn default_ports_lie_below_the_source_port_range() {
    for port in [
        DEFAULT_BREG_PORT,
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
fn occupied_and_ambiguous_ports_are_refused() {
    assert!(ports(1, 1, 2).is_err());
    assert!(ports(0, 2, 3).is_err());
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let occupied = listener.local_addr().unwrap().port();
    for (role, flag) in [
        (PortRole::Breg, Some("--breg-port")),
        (PortRole::Issuer, Some("--issuer-port")),
        (PortRole::Database, Some("--database-port")),
        (PortRole::Receiver, None),
    ] {
        let refusal = format!("{:#}", probe(occupied, role).unwrap_err());
        assert!(refusal.contains(&occupied.to_string()), "{refusal}");
        assert!(refusal.contains(role.name()), "{refusal}");
        assert!(refusal.contains("127.0.0.1"), "{refusal}");
        match flag {
            // A flag-selected port names the flag that chooses it on a first
            // start, so an author can act on the refusal without re-reading
            // the command's own options.
            Some(flag) => assert!(refusal.contains(flag), "{refusal}"),
            // The receiver's port is retained with the session; its refusal
            // must not point at a flag that does not exist.
            None => assert!(!refusal.contains("--"), "{refusal}"),
        }
        assert!(!refusal.contains(".breg"), "{refusal}");
    }
    // A port nothing holds stays usable, so only a real occupant refuses.
    let holder = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let free = holder.local_addr().unwrap().port();
    drop(holder);
    assert!(probe(free, PortRole::Breg).is_ok());
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
    let session = |breg: String| {
        BTreeMap::from([
            ("breg".to_owned(), installed(&breg)),
            (
                "docker".to_owned(),
                installed("Docker version 29.4.0, build 1a2b3c4"),
            ),
        ])
    };

    matching_versions(&session(format!("breg {own}")))
        .expect("the stack binaries of one release start a session");

    for (name, binaries) in [("breg", session("breg 0.26.1".to_owned()))] {
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
    matching_versions(&session(UNREPORTED_VERSION.to_owned()))
        .expect("a prerequisite that reports no version is not compared");

    // A start resolves the prerequisites and compares them before it inspects
    // a container or launches the supervisor.
    let (_temporary, project) = write_init_project();
    let prerequisites = project.join("prerequisites");
    fs::create_dir(&prerequisites).unwrap();
    for (name, reported) in [
        ("breg", "breg 0.26.1".to_owned()),
        ("docker", "Docker version 29.4.0, build 1a2b3c4".to_owned()),
    ] {
        script(&prerequisites.join(name), &format!("echo '{reported}'"));
    }
    let ports = unused_ports();
    let refused = format!(
        "{:#}",
        start(StartArgs {
            project: project.clone(),
            clients_file: None,
            breg_port: Some(ports[0]),
            issuer_port: Some(ports[1]),
            issuer_project: None,
            issuer_image: None,
            database_port: Some(ports[2]),
            breg_bin: Some(prerequisites.join("breg")),
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
    for file in ["audit-key", "cursor-key"] {
        let bytes = private::read(&root.join("secrets").join(file), 64).unwrap();
        assert_eq!(bytes.len(), 43);
        assert!(bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')));
    }
}

#[test]
fn generated_postgres_leaf_verifies_against_its_distinct_ca() {
    let (_temp, state, clients, files) = fixture();
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let output = match Command::new("openssl")
        .arg("verify")
        .arg("-CAfile")
        .arg(state.root().join("tls/ca.pem"))
        .arg(state.root().join("tls/server.pem"))
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => panic!("run openssl verify: {error}"),
    };
    assert!(output.status.success(), "generated TLS chain must verify");
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
        SPATIAL_IMAGE.to_owned(),
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

/// The start help and the owning document agree on the recovery facts an
/// operator needs after a deadline or an outside kill: the document keeps
/// the fact, the help points at the document's own section names.
#[test]
fn dev_start_help_carries_the_outside_kill_fact_and_the_document_sections() {
    let document = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/breg/DEV.md"),
    )
    .expect("the owning lifecycle document");
    assert!(
        document.contains("require inspection of surviving service owners before restart"),
        "products/breg/DEV.md omits the outside-kill fact"
    );
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
        "uncatchable",
        "surviving service owners",
        "products/breg/DEV.md",
        "'Native local BReg lifecycle'",
        "'Retained state and recovery'",
    ] {
        assert!(help.contains(fact), "bregctl dev start help omits {fact}");
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
fn only_a_database_without_the_package_activated_classifies_a_doctor_refusal_as_not_activated() {
    assert_eq!(activation(true, b"{}").unwrap(), Activation::Activated);
    // The one-role session reads the ledger, so a database no apply has
    // committed to is reported as uninitialized, and one whose successor
    // apply has not committed as not having the package active.
    for (code, message) in [
        (
            "startup.database.uninitialized",
            "the database records no activated package",
        ),
        (
            "startup.package.not-active",
            "the database has not activated the package at package.root",
        ),
    ] {
        assert_eq!(
            activation(false, &doctor_refusal(code, message)).unwrap(),
            Activation::NotActivated
        );
    }
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
}

#[test]
fn a_failed_issuer_setup_names_the_phase_logs_and_both_recoveries() {
    let (_temporary, state, _clients, _files) = fixture();
    let root = state.root();
    // The cause the supervisor records for a refused one-time issuer setup:
    // the shared tooling names the service and the bootstrap phase.
    let cause = format!(
        "{}{}",
        "a command this session owns did not succeed: ",
        "the local ThunderID issuer's one-time upstream setup (its ./setup.sh bootstrap) \
         did not complete; the partial state is retained for recovery"
    );
    for failure in [
        start_failure(Some(&cause), &root),
        start_failure(None, &root),
    ] {
        let reported = format!("{failure:#}");
        assert!(reported.contains("local start failed"), "{reported}");
        // The one private path the refusal may name is the retained logs
        // directory DEV.md documents; every other `.breg/dev` path stays out.
        let logs = root.join("logs").display().to_string();
        assert!(reported.contains(&logs), "{reported}");
        let mut rest = reported.as_str();
        while let Some(index) = rest.find(".breg/dev") {
            assert!(rest[index..].starts_with(".breg/dev/logs"), "{reported}");
            rest = &rest[index + 1..];
        }
        // Retention is the recovery: retry keeps the records, and exactly one
        // named command discards them.
        assert!(reported.contains("Retry the same command"), "{reported}");
        assert!(reported.contains("bregctl dev stop --remove"), "{reported}");
    }
    // The recorded issuer cause reaches the terminal with the service, the
    // phase and the retention statement intact.
    let reported = format!("{:#}", start_failure(Some(&cause), &root));
    for fact in ["ThunderID issuer", "./setup.sh", "retained for recovery"] {
        assert!(reported.contains(fact), "{reported}");
    }
    // The bounded refusal the supervisor can carry still holds every fact.
    let bounded: String = cause.chars().take(MAX_REFUSAL).collect();
    assert!(bounded.contains("ThunderID issuer"), "{bounded}");
    assert!(bounded.contains("./setup.sh"), "{bounded}");
}

#[test]
fn the_changed_inputs_refusal_and_stop_help_name_the_same_two_options() {
    // The refusal for edited inputs on a retained session offers both record
    // outcomes, and `dev stop --help` documents the same pair, so neither
    // surface invents an option the other omits.
    for fact in [
        "bregctl dev stop --remove",
        "copy the authored files to a new project directory",
    ] {
        assert!(CHANGED_INPUTS.contains(fact), "{CHANGED_INPUTS}");
    }
    let cli = <crate::Cli as clap::CommandFactory>::command();
    let dev = cli
        .get_subcommands()
        .find(|command| command.get_name() == "dev")
        .expect("bregctl publishes dev");
    let stop = dev
        .get_subcommands()
        .find(|command| command.get_name() == "stop")
        .and_then(|command| command.get_long_about())
        .expect("dev stop describes its own records")
        .to_string();
    assert!(stop.contains("--remove"), "{stop}");
    assert!(
        stop.contains("copy the authored files to a new project directory"),
        "{stop}"
    );
    assert!(stop.contains("'Retained state and recovery'"), "{stop}");
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
    state.package_digest = Some("revision-1".into());
    state.mark_seeded("first-record").unwrap();
    state
        .seed_import_authorities
        .insert("imported-record".into(), uuid::Uuid::nil().to_string());
    state
        .seed_import_intents
        .insert("imported-record".into(), chrono::Utc::now());
    state.status = Status::Ready;
    let owner = state.owner.clone();
    let clients_file = state.clients_file.clone();
    reclaimed(&mut state);
    assert!(state.container_id.is_none());
    assert!(!state.tls_files_copied);
    assert!(!state.database_ready);
    assert!(!state.activated);
    assert!(state.seeded.is_empty());
    // An authority or intent names a row of the removed database, never one
    // the recreated database holds.
    assert!(state.seed_import_authorities.is_empty());
    assert!(state.seed_import_intents.is_empty());
    assert!(matches!(state.status, Status::Stopped));
    // The next start recreates an empty database with the same identities,
    // ports, credentials and already built package.
    assert_eq!(state.owner, owner);
    assert_eq!(state.clients_file, clients_file);
    assert_eq!(state.package_digest.as_deref(), Some("revision-1"));
    assert_eq!(state.database_port, 55448);
    assert_eq!(state.volume_name(), format!("breg-dev-{owner}"));
}

/// A retained session initialized from the project `bregctl init` writes,
/// with the digest a start computes, so a later start compares real inputs.
fn retained_session(project: &Path, container_id: Option<String>) -> State {
    let client_bytes = fs::read(project.join("dev-clients.yaml")).unwrap();
    let clients = config::clients("dev-clients.yaml", &client_bytes).unwrap();
    let captured = capture(project, &client_bytes).unwrap();
    private::directory(&project.join(".breg")).unwrap();
    let state = State {
        api_version: state_api_version(),
        kind: state_kind(),
        project: project.to_path_buf(),
        owner: uuid::Uuid::new_v4().to_string(),
        status: Status::Stopped,
        breg_port: 8094,
        issuer_port: 8095,
        issuer_project: None,
        issuer_owner: None,
        issuer_image: None,
        purpose_port: None,
        database_port: 55448,
        requires_postgis: false,
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
        package_digest: None,
        activated: false,
        seeded: UniqueList::default(),
        seed_import_authorities: BTreeMap::new(),
        seed_import_intents: BTreeMap::new(),
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
        issuer_port: None,
        issuer_project: None,
        issuer_image: None,
        database_port: None,
        breg_bin: Some(project.join("missing-breg")),
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

/// Replace the one occurrence of `from` in an authored file with `to`.
fn edit_authored(path: &Path, from: &str, to: &str) {
    let text = fs::read_to_string(path).unwrap();
    assert_eq!(
        text.matches(from).count(),
        1,
        "{from} in {}",
        path.display()
    );
    fs::write(path, text.replace(from, to)).unwrap();
}

/// Append a comment line to an authored file, changing its bytes only.
fn append_comment(path: &Path, comment: &str) {
    let mut bytes = fs::read(path).unwrap();
    bytes.extend_from_slice(comment.as_bytes());
    fs::write(path, bytes).unwrap();
}

#[test]
fn the_source_pin_follows_the_compiled_meaning_not_the_authored_bytes() {
    let (_temporary, project) = write_init_project();
    let pin = |client_bytes: &[u8]| capture(&project, client_bytes).unwrap().digest;
    let client_bytes = fs::read(project.join("dev-clients.yaml")).unwrap();
    let original = pin(&client_bytes);

    // Comments, blank lines and key order spell the same registry, journeys
    // and clients, so they leave the pin where it was.
    append_comment(&project.join("registry.yaml"), "\n# edited comment\n");
    append_comment(
        &project.join("modules/record-notes/module.yaml"),
        "\n# edited comment\n",
    );
    append_comment(&project.join("tests/journeys.yaml"), "\n# edited comment\n");
    edit_authored(
        &project.join("registry.yaml"),
        "  id: generic-registry\n  version: 0.1.0\n",
        "  version: 0.1.0\n  id: generic-registry\n",
    );
    let mut commented_clients = client_bytes.clone();
    commented_clients.extend_from_slice(b"\n# edited comment\n");
    assert_eq!(pin(&commented_clients), original);

    // A change of meaning in any pinned input moves the pin.
    for (path, from, to) in [
        // The compiled registry revision.
        ("registry.yaml", "  version: 0.1.0\n", "  version: 0.2.0\n"),
        // The package identity, which the compiled revision does not name.
        (
            "registry.yaml",
            "sourceRevision: generic-registry-0.1.0",
            "sourceRevision: generic-registry-0.1.1",
        ),
        // The journeys the session rehearses before it builds a package.
        (
            "tests/journeys.yaml",
            "data: {code: group-a, label: Example group}",
            "data: {code: group-a, label: Edited group}",
        ),
    ] {
        edit_authored(&project.join(path), from, to);
        assert_ne!(pin(&commented_clients), original, "{path}: {to}");
        edit_authored(&project.join(path), to, from);
        assert_eq!(pin(&commented_clients), original, "{path}: {from}");
    }
    let edited_clients = String::from_utf8(client_bytes)
        .unwrap()
        .replace(
            "registry_principal: generic-registry-reader",
            "registry_principal: generic-registry-other-reader",
        )
        .into_bytes();
    assert_ne!(pin(&edited_clients), original);
}

#[test]
fn a_comment_in_a_handler_script_is_a_change_because_the_package_ships_its_bytes() {
    // The compiled registry carries the digest of the exact script bytes it
    // runs, so the pin treats any script edit, a comment included, as a
    // change of what the session would ship.
    let (_temporary, project) = write_init_project();
    edit_authored(
        &project.join("registry.yaml"),
        "    permissions:\n      entities:\n        - entity: record-group\n          \
         rowBoundaries: unrestricted\n          operations: [create, get, list]\n",
        "    permissions:\n      actions:\n        - action: create-record-group\n          \
         operations: [invoke]\n          \
         targets: [{entity: record-group, rowBoundaries: unrestricted}]\n          \
         results: [group]\n      entities:\n        - entity: record-group\n          \
         rowBoundaries: unrestricted\n          operations: [create, get, list]\n",
    );
    append_comment(
        &project.join("registry.yaml"),
        "\nactions:\n  - id: create-record-group\n    inputs:\n      \
         - {id: code, type: string, required: true, maximumLength: 64, classification: public}\n    \
         handler:\n      type: rhai\n      script: scripts/create-record-group.rhai\n      \
         abi: registry.action-handler/v1\n      writes:\n        - id: group\n          \
         target: {entity: record-group}\n          operation: create\n          \
         fields: [code, label]\n",
    );
    fs::create_dir_all(project.join("scripts")).unwrap();
    fs::write(
        project.join("scripts/create-record-group.rhai"),
        "fn handle(ctx) {\n    #{effects: [#{id: \"group\", set: #{code: ctx.inputs.code, \
         label: ctx.inputs.code}}]}\n}\n",
    )
    .unwrap();
    let clients = fs::read(project.join("dev-clients.yaml")).unwrap();
    let original = capture(&project, &clients).unwrap().digest;
    append_comment(&project.join("registry.yaml"), "\n# edited comment\n");
    assert_eq!(capture(&project, &clients).unwrap().digest, original);
    append_comment(
        &project.join("scripts/create-record-group.rhai"),
        "\n// edited comment\n",
    );
    assert_ne!(capture(&project, &clients).unwrap().digest, original);
}

#[test]
fn changed_inputs_are_refused_while_the_session_holds_records() {
    let (_temporary, project) = write_init_project();
    let state = retained_session(&project, Some("c".repeat(64)));
    edit_authored(
        &project.join("registry.yaml"),
        "  version: 0.1.0\n",
        "  version: 0.2.0\n",
    );

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
fn a_byte_only_edit_keeps_the_session_that_holds_records() {
    // A comment changes no compiled meaning, so the retained session and its
    // records stay; the start goes on to look for the breg binary.
    let (_temporary, project) = write_init_project();
    let state = retained_session(&project, Some("c".repeat(64)));
    append_comment(
        &project.join("registry.yaml"),
        "\n# edited while the records are retained\n",
    );
    append_comment(
        &project.join("tests/journeys.yaml"),
        "\n# edited while the records are retained\n",
    );
    append_comment(
        &project.join("dev-clients.yaml"),
        "\n# edited while the records are retained\n",
    );

    let failure = format!(
        "{:#}",
        start_without_binaries(&project).expect_err("no breg binary")
    );
    assert!(!failure.contains("dev stop --remove"), "{failure}");
    let kept = read_state(&state.root()).unwrap();
    assert_eq!(kept.owner, state.owner);
    assert_eq!(kept.container_id, state.container_id);
    let client_bytes = fs::read(project.join("dev-clients.yaml")).unwrap();
    assert_eq!(
        kept.source_digest,
        capture(&project, &client_bytes).unwrap().digest
    );
    assert_eq!(kept.source_digest, state.source_digest);
}

#[test]
fn changed_inputs_replace_a_session_whose_records_were_discarded() {
    // After `dev stop --remove` nothing remains for the source pin to protect,
    // so an edited project starts a fresh session on the retained ports.
    let (_temporary, project) = write_init_project();
    let mut state = retained_session(&project, None);
    let ports = unused_ports();
    state.breg_port = ports[0];
    state.issuer_port = ports[1];
    state.database_port = ports[2];
    state.save().unwrap();
    let previous_key =
        fs::read(state.root().join("credentials/operator/assertion-key.jwk")).unwrap();
    edit_authored(
        &project.join("registry.yaml"),
        "  version: 0.1.0\n",
        "  version: 0.2.0\n",
    );
    let client_bytes = fs::read(project.join("dev-clients.yaml")).unwrap();
    let expected = capture(&project, &client_bytes).unwrap().digest;
    assert_ne!(expected, state.source_digest);

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
            replaced.issuer_port,
            replaced.database_port
        ),
        (ports[0], ports[1], ports[2])
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

/// The rendered machine registration for the fixture's `source` client: the
/// one agent document under the issuer provisioning tree.
fn source_agent_path(state: &State) -> std::path::PathBuf {
    let directory = state.root().join("issuer/registry-schema/agents");
    let entry = std::fs::read_dir(&directory)
        .expect("the issuer provisioning tree exists")
        .find_map(|entry| entry.ok())
        .expect("at least one rendered agent");
    directory.join(entry.path().file_name().expect("a file name"))
}

#[test]
fn export_client_copies_a_stopped_retained_pair_and_retries_without_state_changes() {
    let (_temp, state, clients, files) = fixture();
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let before = fs::read(state.root().join("state.json")).unwrap();
    let registrations = fs::read(source_agent_path(&state)).unwrap();
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
    assert_eq!(fs::read(source_agent_path(&state)).unwrap(), registrations);
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
    let clients = config::clients("dev-clients.yaml", crate::INIT_DEV_CLIENTS).unwrap();
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
    assert!(source.assertion_key_ref.is_none());
    state.status = Status::Stopped;
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let key = fs::read(state.root().join("credentials/source/assertion-key.jwk")).unwrap();
    for other in ["operator", "reader"] {
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
        config::clients("dev-clients.yaml", &fs::read(&resolved).unwrap())
            .expect("starter clients parse");
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
    entity["hooks"] = json!([
        {"phase":"after","id":"record-created-v1","trigger":"created","projection":["code"],"handler":{"type":"url","destinationId":"local-hook"}},
        {"phase":"after","id":"record-patched-v1","trigger":"patched","projection":["label"],"handler":{"type":"url","destinationId":"local-hook"}},
        {"phase":"after","id":"record-second-v1","trigger":"created","projection":["code"],"handler":{"type":"url","destinationId":"second-hook"}}
    ]);
    fs::write(&module, serde_norway::to_string(&source).unwrap()).unwrap();
    let bytes = fs::read(project.join("dev-clients.yaml")).unwrap();
    let clients = config::clients("dev-clients.yaml", &bytes).unwrap();
    let captured = capture(&project, &bytes).unwrap();
    let (_temp, mut state, _, _) = fixture();
    state.webhook_port = Some(18996);
    initialize(&state.root(), &state, &clients, &captured.files).unwrap();
    let root = state.root();
    private::directory(&root.join("build")).unwrap();
    private::directory(&root.join("build/package")).unwrap();
    config::runtime(&root, &state, &clients, false).unwrap();
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
            assert_eq!(binding["networkProfile"], "loopback-development-http");
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
    let mut invalid = saved;
    invalid.webhook_port = Some(invalid.breg_port);
    invalid.save().unwrap();
    assert!(read_state(&root).is_err());
}

#[test]
fn explicit_local_event_destinations_bind_exact_compiled_inventory() {
    let (_project_temp, project) = write_init_project();
    let module = project.join("registry.yaml");
    let mut source: Value = serde_norway::from_slice(&fs::read(&module).unwrap()).unwrap();
    let entity = source["entities"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entity| entity["id"] == "record")
        .unwrap();
    entity["hooks"] = json!([{
        "phase": "after",
        "id":"record-created-v1","trigger":"created","projection":["code"],
        "handler":{"type":"url","destinationId":"openfn"}
    }]);
    fs::write(&module, serde_norway::to_string(&source).unwrap()).unwrap();
    let bytes = fs::read(project.join("dev-clients.yaml")).unwrap();
    let mut clients = config::clients("dev-clients.yaml", &bytes).unwrap();
    let (_temp, mut state, _, _) = fixture();
    fs::set_permissions(&project, fs::Permissions::from_mode(0o700)).unwrap();
    let secrets = secret_root(&project, &mut clients);
    let key = file_secret(&secrets, "event-key", b"synthetic-local-event-key-for-test");
    clients.event_destinations.insert(
        "openfn".into(),
        config::LocalEventDestination {
            origin: "http://127.0.0.1:18888".into(),
            path: "/inbox/registry".into(),
            hmac_sha256_key_ref: key,
        },
    );
    let captured = capture(&project, &bytes).unwrap();
    state.webhook_port = None;
    initialize(&state.root(), &state, &clients, &captured.files).unwrap();
    let root = state.root();
    let compiled = crate::compile(&root.join("project"), crate::ProfileArg::Production, "dev")
        .unwrap_or_else(|failure| panic!("{}", serde_json::to_string(&failure).unwrap()));
    let bindings =
        config::external_event_destinations(&compiled, &clients.event_destinations).unwrap();
    assert_eq!(bindings["openfn"]["origin"], "http://127.0.0.1:18888");
    assert_eq!(bindings["openfn"]["path"], "/inbox/registry");
    assert_eq!(
        bindings["openfn"]["hmacSha256KeyRef"],
        "secret:file/webhook-openfn"
    );
    let runtime: Value =
        serde_norway::from_slice(&fs::read(root.join("runtime-test.yaml")).unwrap()).unwrap();
    assert_eq!(runtime["eventDestinations"], bindings);
    assert!(config::external_event_destinations(&compiled, &BTreeMap::new()).is_err());
}

#[test]
fn local_event_destinations_refuse_an_origin_without_a_usable_port() {
    let (_project_temp, project) = write_init_project();
    let bytes = fs::read(project.join("dev-clients.yaml")).unwrap();
    let mut clients = config::clients("dev-clients.yaml", &bytes).unwrap();
    fs::set_permissions(&project, fs::Permissions::from_mode(0o700)).unwrap();
    let secrets = secret_root(&project, &mut clients);
    let key = file_secret(&secrets, "event-key", b"synthetic-local-event-key-for-test");
    clients.event_destinations.insert(
        "openfn".into(),
        config::LocalEventDestination {
            origin: "http://127.0.0.1:18888".into(),
            path: "/inbox/registry".into(),
            hmac_sha256_key_ref: key,
        },
    );
    config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap();
    // Port zero parses and is not the scheme default, so the clients file is
    // what must refuse it. The origin otherwise reaches the runtime and fails
    // there, naming the destination policy rather than this declaration.
    for origin in ["http://127.0.0.1:0", "http://127.0.0.1"] {
        clients.event_destinations.get_mut("openfn").unwrap().origin = origin.into();
        let refusal = config::clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&clients).unwrap().into_bytes(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            refusal.contains("exact loopback origins"),
            "{origin}: {refusal}"
        );
    }
}

#[test]
fn local_event_destinations_refuse_userinfo_and_noncanonical_paths() {
    let (_project_temp, project) = write_init_project();
    let bytes = fs::read(project.join("dev-clients.yaml")).unwrap();
    let mut clients = config::clients("dev-clients.yaml", &bytes).unwrap();
    fs::set_permissions(&project, fs::Permissions::from_mode(0o700)).unwrap();
    let secrets = secret_root(&project, &mut clients);
    let key = file_secret(&secrets, "event-key", b"synthetic-local-event-key-for-test");
    clients.event_destinations.insert(
        "openfn".into(),
        config::LocalEventDestination {
            origin: "http://127.0.0.1:18888".into(),
            path: "/inbox/registry".into(),
            hmac_sha256_key_ref: key,
        },
    );
    config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap();
    // The runtime's own destination policy refuses userinfo in an origin, and
    // builds its delivery target through a path validator that refuses dot
    // segments, percent escapes, empty segments and non-ASCII bytes. The
    // clients file is what must refuse both, so preflight and startup agree on
    // one answer instead of the declaration surfacing as a failed start.
    for origin in [
        "http://operator@127.0.0.1:18888",
        "http://operator:placeholder@127.0.0.1:18888",
    ] {
        clients.event_destinations.get_mut("openfn").unwrap().origin = origin.into();
        let refusal = config::clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&clients).unwrap().into_bytes(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            refusal.contains("exact loopback origins"),
            "{origin}: {refusal}"
        );
    }
    clients.event_destinations.get_mut("openfn").unwrap().origin = "http://127.0.0.1:18888".into();
    for path in [
        "/inbox/../registry",
        "/inbox/./registry",
        "/inbox/%2e%2e/registry",
        "/inbox//registry",
        "/inbox/na\u{ef}ve",
    ] {
        clients.event_destinations.get_mut("openfn").unwrap().path = path.into();
        let refusal = config::clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&clients).unwrap().into_bytes(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            refusal.contains("exact loopback origins"),
            "{path}: {refusal}"
        );
    }
    clients.event_destinations.get_mut("openfn").unwrap().path = "/inbox/registry".into();
    config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap();
}

#[test]
fn local_event_destinations_refuse_hmac_key_bytes_the_runtime_cannot_load() {
    let (_project_temp, project) = write_init_project();
    let bytes = fs::read(project.join("dev-clients.yaml")).unwrap();
    let mut clients = config::clients("dev-clients.yaml", &bytes).unwrap();
    fs::set_permissions(&project, fs::Permissions::from_mode(0o700)).unwrap();
    let secrets = secret_root(&project, &mut clients);
    // The runtime resolves this key through the shared secret resolver, which
    // refuses any value carrying a NUL byte. A randomly generated key holds one
    // about one time in eight. The clients file resolves its reference through
    // the same resolver, so it refuses the value before a start rather than
    // leaving it to a failed one.
    let mut material = b"synthetic-local-event-key-for-tes".to_vec();
    material[8] = 0;
    let key = file_secret(&secrets, "event-key", &material);
    clients.event_destinations.insert(
        "openfn".into(),
        config::LocalEventDestination {
            origin: "http://127.0.0.1:18888".into(),
            path: "/inbox/registry".into(),
            hmac_sha256_key_ref: key,
        },
    );
    let refusal = config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap_err()
    .to_string();
    assert!(
        refusal.contains("eventDestinations.openfn.hmacSha256KeyRef could not be resolved")
            && refusal.contains("without NUL bytes"),
        "{refusal}"
    );

    private::replace(
        &secrets.join("event-key"),
        b"synthetic-local-event-key-for-test",
    )
    .unwrap();
    config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap();
}

#[test]
fn an_imported_assertion_key_needs_a_usable_key_identifier() {
    // Every token one of these clients obtains is a private_key_jwt assertion,
    // whose header names the key it was signed with. A key carrying no usable
    // identifier imports and registers cleanly and then fails at the first
    // token request, so it is refused where the operator named the key.
    for kid in [
        Value::Null,
        json!(""),
        json!("   "),
        json!(7),
        json!("k".repeat(257)),
    ] {
        let (_temp, state, mut clients, files) = fixture();
        let input = secret_root(&state.project, &mut clients);
        config::keypair(&input).unwrap();
        let mut key: Value = serde_json::from_slice(
            &private::read(&input.join("assertion-key.jwk"), MAX_BYTES).unwrap(),
        )
        .unwrap();
        if kid.is_null() {
            key.as_object_mut().unwrap().remove("kid");
        } else {
            key["kid"] = kid.clone();
        }
        let replaced = file_secret(
            &input,
            "unusable-kid.jwk",
            &serde_json::to_vec(&key).unwrap(),
        );
        clients
            .clients
            .iter_mut()
            .find(|client| client.id == "source")
            .unwrap()
            .assertion_key_ref = Some(replaced);
        let refusal = format!(
            "{:#}",
            initialize(&state.root(), &state, &clients, &files).unwrap_err()
        );
        assert!(
            refusal.contains("bounded, non-blank kid"),
            "{kid}: {refusal}"
        );
    }

    let (_temp, state, mut clients, files) = fixture();
    let input = secret_root(&state.project, &mut clients);
    config::keypair(&input).unwrap();
    clients
        .clients
        .iter_mut()
        .find(|client| client.id == "source")
        .unwrap()
        .assertion_key_ref = Some(SecretReference::parse("secret:file/assertion-key.jwk").unwrap());
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let public: Value = serde_json::from_slice(
        &private::read(
            &state.root().join("credentials/source/public.jwk"),
            MAX_BYTES,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        public["kid"]
            .as_str()
            .is_some_and(|kid| !kid.trim().is_empty()),
        "an imported key reaches registration carrying its identifier: {public}"
    );
}

#[test]
fn local_evidence_provider_copies_owner_secrets_and_renders_exact_binding() {
    let (_temp, state, mut clients, files) = fixture();
    let root = state.root();
    let secrets = secret_root(&state.project, &mut clients);
    let token = file_secret(&secrets, "provider-token", b"synthetic-provider-token");
    let jwks = file_secret(&secrets, "provider-jwks", br#"{"keys":[]}"#);
    clients.evidence_providers.insert(
        "qualification".into(),
        config::LocalEvidenceProvider {
            base_url: "http://127.0.0.1:18093".into(),
            trust_binding_id: "exact-local-trust-v1".into(),
            token_ref: Some(token),
            private_key_jwt: None,
            trusted_jwks_ref: jwks,
            revoked_key_ids: vec![],
            ca_bundle_ref: None,
        },
    );
    config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap();
    initialize(&root, &state, &clients, &files).unwrap();
    let runtime: Value =
        serde_norway::from_slice(&fs::read(root.join("runtime-test.yaml")).unwrap()).unwrap();
    let provider = &runtime["evidenceProviders"]["qualification"];
    assert_eq!(provider["baseUrl"], "http://127.0.0.1:18093");
    assert_eq!(provider["trustBindingId"], "exact-local-trust-v1");
    assert_eq!(
        provider["tokenRef"],
        "secret:file/evidence-token-qualification"
    );
    assert_eq!(
        provider["trustedJwksRef"],
        "secret:file/evidence-jwks-qualification"
    );
    assert_eq!(
        fs::read(root.join("secrets/evidence-token-qualification")).unwrap(),
        b"synthetic-provider-token"
    );
    // Port zero parses and is not the scheme default, so the clients file is
    // what must refuse it. A provider bound to it starts a session in which
    // every Evidence request targets an unusable port.
    for base_url in [
        "https://evidence.example.org",
        "http://127.0.0.1:0",
        "http://127.0.0.1",
    ] {
        clients
            .evidence_providers
            .get_mut("qualification")
            .unwrap()
            .base_url = base_url.into();
        let refusal = config::clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&clients).unwrap().into_bytes(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            refusal.contains("exact loopback origins"),
            "{base_url}: {refusal}"
        );
    }
    // The reader's URL type refuses a base URL carrying credentials at the
    // declaration, before any session starts.
    for base_url in [
        "http://reader@127.0.0.1:18093",
        "http://reader:secret@127.0.0.1:18093",
    ] {
        clients
            .evidence_providers
            .get_mut("qualification")
            .unwrap()
            .base_url = base_url.into();
        let refusal = config::clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&clients).unwrap().into_bytes(),
        )
        .unwrap_err()
        .to_string();
        assert!(refusal.contains("no user information"), "{refusal}");
        assert!(!refusal.contains("secret"), "{refusal}");
    }
}

#[test]
fn local_review_authority_uses_refreshing_logical_client_without_exposing_credentials() {
    let (_temp, state, mut clients, files) = fixture();
    let root = state.root();
    let secrets = secret_root(&state.project, &mut clients);
    let completion = file_secret(
        &secrets,
        "review-completion-token",
        b"synthetic-completion-token",
    );
    clients.review_authorities.insert(
        "casework-a".into(),
        config::LocalReviewAuthority {
            endpoint: "http://127.0.0.1:18096/reviews/".into(),
            profile: "integration-requester".into(),
            producer_id: "registry-producer".into(),
            recovery_days: 7,
            client: "operator".into(),
            completion_token_ref: Some(completion.clone()),
            completion_recipient: Some("registry-breg".into()),
        },
    );
    config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap();
    initialize(&root, &state, &clients, &files).unwrap();

    let runtime_bytes = fs::read(root.join("runtime-test.yaml")).unwrap();
    let runtime: Value = serde_norway::from_slice(&runtime_bytes).unwrap();
    let authority = &runtime["reviewAuthorities"]["casework-a"];
    assert_eq!(authority["endpoint"], "http://127.0.0.1:18096/reviews/");
    assert_eq!(authority["profile"], "integration-requester");
    assert_eq!(authority["producerId"], "registry-producer");
    assert_eq!(authority["recoveryDays"], 7);
    let oauth = &authority["privateKeyJwt"];
    assert_eq!(oauth["tokenEndpoint"], "http://127.0.0.1:8095/oauth2/token");
    assert_eq!(oauth["assertionAudience"], "http://127.0.0.1:8095");
    assert_eq!(oauth["resource"], state.audience());
    assert_eq!(oauth["scopes"], json!(["registry:generic:operate"]));
    assert_eq!(
        oauth["clientIdRef"],
        "secret:file/review-authority-casework-a-client-id"
    );
    assert_eq!(
        oauth["clientAssertionKeyRef"],
        "secret:file/review-authority-casework-a-client-assertion-key"
    );
    assert_eq!(
        authority["completionTokenRef"],
        "secret:file/review-completion-casework-a-token"
    );
    assert_eq!(authority["completionRecipient"], "registry-breg");
    assert!(authority.get("tokenRef").is_none());

    assert_eq!(
        fs::read(root.join("secrets/review-authority-casework-a-client-id")).unwrap(),
        fs::read(root.join("credentials/operator/client-id")).unwrap()
    );
    assert_eq!(
        fs::read(root.join("secrets/review-authority-casework-a-client-assertion-key")).unwrap(),
        fs::read(root.join("credentials/operator/assertion-key.jwk")).unwrap()
    );
    assert_eq!(
        fs::read(root.join("secrets/review-completion-casework-a-token")).unwrap(),
        b"synthetic-completion-token"
    );
    let rendered = String::from_utf8(runtime_bytes).unwrap();
    assert!(!rendered.contains("synthetic-completion-token"));
    assert!(!rendered.contains(completion.as_str()));
    registry_breg::runtime_config::load_runtime_config(&root.join("runtime-test.yaml")).unwrap();
}

#[test]
fn local_review_authorities_are_closed_and_bounded() {
    let (_temp, state, mut clients, _files) = fixture();
    let binding = config::LocalReviewAuthority {
        endpoint: "http://127.0.0.1:18096/".into(),
        profile: "integration-requester".into(),
        producer_id: "registry-producer".into(),
        recovery_days: 7,
        client: "operator".into(),
        completion_token_ref: None,
        completion_recipient: None,
    };
    clients
        .review_authorities
        .insert("casework-a".into(), binding.clone());
    config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap();

    for endpoint in [
        "https://casework.example/",
        "http://127.0.0.1/",
        "http://127.0.0.1:0/",
        "http://secret@127.0.0.1:18096/",
        "http://127.0.0.1:18096/?authority=other",
    ] {
        clients
            .review_authorities
            .get_mut("casework-a")
            .unwrap()
            .endpoint = endpoint.into();
        assert!(config::clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&clients).unwrap().into_bytes()
        )
        .is_err());
    }
    clients
        .review_authorities
        .get_mut("casework-a")
        .unwrap()
        .endpoint = "http://127.0.0.1:18096/".into();
    for invalid in [String::new(), "x".repeat(129), "bad profile".to_owned()] {
        clients
            .review_authorities
            .get_mut("casework-a")
            .unwrap()
            .profile = invalid;
        assert!(config::clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&clients).unwrap().into_bytes()
        )
        .is_err());
    }
    clients
        .review_authorities
        .get_mut("casework-a")
        .unwrap()
        .profile = "integration-requester".into();
    clients
        .review_authorities
        .get_mut("casework-a")
        .unwrap()
        .client = "undeclared-producer".into();
    assert!(config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes()
    )
    .is_err());

    clients.review_authorities.clear();
    for index in 0..9 {
        clients
            .review_authorities
            .insert(format!("casework-{index}"), binding.clone());
    }
    assert!(config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes()
    )
    .is_err());

    let secrets = secret_root(&state.project, &mut clients);
    let completion = file_secret(
        &secrets,
        "review-completion-token",
        b"synthetic-completion-token",
    );
    clients.review_authorities.clear();
    let mut mismatched = binding;
    mismatched.completion_token_ref = Some(completion);
    clients
        .review_authorities
        .insert("casework-a".into(), mismatched);
    let refusal = config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap_err()
    .to_string();
    assert!(refusal.contains("declared together"), "{refusal}");
}

#[test]
fn local_review_executors_require_one_declared_service_client_and_profile() {
    let (_temp, _state, mut clients, _files) = fixture();
    clients.review_executors.insert(
        "automatic-applier".into(),
        config::LocalReviewExecutor {
            access_profile: "operator".into(),
            client: "operator".into(),
        },
    );
    config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap();

    let mut invalid = clients.clone();
    invalid
        .review_executors
        .get_mut("automatic-applier")
        .unwrap()
        .client = "undeclared".into();
    assert!(config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&invalid).unwrap().into_bytes()
    )
    .is_err());

    let mut invalid = clients.clone();
    invalid
        .review_executors
        .get_mut("automatic-applier")
        .unwrap()
        .access_profile = "other-profile".into();
    assert!(config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&invalid).unwrap().into_bytes()
    )
    .is_err());

    let mut invalid = clients.clone();
    invalid
        .clients
        .iter_mut()
        .find(|client| client.id == "operator")
        .unwrap()
        .claims
        .insert("registry_actor_kind".into(), json!("agent"));
    assert!(config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&invalid).unwrap().into_bytes()
    )
    .is_err());

    let binding = clients.review_executors["automatic-applier"].clone();
    for index in 0..9 {
        clients
            .review_executors
            .insert(format!("automatic-applier-{index}"), binding.clone());
    }
    assert!(config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes()
    )
    .is_err());
}

#[test]
fn local_review_executor_uses_refreshing_service_identity_for_this_registry() {
    let (_project_temp, project) = write_init_project();
    let project_file = project.join("registry.yaml");
    let mut definition: Value =
        serde_norway::from_slice(&fs::read(&project_file).unwrap()).unwrap();
    definition["entities"].as_array_mut().unwrap().push(json!({
        "id": "automatic-record",
        "primaryDataset": "generic-registry",
        "route": "automatic-records",
        "mutationMode": "mutable",
        "classification": "internal",
        "changeControl": {"requiredFor":["create"]},
        "fields": [
            {"id":"code", "type":"string", "required":true, "minimumLength":1, "maximumLength":64, "classification":"internal"},
            {"id":"label", "type":"string", "required":true, "maximumLength":200, "classification":"internal"}
        ]
    }));
    definition["entities"].as_array_mut().unwrap().push(json!({
        "id": "record-change",
        "primaryDataset": "generic-registry",
        "route": "record-changes",
        "mutationMode": "mutable",
        "classification": "internal",
        "fields": [
            {"id":"code", "type":"string", "required":true, "minimumLength":1, "maximumLength":64, "classification":"internal"},
            {"id":"label", "type":"string", "required":true, "maximumLength":200, "classification":"internal"}
        ],
        "changeRequest": {
            "effects": [{
                "id": "created-record",
                "target": {"entity":"automatic-record"},
                "operation": "create",
                "set": {"code":{"fromField":"code"}, "label":{"fromField":"label"}}
            }],
            "review": {"type": "required", "authority":"casework", "policyId":"record-approval"},
            "onApproved": {"mode":"automatic", "executor":"automatic-applier"},
            "retention": {"mode":"operator-erase"}
        }
    }));
    let operator = definition["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|profile| profile["id"] == "operator")
        .unwrap();
    operator["permissions"]["entities"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "entity":"record-change",
            "operations":["create", "get", "patch", "submit-request"],
            "readableFields":["code", "label"],
            "writableFields":["code", "label"],
            "requestVisibility":"owner",
            "rowBoundaries":"unrestricted"
        }));
    definition["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"automatic-applier",
            "actorKind":"service",
            "requesterClients":["automatic-applier"],
            "principalClaim":"sub",
            "requiredScopes":["registry:generic:apply"],
            "requiredPurposes":["registry-application"],
            "permissions":{"entities":[{
                "entity":"record-change",
                "operations":["get", "apply-request"],
                "readableFields":["code", "label"],
                "rowBoundaries":"unrestricted",
            "applyTargets":[{"entity":"automatic-record", "rowBoundaries":"unrestricted"}],
                "readableRequestFields":["review-state"]
            }]}
        }));
    fs::write(&project_file, serde_norway::to_string(&definition).unwrap()).unwrap();

    let clients_file = project.join("dev-clients.yaml");
    let mut client_source: Value =
        serde_norway::from_slice(&fs::read(&clients_file).unwrap()).unwrap();
    client_source["clients"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"automatic-applier",
            "accessProfiles":["automatic-applier"],
            "scopes":["registry:generic:apply", "registry:unused"],
            "claims":{
                "registry_purpose":"registry-application"
            }
        }));
    client_source["reviewExecutors"] = json!({
        "automatic-applier": {
            "accessProfile":"automatic-applier",
            "client":"automatic-applier"
        }
    });
    let client_bytes = serde_norway::to_string(&client_source)
        .unwrap()
        .into_bytes();
    fs::write(&clients_file, &client_bytes).unwrap();
    let clients = config::clients("dev-clients.yaml", &client_bytes).unwrap();
    let captured = capture(&project, &client_bytes).unwrap();
    let (_state_temp, mut state, _, _) = fixture();
    state.instance_id = captured.instance_id;
    initialize(&state.root(), &state, &clients, &captured.files).unwrap();

    let root = state.root();
    let runtime_bytes = fs::read(root.join("runtime-test.yaml")).unwrap();
    let runtime: Value = serde_norway::from_slice(&runtime_bytes).unwrap();
    let executor = &runtime["reviewExecutors"]["automatic-applier"];
    assert_eq!(executor["endpoint"], state.breg_origin());
    assert_eq!(executor["registryId"], "generic-registry");
    assert_eq!(executor["accessProfile"], "automatic-applier");
    assert!(executor.get("tokenRef").is_none());
    let oauth = &executor["privateKeyJwt"];
    assert_eq!(oauth["tokenEndpoint"], "http://127.0.0.1:8095/oauth2/token");
    assert_eq!(oauth["assertionAudience"], "http://127.0.0.1:8095");
    assert_eq!(oauth["resource"], state.audience());
    assert_eq!(oauth["scopes"], json!(["registry:generic:apply"]));
    assert_eq!(
        oauth["clientIdRef"],
        "secret:file/review-executor-automatic-applier-client-id"
    );
    assert_eq!(
        oauth["clientAssertionKeyRef"],
        "secret:file/review-executor-automatic-applier-client-assertion-key"
    );
    assert_eq!(
        fs::read(root.join("secrets/review-executor-automatic-applier-client-id")).unwrap(),
        fs::read(root.join("credentials/automatic-applier/client-id")).unwrap()
    );
    assert_eq!(
        fs::read(root.join("secrets/review-executor-automatic-applier-client-assertion-key"))
            .unwrap(),
        fs::read(root.join("credentials/automatic-applier/assertion-key.jwk")).unwrap()
    );
    let compiled = crate::compile(&root.join("project"), crate::ProfileArg::Production, "dev")
        .unwrap_or_else(|failure| panic!("{}", serde_json::to_string(&failure).unwrap()));
    registry_breg::runtime_config::load_runtime_config(&root.join("runtime-test.yaml"))
        .unwrap()
        .activate_review_executors(&compiled)
        .expect("the authored automatic executor activates");
    assert!(!String::from_utf8(runtime_bytes)
        .unwrap()
        .contains("PRIVATE KEY"));
}

#[test]
fn local_evidence_provider_ids_follow_the_governed_evidence_grammar() {
    // The map key names a provider the registry project declares, and the
    // governed Evidence identifier grammar admits an underscore. A key this
    // file refuses is a declared provider a dev session can never bind.
    let (_temp, state, mut clients, _files) = fixture();
    let secrets = secret_root(&state.project, &mut clients);
    let token = file_secret(&secrets, "provider-token", b"synthetic-provider-token");
    let jwks = file_secret(&secrets, "provider-jwks", br#"{"keys":[]}"#);
    let provider = config::LocalEvidenceProvider {
        base_url: "http://127.0.0.1:18093".into(),
        trust_binding_id: "exact-local-trust-v1".into(),
        token_ref: Some(token),
        private_key_jwt: None,
        trusted_jwks_ref: jwks,
        revoked_key_ids: vec![],
        ca_bundle_ref: None,
    };
    for id in ["qualification", "trusted_provider", "provider-2"] {
        clients.evidence_providers.clear();
        clients
            .evidence_providers
            .insert(id.into(), provider.clone());
        config::clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&clients).unwrap().into_bytes(),
        )
        .unwrap_or_else(|error| panic!("{id}: {error}"));
    }
    // The grammar is closed in the other direction too: it is anchored on a
    // lowercase letter and admits no other byte.
    for id in ["2provider", "_provider", "Provider", "provider.two", ""] {
        clients.evidence_providers.clear();
        clients
            .evidence_providers
            .insert(id.into(), provider.clone());
        let refusal = config::clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&clients).unwrap().into_bytes(),
        )
        .unwrap_err()
        .to_string();
        assert!(refusal.contains("local identifier"), "{id}: {refusal}");
    }
}

#[test]
fn local_evidence_provider_refreshing_credentials_preserve_exact_authority() {
    let (_temp, state, mut clients, files) = fixture();
    let secrets = secret_root(&state.project, &mut clients);
    let key = secrets.join("assertion-key.jwk");
    config::keypair(&secrets).unwrap();
    let jwks = file_secret(&secrets, "provider-jwks", br#"{"keys":[]}"#);
    clients.evidence_providers.insert(
        "qualification".into(),
        config::LocalEvidenceProvider {
            base_url: "http://127.0.0.1:18093".into(),
            trust_binding_id: "exact-local-trust-v1".into(),
            token_ref: None,
            private_key_jwt: Some(config::LocalEvidencePrivateKeyJwt {
                token_endpoint: "http://127.0.0.1:18091/oauth2/token".into(),
                client_id: "guard-reader".into(),
                private_key_ref: SecretReference::parse("secret:file/assertion-key.jwk").unwrap(),
                assertion_audience: "http://127.0.0.1:18091".into(),
                resource: "urn:example:evidence".into(),
                scopes: vec!["evidence:invoke".into()],
            }),
            trusted_jwks_ref: jwks,
            revoked_key_ids: vec![],
            ca_bundle_ref: None,
        },
    );
    let serialized = serde_json::to_value(&clients).unwrap();
    config::clients(
        "dev-clients.yaml",
        &serde_json::to_vec(&serialized).unwrap(),
    )
    .unwrap();
    let oversized_scope_parameter = (0..32)
        .map(|index| format!("scope-{index:02}-{}", "a".repeat(119)))
        .collect::<Vec<_>>();
    for (name, value) in [
        ("tokenEndpoint", json!("https://elsewhere.example/token")),
        // The token endpoint carries the same port-zero hole as the provider
        // origin: it parses, it is not the scheme default, and it leaves every
        // credential refresh pointed at an unusable port.
        ("tokenEndpoint", json!("http://127.0.0.1:0/oauth2/token")),
        ("tokenEndpoint", json!("http://127.0.0.1/oauth2/token")),
        ("scopes", json!([])),
        ("scopes", json!(["evidence:invoke", "evidence:invoke"])),
        ("scopes", json!(oversized_scope_parameter)),
        ("clientId", json!(" \t")),
        ("resource", json!("not-a-resource")),
    ] {
        let mut rejected = serialized.clone();
        rejected["evidenceProviders"]["qualification"]["privateKeyJwt"][name] = value;
        assert!(
            config::clients("dev-clients.yaml", &serde_json::to_vec(&rejected).unwrap()).is_err()
        );
    }
    let mut both = serialized;
    both["evidenceProviders"]["qualification"]["tokenRef"] = json!("secret:file/provider-jwks");
    let refusal = config::clients("dev-clients.yaml", &serde_json::to_vec(&both).unwrap())
        .unwrap_err()
        .to_string();
    assert!(
        refusal.contains("exactly one tokenRef or privateKeyJwt"),
        "{refusal}"
    );
    initialize(&state.root(), &state, &clients, &files).unwrap();
    let document: Value =
        serde_norway::from_slice(&fs::read(state.root().join("runtime-test.yaml")).unwrap())
            .unwrap();
    let provider = &document["evidenceProviders"]["qualification"];
    assert!(provider["tokenRef"].is_null());
    let credential = &provider["privateKeyJwt"];
    assert_eq!(
        credential["privateKeyRef"],
        "secret:file/evidence-client-key-qualification"
    );
    assert_eq!(credential["resource"], "urn:example:evidence");
    assert_eq!(credential["scopes"], json!(["evidence:invoke"]));
    assert_eq!(credential["assertionAudience"], "http://127.0.0.1:18091");
    assert!(!serde_json::to_string(provider)
        .unwrap()
        .contains("secret:file/assertion-key.jwk"));
    assert_eq!(
        fs::read(
            state
                .root()
                .join("secrets/evidence-client-key-qualification")
        )
        .unwrap(),
        fs::read(key).unwrap()
    );
    assert!(!state
        .root()
        .join("secrets/evidence-token-qualification")
        .exists());
}

#[test]
fn local_evidence_provider_revocations_match_the_verifiers_bound() {
    let (_temp, state, mut clients, _files) = fixture();
    let secrets = secret_root(&state.project, &mut clients);
    let token = file_secret(&secrets, "provider-token", b"synthetic-provider-token");
    let jwks = file_secret(&secrets, "provider-jwks", br#"{"keys":[]}"#);
    let revoked_key_ids = (0..=33)
        .map(|index| URL_SAFE_NO_PAD.encode([index as u8; 32]))
        .collect::<Vec<_>>();
    clients.evidence_providers.insert(
        "qualification".into(),
        config::LocalEvidenceProvider {
            base_url: "http://127.0.0.1:18093".into(),
            trust_binding_id: "exact-local-trust-v1".into(),
            token_ref: Some(token),
            private_key_jwt: None,
            trusted_jwks_ref: jwks,
            revoked_key_ids: revoked_key_ids[..33].to_vec(),
            ca_bundle_ref: None,
        },
    );
    config::clients("dev-clients.yaml", &serde_json::to_vec(&clients).unwrap()).unwrap();
    clients
        .evidence_providers
        .get_mut("qualification")
        .unwrap()
        .revoked_key_ids = revoked_key_ids;
    assert!(config::clients("dev-clients.yaml", &serde_json::to_vec(&clients).unwrap()).is_err());
}

#[test]
fn event_free_sessions_keep_working_without_receiver_state() {
    let (_temp, state, clients, files) = fixture();
    assert_eq!(state.webhook_port, None);
    initialize(&state.root(), &state, &clients, &files).unwrap();
    assert_eq!(read_state(&state.root()).unwrap().webhook_port, None);
    assert!(!state.root().join("secrets/webhook-key").exists());
    let report = events::report(&state.root(), false).unwrap();
    assert_eq!(report["deliveries"], json!([]));
}

#[test]
fn fresh_token_rejects_path_clients_and_stopped_sessions_without_network() {
    let (_temp, state, clients, files) = fixture();
    for client in ["../operator", "/operator", "", "operator/header"] {
        assert!(fresh_token(&state.project, client)
            .unwrap_err()
            .to_string()
            .contains("bounded local client"));
    }
    initialize(&state.root(), &state, &clients, &files).unwrap();
    assert!(fresh_token(&state.project, "operator")
        .unwrap_err()
        .to_string()
        .contains("must be ready"));
    assert!(!state.root().join("secrets/operator.header").exists());
}

fn unused_ports() -> [u16; 3] {
    let sockets = [0; 3].map(|_| std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap());
    sockets
        .each_ref()
        .map(|socket| socket.local_addr().unwrap().port())
}

#[test]
fn candidate_issuer_image_is_immutable_and_retained() {
    let image = format!("sha256:{}", "a".repeat(64));
    assert_eq!(candidate_issuer_image(&image).unwrap(), image);
    for invalid in [
        "latest",
        "ghcr.io/example/candidate:latest",
        "sha256:short",
        &format!("sha256:{}", "A".repeat(64)),
    ] {
        assert!(candidate_issuer_image(invalid).is_err());
    }
    let (_temporary, mut state, _clients, _files) = fixture();
    state.issuer_image = Some(image.clone());
    let encoded = serde_json::to_vec(&state).unwrap();
    let restored = decode_state(&encoded).unwrap();
    assert_eq!(restored.issuer_image, Some(image));
}

#[test]
fn approved_grant_requires_explicit_connection_and_refuses_policy_fields() {
    let args = [
        "bregctl",
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
        "bregctl",
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
fn retained_database_selection_preserves_the_spatial_choice() {
    let (_temporary, mut state, _clients, _files) = fixture();
    assert!(!state.requires_postgis);
    let restored = decode_state(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert_eq!(restored.database_image(), IMAGE);
    state.requires_postgis = true;
    let restored = decode_state(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert_eq!(restored.database_image(), SPATIAL_IMAGE);
}

#[test]
fn spatial_prerequisites_provision_the_bbox_role_each_runtime_file_serves_with() {
    // The served database runs with one role and the schema-test rehearsal
    // with a separate runtime role; each derives its bbox owner from its own
    // runtime role, and only the migration role may SET it.
    for runtime in [MIGRATION_ROLE, RUNTIME_ROLE] {
        let bbox = registry_breg::postgres::spatial_bbox_role(
            &registry_breg::postgres::SqlIdentifier::parse(runtime).unwrap(),
        );
        let statements = spatial_prerequisites_sql(runtime);
        assert!(
            statements.contains(&format!("CREATE ROLE {} NOLOGIN", bbox.as_str())),
            "{statements}"
        );
        assert!(
            statements.contains(&format!(
                "GRANT {} TO {MIGRATION_ROLE} WITH INHERIT FALSE, SET TRUE",
                bbox.as_str()
            )),
            "{statements}"
        );
    }
}

const CLIENTS_HEADER: &str =
    "apiVersion: id.registrystack.org/formats/breg/dev-clients/v1alpha1\nkind: BRegDevClients\n";

const ONE_CLIENT: &str = "clients:
  - id: operator
    accessProfiles: [operator]
    scopes: [registry:generic:operate]
    claims: {registry_principal: generic-registry-operator, registry_purpose: registry-operations}
";

/// The reader's report for a clients file it refuses.
fn clients_refusal(bytes: &[u8]) -> registry_platform_yaml::Report {
    match config::clients("dev-clients.yaml", bytes)
        .expect_err("the reader refuses the clients file")
        .downcast::<ClientsRefused>()
    {
        Ok(refused) => refused.0,
        Err(error) => panic!("not a document refusal: {error:#}"),
    }
}

fn codes(report: &registry_platform_yaml::Report) -> Vec<&str> {
    report
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect()
}

#[test]
fn a_clients_file_without_the_header_is_refused_naming_the_current_one() {
    let report = clients_refusal(format!("version: 1\n{ONE_CLIENT}").as_bytes());
    assert_eq!(
        codes(&report),
        ["config.missing-envelope", "config.removed-key"],
        "{}",
        report.render_human()
    );
    let rendered = report.render_human();
    assert!(rendered.contains("dev-clients.yaml:1:1"), "{rendered}");
    assert!(
        rendered.contains("id.registrystack.org/formats/breg/dev-clients/v1alpha1")
            && rendered.contains("BRegDevClients"),
        "{rendered}"
    );
}

#[test]
fn every_removed_clients_member_is_refused_at_its_position_naming_its_replacement() {
    let document = format!(
        "{CLIENTS_HEADER}version: 1
clients:
  - id: operator
    accessProfiles: [operator]
    scopes: [registry:generic:operate]
    claims: {{registry_principal: generic-registry-operator, registry_purpose: registry-operations}}
    clientIdFile: /private/published-client-id
    assertionKeyFile: /private/published-assertion-key
    assertionKeyInputFile: /private/imported-assertion-key
eventDestinations:
  receiver:
    origin: http://127.0.0.1:18888
    path: /inbox
    hmacKeyFile: /private/hmac-key
evidenceProviders:
  qualification:
    baseUrl: http://127.0.0.1:18093
    trustBindingId: exact-local-trust-v1
    tokenFile: /private/provider-token
    trustedJwksFile: /private/provider-jwks
    caBundleFile: /private/provider-ca
    privateKeyJwt:
      tokenEndpoint: http://127.0.0.1:18091/oauth2/token
      clientId: guard-reader
      privateKeyFile: /private/provider-key
      assertionAudience: http://127.0.0.1:18091
      resource: urn:example:evidence
      scopes: [evidence:invoke]
reviewAuthorities:
  casework-a:
    endpoint: http://127.0.0.1:18096/
    profile: integration-requester
    producerId: registry-producer
    recoveryDays: 7
    client: operator
    completionTokenFile: /private/completion-token
    completionRecipient: registry-breg
issuer:
  interactiveApplications:
    - id: portal
      clientSecretFile: /private/portal-secret
      origin: http://127.0.0.1:3000
      redirectUris: [http://127.0.0.1:3000/callback]
      grants: [{{scopes: [registry:generic:operate]}}]
      tokenAttributes: []
  syntheticUsers:
    - username: staff
      email: staff@example.test
      passwordFile: /private/staff-password
      attributes: {{}}
      grants: [{{scopes: [registry:generic:operate]}}]
"
    );
    let report = clients_refusal(document.as_bytes());
    let rendered = report.render_human();
    let removed = report
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "config.removed-key")
        .map(|diagnostic| {
            let source = diagnostic
                .source
                .as_ref()
                .expect("a removed key has a position");
            assert!(source.line.is_some(), "{rendered}");
            (
                diagnostic.path.as_str(),
                diagnostic.suggested_action.as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for (path, replacement) in [
        ("/version", "apiVersion"),
        ("/clients/0/clientIdFile", "bregctl dev export-client"),
        ("/clients/0/assertionKeyFile", "bregctl dev export-client"),
        ("/clients/0/assertionKeyInputFile", "assertionKeyRef"),
        (
            "/eventDestinations/receiver/hmacKeyFile",
            "hmacSha256KeyRef",
        ),
        ("/evidenceProviders/qualification/tokenFile", "tokenRef"),
        (
            "/evidenceProviders/qualification/trustedJwksFile",
            "trustedJwksRef",
        ),
        (
            "/evidenceProviders/qualification/caBundleFile",
            "caBundleRef",
        ),
        (
            "/evidenceProviders/qualification/privateKeyJwt/privateKeyFile",
            "privateKeyRef",
        ),
        (
            "/reviewAuthorities/casework-a/completionTokenFile",
            "completionTokenRef",
        ),
        (
            "/issuer/interactiveApplications/0/clientSecretFile",
            "clientSecretRef",
        ),
        ("/issuer/syntheticUsers/0/passwordFile", "passwordRef"),
    ] {
        let fix = removed
            .get(path)
            .unwrap_or_else(|| panic!("{path} is not reported as removed: {rendered}"));
        assert!(fix.contains(replacement), "{path}: {fix}");
    }
    assert_eq!(removed.len(), 12, "{rendered}");
    assert!(
        !codes(&report).contains(&"config.unknown-key"),
        "a removed member is not also unknown: {rendered}"
    );
    assert!(
        !rendered.contains("/private/"),
        "no authored path is repeated: {rendered}"
    );
}

#[test]
fn every_unknown_clients_member_is_reported_with_its_position() {
    let document = format!(
        "{CLIENTS_HEADER}clients:
  - id: operator
    accessProfiles: [operator]
    scopes: [registry:generic:operate]
    claims: {{registry_principal: generic-registry-operator, registry_purpose: registry-operations}}
    assertionKey: secret:file/operator-key
seed: []
secretProvider: {{environment: {{}}}}
"
    );
    let report = clients_refusal(document.as_bytes());
    let rendered = report.render_human();
    let unknown = report
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "config.unknown-key")
        .map(|diagnostic| {
            let source = diagnostic
                .source
                .as_ref()
                .expect("an unknown key has a position");
            (diagnostic.path.as_str(), source.line)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        unknown,
        [
            ("/clients/0/assertionKey", Some(8)),
            ("/secretProvider", Some(10))
        ],
        "{rendered}"
    );
    assert!(
        rendered.contains("secretProviders"),
        "the closest key is named: {rendered}"
    );
}

#[test]
fn a_secret_reference_needs_a_declared_provider() {
    let (_temp, state, mut clients, _files) = fixture();
    let secrets = secret_root(&state.project, &mut clients);
    let completion = file_secret(
        &secrets,
        "review-completion-token",
        b"synthetic-completion-token",
    );
    clients.review_authorities.insert(
        "casework-a".into(),
        config::LocalReviewAuthority {
            endpoint: "http://127.0.0.1:18096/".into(),
            profile: "integration-requester".into(),
            producer_id: "registry-producer".into(),
            recovery_days: 7,
            client: "operator".into(),
            completion_token_ref: Some(completion.clone()),
            completion_recipient: Some("registry-breg".into()),
        },
    );
    config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .expect("a declared file provider resolves the reference");

    let mut undeclared = clients.clone();
    undeclared.secret_providers = None;
    let refusal = format!(
        "{:#}",
        config::clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&undeclared).unwrap().into_bytes()
        )
        .unwrap_err()
    );
    assert!(
        refusal.contains("reviewAuthorities.casework-a.completionTokenRef names a secret")
            && refusal.contains("declares no secretProviders"),
        "{refusal}"
    );
    assert!(!refusal.contains(completion.as_str()), "{refusal}");

    // A reference to a provider the file does not enable is refused, naming
    // the member and the block that enables it.
    let mut disabled = clients.clone();
    disabled
        .review_authorities
        .get_mut("casework-a")
        .unwrap()
        .completion_token_ref =
        Some(SecretReference::parse("secret:env/BREGCTL_DEV_UNSET_SECRET").unwrap());
    let refusal = format!(
        "{:#}",
        config::clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&disabled).unwrap().into_bytes()
        )
        .unwrap_err()
    );
    assert!(
        refusal.contains("completionTokenRef could not be resolved")
            && refusal.contains("declare the provider the reference names under secretProviders"),
        "{refusal}"
    );
    assert!(!refusal.contains("BREGCTL_DEV_UNSET_SECRET"), "{refusal}");
}

#[test]
fn an_environment_reference_resolves_through_the_declared_provider() {
    // Cargo sets its package variables in the environment of every test it
    // runs, so the test reads one without writing the process environment.
    assert_eq!(
        std::env::var("CARGO_PKG_NAME").as_deref(),
        Ok(env!("CARGO_PKG_NAME"))
    );
    let (_temp, state, mut clients, files) = fixture();
    clients.secret_providers = Some(SecretProvidersConfig {
        file: None,
        environment: Some(registry_platform_config::EnvironmentSecretProviderConfig {}),
    });
    let binding = config::LocalReviewAuthority {
        endpoint: "http://127.0.0.1:18096/".into(),
        profile: "integration-requester".into(),
        producer_id: "registry-producer".into(),
        recovery_days: 7,
        client: "operator".into(),
        completion_token_ref: Some(SecretReference::parse("secret:env/CARGO_PKG_NAME").unwrap()),
        completion_recipient: Some("registry-breg".into()),
    };
    clients
        .review_authorities
        .insert("casework-a".into(), binding.clone());
    config::clients(
        "dev-clients.yaml",
        &serde_norway::to_string(&clients).unwrap().into_bytes(),
    )
    .unwrap();
    initialize(&state.root(), &state, &clients, &files).unwrap();
    assert_eq!(
        fs::read(
            state
                .root()
                .join("secrets/review-completion-casework-a-token")
        )
        .unwrap(),
        env!("CARGO_PKG_NAME").as_bytes()
    );

    let mut unset = binding;
    unset.completion_token_ref =
        Some(SecretReference::parse("secret:env/BREGCTL_DEV_UNSET_SECRET").unwrap());
    clients
        .review_authorities
        .insert("casework-a".into(), unset);
    let refusal = format!(
        "{:#}",
        config::clients(
            "dev-clients.yaml",
            &serde_norway::to_string(&clients).unwrap().into_bytes()
        )
        .unwrap_err()
    );
    assert!(
        refusal.contains("completionTokenRef could not be resolved")
            && refusal.contains("set the environment variable the reference names"),
        "{refusal}"
    );
    assert!(!refusal.contains("BREGCTL_DEV_UNSET_SECRET"), "{refusal}");
}

#[test]
fn a_secret_file_must_be_owner_only_and_within_its_bound() {
    let (_temp, state, mut clients, _files) = fixture();
    let secrets = secret_root(&state.project, &mut clients);
    let password = file_secret(
        &secrets,
        "staff-password",
        b"synthetic-staff-password-for-test",
    );
    clients.issuer.synthetic_users.push(config::BrowserUser {
        username: "staff".into(),
        email: "staff@example.test".into(),
        password_ref: password,
        attributes: BTreeMap::new(),
        grants: vec![config::LocalPermissionGrant {
            audience: None,
            scopes: vec!["registry:generic:operate".into()],
        }],
    });
    let check = |clients: &Clients| {
        config::clients(
            "dev-clients.yaml",
            &serde_norway::to_string(clients).unwrap().into_bytes(),
        )
        .map_err(|error| format!("{error:#}"))
    };
    check(&clients).unwrap();

    let file = secrets.join("staff-password");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    let refusal = check(&clients).unwrap_err();
    assert!(
        refusal.contains("issuer.syntheticUsers.staff.passwordRef could not be resolved")
            && refusal.contains("mode 0400 or 0600"),
        "{refusal}"
    );
    assert!(
        !refusal.contains("staff-password") && !refusal.contains("synthetic-staff"),
        "{refusal}"
    );

    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    private::replace(&file, &[b'p'; 1025]).unwrap();
    let refusal = check(&clients).unwrap_err();
    assert!(
        refusal.contains("passwordRef is larger than its 1024-byte limit"),
        "{refusal}"
    );
}

#[test]
fn retained_clients_round_trip_through_the_shared_reader() {
    let (_temp, state, mut clients, _files) = fixture();
    let secrets = secret_root(&state.project, &mut clients);
    clients.clients[1].assertion_key_ref = Some(file_secret(&secrets, "source-key", b"{}"));
    let written = serde_json::to_vec(&clients).unwrap();
    let written_value: Value = serde_json::from_slice(&written).unwrap();
    assert_eq!(
        written_value["apiVersion"],
        "id.registrystack.org/formats/breg/dev-clients/v1alpha1"
    );
    assert_eq!(written_value["kind"], "BRegDevClients");
    assert!(written_value.get("version").is_none());
    let read = config::retained(&written).expect("the retained document reads back");
    assert_eq!(serde_json::to_value(&read).unwrap(), written_value);
    // The retained copy is read through the same reader as the authored file,
    // so a retained document from an earlier bregctl is refused.
    let mut earlier = written_value;
    earlier.as_object_mut().unwrap().remove("apiVersion");
    earlier.as_object_mut().unwrap().remove("kind");
    earlier["version"] = json!(1);
    assert!(config::retained(&serde_json::to_vec(&earlier).unwrap()).is_err());
    // The session commands name the way out of a session an earlier bregctl
    // started.
    let root = state.project.join("earlier-session");
    private::directory(&root).unwrap();
    private::create(
        &root.join("clients.json"),
        &serde_json::to_vec(&earlier).unwrap(),
    )
    .unwrap();
    let refusal = retained_clients(&root).unwrap_err().to_string();
    assert!(
        refusal.starts_with("retained clients are invalid"),
        "{refusal}"
    );
    assert!(
        refusal.contains("bregctl dev stop --remove with that bregctl"),
        "{refusal}"
    );
}

#[test]
fn the_grant_report_carries_the_diagnostics_member_every_report_has() {
    let report = grant_report(&registry_thunderid_tooling::grant_file::GrantOutput {
        header_file: PathBuf::from("/project/.breg/grant.header"),
        grant_expires_at: 1_700_000_000,
    });
    assert_eq!(
        report,
        json!({
            "ok": true,
            "command": "dev grant",
            "headerFile": "/project/.breg/grant.header",
            "grantExpiresAt": 1_700_000_000,
            "diagnostics": []
        })
    );
}
