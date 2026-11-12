use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::*;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/identity");

fn fixture(name: &str) -> String {
    fs::read_to_string(Path::new(DIR).join(name)).expect("fixture")
}

struct Case {
    deployment: String,
    facts: Vec<(String, String)>,
    jwks: BTreeMap<String, Vec<u8>>,
}

fn case() -> Case {
    Case {
        deployment: fixture("deployment.yaml"),
        facts: vec![
            ("breg".into(), fixture("facts-breg.yaml")),
            ("evidence".into(), fixture("facts-evidence.yaml")),
        ],
        jwks: ["case-portal", "field-agent", "task-agent"]
            .into_iter()
            .map(|name| {
                (
                    format!("keys/{name}.jwks.json"),
                    fixture(&format!("keys/{name}.jwks.json")).into_bytes(),
                )
            })
            .collect(),
    }
}

impl Case {
    fn run(&self) -> Result<Generated, ToolingError> {
        let facts: Vec<Source<'_>> = self
            .facts
            .iter()
            .map(|(label, text)| Source {
                label,
                bytes: text.as_bytes(),
            })
            .collect();
        generate(&Inputs {
            deployment: Source {
                label: "deployment.yaml",
                bytes: self.deployment.as_bytes(),
            },
            facts: &facts,
            public_jwks: &self.jwks,
        })
    }

    /// The diagnostic or refusal code the run ends with.
    fn refusal(&self) -> Vec<String> {
        match self.run() {
            Ok(_) => panic!("the run was accepted"),
            Err(ToolingError::IdentityRefused { code, .. }) => vec![code.to_owned()],
            Err(error) => error
                .report()
                .map(|report| {
                    report
                        .diagnostics()
                        .iter()
                        .map(|diagnostic| diagnostic.code.clone())
                        .collect()
                })
                .unwrap_or_else(|| panic!("unexpected error: {error}")),
        }
    }
}

fn text(generated: &Generated, path: &str) -> String {
    String::from_utf8(generated.files[path].clone()).expect("utf-8")
}

#[test]
fn a_deployment_renders_every_output_file() {
    let generated = case().run().expect("generates");
    let mut paths: Vec<_> = generated.files.keys().map(String::as_str).collect();
    paths.sort_unstable();
    let agents: Vec<_> = paths
        .iter()
        .filter(|path| path.starts_with("registry-schema/agents/"))
        .collect();
    assert_eq!(agents.len(), 3, "one agent per machine client");
    for expected in [
        "deployment.yaml",
        "identity-receipt.json",
        "registry-schema/agent-type.yaml",
        "resources/resources.yaml",
    ] {
        assert!(paths.contains(&expected), "missing {expected}");
    }
    assert_eq!(paths.len(), 7);
    assert!(text(&generated, "deployment.yaml").contains("public_url: https://id.registry.example"));
}

/// ThunderID loads `connection` resources into its identity-provider store
/// only when that store reads files (composite or declarative); the mutable
/// default ignores them, so an exchange would find no assertion authority.
#[test]
fn the_deployment_fragment_lets_thunderid_load_the_generated_connections() {
    let generated = case().run().expect("generates");
    assert!(text(&generated, "resources/resources.yaml").contains("resource_type: connection"));
    let deployment = parse(&text(&generated, "deployment.yaml"));
    assert_eq!(deployment["identity_provider"]["store"], "composite");
}

#[test]
fn deployment_display_text_never_says_local() {
    let generated = case().run().expect("generates");
    for (path, bytes) in &generated.files {
        let text = String::from_utf8_lossy(bytes);
        // `local_attribute` is the upstream mapping key, not display text.
        let text = text.replace("local_attribute", "");
        assert!(
            !text.to_lowercase().contains("local"),
            "{path} describes a deployment as local"
        );
    }
    let resources = text(&generated, "resources/resources.yaml");
    assert!(resources.contains("description: Resource records"));
    assert!(resources.contains("description: Permission records:get"));
}

#[test]
fn two_runs_are_byte_identical() {
    let first = case().run().unwrap();
    let second = case().run().unwrap();
    assert_eq!(first.files, second.files);
}

#[test]
fn secrets_render_as_placeholders_and_nothing_secret_reaches_the_schema_directory() {
    let generated = case().run().unwrap();
    let resources = text(&generated, "resources/resources.yaml");
    for name in [
        "STAFF_PORTAL_CLIENT_SECRET",
        "OFFICER_ONE_PASSWORD",
        "FARMER_ONE_PASSWORD",
    ] {
        assert!(resources.contains(&format!("{{{{.{name}}}}}")), "{name}");
    }
    for (path, bytes) in &generated.files {
        if path.starts_with("registry-schema/") {
            let content = String::from_utf8_lossy(bytes);
            assert!(!content.contains("{{."), "{path} carries a placeholder");
            assert!(!content.contains("clientSecret"), "{path} carries a secret");
            assert!(!content.contains("password"), "{path} carries a password");
        }
    }
    assert_eq!(
        generated.summary.required_environment,
        [
            "FARMER_ONE_PASSWORD",
            "OFFICER_ONE_PASSWORD",
            "STAFF_PORTAL_CLIENT_SECRET"
        ]
    );
}

#[test]
fn private_key_material_is_refused() {
    for member in ["d", "p", "q", "dp", "dq", "qi"] {
        let mut case = case();
        let mut jwks: serde_json::Value =
            serde_json::from_slice(&case.jwks["keys/case-portal.jwks.json"]).unwrap();
        jwks["keys"][0][member] = serde_json::json!("c2VjcmV0");
        case.jwks.insert(
            "keys/case-portal.jwks.json".into(),
            serde_json::to_vec(&jwks).unwrap(),
        );
        assert_eq!(
            case.refusal(),
            ["identity.deployment.private-key-material"],
            "{member}"
        );
    }
}

#[test]
fn a_missing_or_malformed_key_file_is_refused() {
    let mut missing = case();
    missing.jwks.remove("keys/field-agent.jwks.json");
    assert_eq!(missing.refusal(), ["identity.deployment.missing-key-file"]);
    let mut malformed = case();
    malformed
        .jwks
        .insert("keys/field-agent.jwks.json".into(), b"{\"keys\":[]}".to_vec());
    assert_eq!(malformed.refusal(), ["identity.deployment.invalid-key-file"]);
}

#[test]
fn an_http_issuer_is_refused_for_a_deployment_and_dev_stays_loopback_only() {
    let mut case = case();
    for (_, facts) in &mut case.facts {
        *facts = facts.replace("https://id.registry.example", "http://127.0.0.1:8091");
    }
    assert_eq!(case.refusal(), ["identity.facts.issuer-not-https"]);

    // Development validation still refuses a hosted (https) browser origin.
    use crate::description::InteractiveApplication;
    let mut description = crate::testing::synthetic_description();
    description
        .interactive_applications
        .push(InteractiveApplication {
            id: "0197aaaa-0000-7000-8000-0000000000e1".into(),
            client_id: "browser".into(),
            client_secret_file: "secrets/app".into(),
            origin: "https://staff.registry.example".into(),
            redirect_uris: vec!["https://staff.registry.example/cb".into()],
            audience: description.resource_servers[0].identifier.clone(),
            token_attributes: vec!["registry_role".into()],
        });
    assert!(description.validate().is_err());
}

#[test]
fn products_that_disagree_on_the_issuer_or_a_claim_type_are_refused() {
    let mut issuers = case();
    issuers.facts[1].1 = issuers.facts[1]
        .1
        .replace("https://id.registry.example", "https://other.example");
    assert_eq!(issuers.refusal(), ["identity.facts.issuer-mismatch"]);
    let mut claims = case();
    claims.facts[1].1 = claims.facts[1]
        .1
        .replace("registry_actor_kind: string", "registry_actor_kind: string-array");
    assert_eq!(claims.refusal(), ["identity.facts.claim-conflict"]);
}

#[test]
fn a_grant_to_a_client_a_product_does_not_admit_is_refused() {
    // breg admits case-portal and staff-portal only.
    let mut case = case();
    case.deployment = case.deployment.replace(
        "      - product: evidence\n        accessProfiles: [invoke]\n    claims:\n      registry_actor_kind: service\n      evidence_audience",
        "      - product: breg\n        accessProfiles: [case-read]\n    claims:\n      registry_actor_kind: service\n      evidence_audience",
    );
    assert_eq!(case.refusal(), ["identity.deployment.client-not-admitted"]);
}

#[test]
fn a_grant_beyond_a_profiles_requester_clients_is_refused() {
    // evidence admits everyone, but `invoke` is for field-agent alone.
    let mut case = case();
    case.deployment = case.deployment.replace(
        "    grants:\n      - product: breg\n        accessProfiles: [case-read]\n    claims:\n      registry_actor_kind: service\n  - id: field-agent",
        "    grants:\n      - product: evidence\n        accessProfiles: [invoke]\n    claims:\n      registry_actor_kind: service\n  - id: field-agent",
    );
    assert_eq!(case.refusal(), ["identity.deployment.client-not-admitted"]);
}

#[test]
fn unknown_products_and_profiles_are_refused() {
    let mut product = case();
    product.deployment = product.deployment.replace("product: evidence\n        accessProfiles: [invoke]", "product: nowhere\n        accessProfiles: [invoke]");
    assert_eq!(product.refusal(), ["identity.deployment.unknown-product"]);
    let mut profile = case();
    profile.deployment = profile.deployment.replace("accessProfiles: [invoke]", "accessProfiles: [missing]");
    assert_eq!(profile.refusal(), ["identity.deployment.unknown-profile"]);
}

#[test]
fn user_claims_are_validated_against_the_merged_facts() {
    let mut unknown = case();
    unknown.deployment = unknown
        .deployment
        .replace("registry_role: officer", "registry_rank: officer");
    assert_eq!(unknown.refusal(), ["identity.deployment.unknown-claim"]);
    let mut typed = case();
    typed.deployment = typed
        .deployment
        .replace("registry_role: officer", "evidence_tags: officer");
    assert_eq!(typed.refusal(), ["identity.deployment.claim-type"]);
    let mut client_claim = case();
    client_claim.deployment = client_claim
        .deployment
        .replace("evidence_tags: [field]", "evidence_tags: field");
    assert_eq!(client_claim.refusal(), ["identity.deployment.claim-type"]);
}

#[test]
fn several_purposes_need_an_explicit_choice() {
    let mut case = case();
    case.facts[0].1 = case.facts[0]
        .1
        .replace("purposes: [eligibility]", "purposes: [eligibility, audit]");
    // case-portal and both users hold case-read.
    assert_eq!(
        case.refusal(),
        ["identity.deployment.ambiguous-purpose"; 3]
    );
    case.deployment = case
        .deployment
        .replace(
            "    claims:\n      registry_actor_kind: service\n  - id: field-agent",
            "    claims:\n      registry_actor_kind: service\n      registry_purpose: audit\n  - id: field-agent",
        )
        .replace(
            "      registry_actor_kind: human\n",
            "      registry_actor_kind: human\n      registry_purpose: audit\n",
        );
    let generated = case.run().expect("an explicit purpose is accepted");
    let agent = agent_for(&generated, "case-portal");
    assert_eq!(agent["attributes"]["registry_purpose"], "audit");
    let documents = resources(&generated);
    assert!(of_type(&documents, "user")
        .iter()
        .all(|user| user["attributes"]["registry_purpose"] == "audit"));
}

#[test]
fn only_the_purposes_of_a_product_that_reads_the_claim_are_derived_or_checked() {
    // Evidence takes its purpose from the request, not from a token claim,
    // so its profiles' purposes neither choose nor contradict the
    // registry_purpose BReg reads.
    let mut case = case();
    case.facts[1].1 = case.facts[1].1.replace(
        "    requesterClients: [field-agent]\n",
        "    purposes: [readiness, audit]\n    requesterClients: [field-agent]\n",
    );
    let generated = case.run().expect("Evidence purposes do not make a token ambiguous");
    assert!(agent_for(&generated, "field-agent")["attributes"]
        .get("registry_purpose")
        .is_none());
    assert_eq!(
        agent_for(&generated, "case-portal")["attributes"]["registry_purpose"],
        "eligibility"
    );
}

#[test]
fn a_machine_client_cannot_claim_to_be_human_nor_a_user_a_service() {
    let mut machine = case();
    machine.deployment = machine.deployment.replacen(
        "      registry_actor_kind: service",
        "      registry_actor_kind: human",
        1,
    );
    assert!(machine
        .refusal()
        .contains(&"identity.deployment.actor-kind-mismatch".to_owned()));
    let mut user = case();
    user.deployment = user.deployment.replacen(
        "      registry_actor_kind: human",
        "      registry_actor_kind: service",
        1,
    );
    assert_eq!(user.refusal(), ["identity.deployment.actor-kind-mismatch"]);
}

#[test]
fn an_actor_kind_the_runtime_cannot_parse_is_refused_on_a_profile_that_names_no_kind() {
    // case-portal holds only case-read, which neither selects by nor
    // requires an actor kind, so only the closed set of kinds refuses it.
    for kind in ["robot", "Service"] {
        let mut case = case();
        case.deployment = case.deployment.replacen(
            "      registry_actor_kind: service",
            &format!("      registry_actor_kind: {kind}"),
            1,
        );
        assert!(
            case.refusal()
                .contains(&"identity.deployment.unknown-actor-kind".to_owned()),
            "accepted {kind}"
        );
    }
}

#[test]
fn the_actor_kind_follows_the_principal_when_the_operator_states_none() {
    let mut case = case();
    case.deployment = case
        .deployment
        .replace("      registry_actor_kind: human\n", "");
    let generated = case.run().expect("generates");
    let resources = text(&generated, "resources/resources.yaml");
    // Each user still carries the human kind, derived from the principal.
    assert!(resources.matches("registry_actor_kind: human").count() >= 2);
}

/// The fixture with a BReg profile that requires `kind` of whoever holds
/// it, without selecting it by that claim, the way Messaging
/// resolves a profile by client id and then checks the kind.
fn case_with_profile_requiring(kind: &str) -> Case {
    let mut case = case();
    case.facts[0]
        .1
        .push_str(&format!("  - id: case-kind\n    scopes: [records:get]\n    actorKind: {kind}\n"));
    case
}

const CASE_PORTAL_GRANT: &str =
    "        accessProfiles: [case-read]\n    claims:\n      registry_actor_kind: service\n";

#[test]
fn a_machine_clients_kind_follows_a_granted_profile_that_requires_one() {
    let mut case = case_with_profile_requiring("agent");
    case.deployment = case
        .deployment
        .replacen(CASE_PORTAL_GRANT, "        accessProfiles: [case-kind]\n", 1);
    let generated = case.run().expect("generates");
    let agent = agent_for(&generated, "case-portal");
    assert_eq!(agent["attributes"]["registry_actor_kind"], "agent");
}

#[test]
fn a_principal_of_another_kind_than_a_granted_profile_requires_is_refused() {
    let mut machine = case_with_profile_requiring("agent");
    machine.deployment = machine.deployment.replacen(
        CASE_PORTAL_GRANT,
        &CASE_PORTAL_GRANT.replace("[case-read]", "[case-kind]"),
        1,
    );
    assert_eq!(
        machine.refusal(),
        ["identity.deployment.profile-requires-actor-kind"]
    );
    let mut user = case_with_profile_requiring("service");
    user.deployment = user.deployment.replacen(
        "accessProfiles: [case-read, case-write]",
        "accessProfiles: [case-read, case-kind]",
        1,
    );
    assert_eq!(
        user.refusal(),
        ["identity.deployment.profile-requires-actor-kind"]
    );
}

/// Add to `case` an Evidence standing profile that admits only humans and
/// services, the way Evidence refuses an agent without a task grant every
/// profile that does not name agents.
fn with_standing_profile(mut case: Case) -> Case {
    case.facts[1].1 = case.facts[1].1.replace(
        "assertionIssuers:\n",
        "  - id: standing\n    scopes: [evidence:standing]\n    admittedActorKinds: [human, service]\n    requiredClaims: [registry_actor_kind]\nassertionIssuers:\n",
    );
    case.deployment = case.deployment.replacen(
        "        accessProfiles: [task-invoke]\n",
        "        accessProfiles: [task-invoke, standing]\n",
        1,
    );
    case
}

#[test]
fn a_principal_of_a_kind_a_granted_profile_does_not_admit_is_refused() {
    // An agent stated by hand.
    assert_eq!(
        with_standing_profile(case()).refusal(),
        ["identity.deployment.profile-refuses-actor-kind"]
    );
    // An agent derived from Casework's task-assert, which requires one of
    // the client's own token.
    assert_eq!(
        with_standing_profile(case_with_task_assert("")).refusal(),
        ["identity.deployment.profile-refuses-actor-kind"]
    );
    // A service the profile admits is generated.
    let mut service = with_standing_profile(case());
    service.deployment = service
        .deployment
        .replacen("[task-invoke, standing]", "[task-invoke]", 1)
        .replacen(
            "        accessProfiles: [invoke]\n",
            "        accessProfiles: [invoke, standing]\n",
            1,
        );
    service.run().expect("generates");
}

#[test]
fn a_principal_carrying_a_claim_a_granted_profile_refuses_is_refused() {
    let mut case = case();
    case.facts[1].1 = case
        .facts[1]
        .1
        .replace(
            "  evidence_tags: string-array\n",
            "  evidence_tags: string-array\n  evidence_actor: string\n",
        )
        .replace(
            "    requesterClients: [field-agent]\n",
            "    requesterClients: [field-agent]\n    refusedClaims: [evidence_actor]\n",
        );
    case.run().expect("generates without the claim");
    case.deployment = case.deployment.replacen(
        "      evidence_tags: [field]\n",
        "      evidence_tags: [field]\n      evidence_actor: officer-one\n",
        1,
    );
    assert_eq!(
        case.refusal(),
        ["identity.deployment.profile-refuses-claim"]
    );
}

#[test]
fn a_machine_client_granted_a_profile_that_requires_a_human_is_refused() {
    let mut case = case_with_profile_requiring("human");
    case.deployment = case
        .deployment
        .replacen(CASE_PORTAL_GRANT, "        accessProfiles: [case-kind]\n", 1);
    assert_eq!(
        case.refusal(),
        ["identity.deployment.machine-requires-human"]
    );
}

#[test]
fn claims_that_select_an_ungranted_profile_are_refused() {
    // case-portal is granted only BReg profiles; these claims select the
    // Evidence `invoke` profile, whose requester clients admit case-portal.
    let mut case = case();
    case.facts[1].1 = case.facts[1].1.replace(
        "requesterClients: [field-agent]",
        "requesterClients: [case-portal, field-agent]",
    );
    case.deployment = case.deployment.replacen(
        "    claims:\n      registry_actor_kind: service\n  - id: field-agent",
        "    claims:\n      registry_actor_kind: service\n      evidence_tags: [field]\n  - id: field-agent",
        1,
    );
    assert_eq!(
        case.refusal(),
        ["identity.deployment.claims-select-ungranted-profile"]
    );
}

#[test]
fn a_granted_profile_the_clients_claims_cannot_select_is_refused() {
    let mut case = case();
    case.deployment = case
        .deployment
        .replace("evidence_tags: [field]", "evidence_tags: [other]");
    assert_eq!(
        case.refusal(),
        ["identity.deployment.profile-not-selectable"]
    );
}

#[test]
fn a_profile_without_selectors_is_never_checked_against_claims() {
    // BReg states no selectors; its clients may carry any declared claims.
    let mut case = case();
    case.facts[1].1 = case.facts[1]
        .1
        .replace("    selectedBy:\n      registry_actor_kind: [service]\n      evidence_tags: [field]\n", "")
        .replace("    selectedBy:\n      registry_actor_kind: [agent]\n", "");
    assert!(case.run().is_ok());
}

#[test]
fn each_principal_kind_has_its_own_identifier_namespace() {
    // A machine client whose id spells another kind's prefix plus a user's id
    // must not share that user's `sub`.
    let mut case = case();
    case.deployment = case.deployment.replacen(
        "clients:\n",
        "clients:\n  - id: user-officer-one\n    publicJwksFile: keys/case-portal.jwks.json\n    grants:\n      - product: breg\n        accessProfiles: [case-read]\n    claims:\n      registry_actor_kind: service\n",
        1,
    );
    case.facts[0].1 = case.facts[0]
        .1
        .replace("  - staff-portal\n", "  - staff-portal\n  - user-officer-one\n");
    let generated = case.run().expect("generates");
    let receipt: serde_json::Value =
        serde_json::from_str(&text(&generated, "identity-receipt.json")).unwrap();
    let sid = deployment_session_id("https://id.registry.example");
    let machine = local::derived_uuid(&format!("{sid}:machine:user-officer-one"));
    let user = local::derived_uuid(&format!("{sid}:user:officer-one"));
    assert_ne!(machine, user);
    assert_eq!(receipt["clients"]["user-officer-one"]["sub"], machine);
    assert_eq!(receipt["users"]["officer-one"]["sub"], user);
    assert!(receipt["clients"].get("officer-one").is_none());
    assert_eq!(
        receipt["clients"]["staff-portal"]["sub"],
        local::derived_uuid(&format!("{sid}:application:staff-portal"))
    );
}

fn parse(text: &str) -> serde_json::Value {
    #[allow(
        clippy::disallowed_methods,
        reason = "reads back a ThunderID resource this crate rendered, an external format (platform/thunderid-resources) ThunderID owns"
    )]
    serde_norway::from_str(text).expect("yaml")
}

fn agent_for(generated: &Generated, client: &str) -> serde_json::Value {
    generated
        .files
        .iter()
        .filter(|(path, _)| path.starts_with("registry-schema/agents/"))
        .map(|(_, bytes)| parse(std::str::from_utf8(bytes).unwrap()))
        .find(|agent| agent["inboundAuthConfig"][0]["config"]["clientId"] == client)
        .expect("agent")
}

fn resources(generated: &Generated) -> Vec<serde_json::Value> {
    text(generated, "resources/resources.yaml")
        .split("---\n")
        .filter(|part| !part.trim().is_empty())
        .map(parse)
        .collect()
}

fn of_type<'a>(documents: &'a [serde_json::Value], kind: &str) -> Vec<&'a serde_json::Value> {
    documents
        .iter()
        .filter(|document| document["resource_type"] == kind)
        .collect()
}

fn role_permissions(
    documents: &[serde_json::Value],
    role_name: &str,
    audience: &str,
) -> Vec<String> {
    let server = of_type(documents, "resource_server")
        .into_iter()
        .find(|server| server["identifier"] == audience)
        .expect("resource server");
    let role = of_type(documents, "role")
        .into_iter()
        .find(|role| role["name"] == role_name)
        .expect("role");
    role["permissions"]
        .as_array()
        .expect("role permissions")
        .iter()
        .find(|permission| permission["resourceServerId"] == server["id"])
        .expect("resource permission")["permissions"]
        .as_array()
        .expect("permission names")
        .iter()
        .map(|permission| permission.as_str().expect("permission").to_owned())
        .collect()
}

const CASEWORK_BROWSER: &str = "apiVersion: id.registrystack.org/formats/platform/identity-facts/v1\nkind: PlatformIdentityFacts\nproduct: casework\nissuer: https://id.registry.example\naudience: urn:casework:example\nallowedClients:\n  - staff-portal\nclaims:\n  registry_actor_kind: string\naccessProfiles:\n  - id: review\n    scopes: [casework:review]\n    actorKind: human\n  - id: intake\n    scopes: [casework:intake]\n    actorKind: human\n";

fn cross_resource_browser_case(app_profile: &str) -> Case {
    let mut case = case();
    case.facts
        .push(("casework".into(), CASEWORK_BROWSER.into()));
    case.deployment = case
        .deployment
        .replace(
            "      - product: breg\n        accessProfiles: [case-read]\nusers:\n",
            &format!(
                "      - product: breg\n        accessProfiles: [case-read]\n      - product: casework\n        accessProfiles: [{app_profile}]\nusers:\n"
            ),
        )
        .replace(
            "      - product: breg\n        accessProfiles: [case-read, case-write]\n  - id: farmer-one\n",
            "      - product: breg\n        accessProfiles: [case-read, case-write]\n      - product: casework\n        accessProfiles: [review]\n  - id: farmer-one\n",
        );
    case
}

fn reverse_cross_resource_browser_case() -> Case {
    let mut case = cross_resource_browser_case("review");
    case.deployment = case
        .deployment
        .replace(
            "    redirectUris: [https://staff.registry.example/auth/callback]\n    product: breg\n",
            "    redirectUris: [https://staff.registry.example/auth/callback]\n    product: casework\n",
        )
        .replace(
            "        accessProfiles: [case-read, case-write]\n      - product: casework",
            "        accessProfiles: [case-read]\n      - product: casework",
        );
    case
}

#[test]
fn machine_clients_carry_public_keys_roles_claims_and_the_crates_ids() {
    let generated = case().run().unwrap();
    let agent = agent_for(&generated, "case-portal");
    let config = &agent["inboundAuthConfig"][0]["config"];
    assert_eq!(config["tokenEndpointAuthMethod"], "private_key_jwt");
    let jwks: serde_json::Value =
        serde_json::from_str(config["certificate"]["value"].as_str().unwrap()).unwrap();
    assert_eq!(jwks["keys"][0]["kid"], "case-portal-key-1");
    assert_eq!(agent["attributes"]["registry_purpose"], "eligibility");
    assert_eq!(agent["attributes"]["registry_actor_kind"], "service");
    // The sub the issuer mints is the machine id the per-kind formula derives.
    let issuer = &generated.summary.issuer;
    let session = deployment_session_id(issuer);
    assert_eq!(
        agent["id"].as_str().unwrap(),
        crate::local::derived_uuid(&format!("{session}:machine:case-portal"))
    );
    let documents = resources(&generated);
    let servers = of_type(&documents, "resource_server");
    let breg = servers
        .iter()
        .find(|server| server["identifier"] == "urn:breg:example")
        .expect("breg server");
    let scopes: Vec<_> = breg["resources"][0]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|action| action["handle"].as_str().unwrap().to_owned())
        .collect();
    assert!(scopes.contains(&"get".to_owned()) || breg["resources"].as_array().unwrap().len() >= 2);
    let roles = of_type(&documents, "role");
    let role = roles
        .iter()
        .find(|role| {
            role["assignments"]
                .as_array()
                .unwrap()
                .iter()
                .any(|assignment| assignment["id"] == agent["id"])
        })
        .expect("role for case-portal");
    assert_eq!(
        role["permissions"][0]["permissions"],
        serde_json::json!(["records:get", "records:search"])
    );
}

#[test]
fn an_exchange_client_holds_only_the_bootstrap_permission() {
    let generated = case().run().unwrap();
    let agent = agent_for(&generated, "task-agent");
    let config = &agent["inboundAuthConfig"][0]["config"];
    assert!(config["grantTypes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|grant| grant == "urn:ietf:params:oauth:grant-type:token-exchange"));
    let documents = resources(&generated);
    assert_eq!(of_type(&documents, "connection").len(), 1);
    let role = of_type(&documents, "role")
        .into_iter()
        .find(|role| {
            role["assignments"]
                .as_array()
                .unwrap()
                .iter()
                .any(|assignment| assignment["id"] == agent["id"])
        })
        .unwrap();
    assert_eq!(
        role["permissions"].as_array().unwrap().len(),
        1,
        "only the bootstrap resource"
    );
    assert_eq!(
        role["permissions"][0]["permissions"],
        serde_json::json!(["casework:grants:assert"])
    );
}

#[test]
fn browser_apps_users_and_extension_types_render_without_secrets_or_a_logo_by_default() {
    let generated = case().run().unwrap();
    let documents = resources(&generated);
    let app = of_type(&documents, "application")[0];
    assert_eq!(app["url"], "https://staff.registry.example");
    assert!(app.get("logoUrl").is_none());
    assert_eq!(
        app["inboundAuthConfig"][0]["config"]["clientSecret"],
        "{{.STAFF_PORTAL_CLIENT_SECRET}}"
    );
    assert_eq!(
        app["allowedUserTypes"],
        serde_json::json!(["RegistryPerson", "Farmer"])
    );
    let types: Vec<_> = of_type(&documents, "user_type")
        .iter()
        .map(|document| document["name"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(types, ["RegistryPerson", "Farmer"]);
    let users = of_type(&documents, "user");
    assert_eq!(users.len(), 2);
    let farmer = users
        .iter()
        .find(|user| user["attributes"]["username"] == "farmer-one")
        .unwrap();
    assert_eq!(farmer["type"], "Farmer");
    assert_eq!(farmer["credentials"]["password"], "{{.FARMER_ONE_PASSWORD}}");
    let organization = of_type(&documents, "organization_unit");
    assert_eq!(organization[0]["handle"], "registry");
}

#[test]
fn one_browser_app_carries_default_and_explicit_cross_resource_grants() {
    let generated = cross_resource_browser_case("review")
        .run()
        .expect("the admitted browser app reaches both products");
    let documents = resources(&generated);
    let app = of_type(&documents, "application")[0];
    assert_eq!(
        app["inboundAuthConfig"][0]["config"]["token"]["accessToken"]["defaultAudience"],
        "urn:breg:example",
        "BrowserApp.product remains the token's one default audience"
    );
    assert_eq!(
        role_permissions(&documents, "Browser staff-portal", "urn:breg:example"),
        ["records:get", "records:search"]
    );
    assert_eq!(
        role_permissions(
            &documents,
            "Browser staff-portal",
            "urn:casework:example"
        ),
        ["casework:review"]
    );
    assert_eq!(
        role_permissions(&documents, "User officer-one", "urn:breg:example"),
        ["records:get", "records:patch", "records:search"],
        "the default product still lets a user's grant exceed the app's own profile"
    );
    assert_eq!(
        role_permissions(&documents, "User officer-one", "urn:casework:example"),
        ["casework:review"]
    );
}

#[test]
fn a_cross_resource_user_grant_requires_the_apps_same_access_profile() {
    assert_eq!(
        cross_resource_browser_case("intake").refusal(),
        ["identity.deployment.client-not-admitted"]
    );
}

#[test]
fn a_cross_resource_apps_client_checks_every_profile_selected_by_user_claims() {
    let mut case = cross_resource_browser_case("review");
    case.facts[2].1 = case.facts[2]
        .1
        .replace(
            "  registry_actor_kind: string\n",
            "  registry_actor_kind: string\n  casework_role: string\n",
        )
        .replace(
            "    actorKind: human\n  - id: intake",
            "    actorKind: human\n    selectedBy: {casework_role: [staff]}\n  - id: intake",
        )
        .replace(
            "    scopes: [casework:intake]\n    actorKind: human\n",
            "    scopes: [casework:intake]\n    actorKind: human\n    selectedBy: {casework_role: [staff]}\n",
        );
    case.deployment = case
        .deployment
        .replace(
            "tokenAttributes: [registry_actor_kind, registry_role]",
            "tokenAttributes: [registry_actor_kind, registry_role, casework_role]",
        )
        .replace(
            "      registry_role: officer\n",
            "      registry_role: officer\n      casework_role: staff\n",
        );
    assert_eq!(
        case.refusal(),
        ["identity.deployment.claims-select-ungranted-profile"]
    );
}

#[test]
fn a_non_default_purpose_grant_is_projected_without_changing_the_default_audience() {
    let generated = reverse_cross_resource_browser_case()
        .run()
        .expect("the reverse cross-resource deployment generates");
    let documents = resources(&generated);
    let app = of_type(&documents, "application")[0];
    let token = &app["inboundAuthConfig"][0]["config"]["token"];
    assert_eq!(
        token["accessToken"]["defaultAudience"],
        "urn:casework:example"
    );
    for projection in [
        &token["accessToken"]["userConfig"]["attributes"],
        &token["idToken"]["userAttributes"],
    ] {
        assert!(
            projection
                .as_array()
                .expect("projected attributes")
                .contains(&serde_json::json!("registry_purpose")),
            "the BReg grant's purpose must be projected"
        );
    }
}

#[test]
fn the_receipt_records_inputs_subs_the_pin_and_required_environment() {
    let generated = case().run().unwrap();
    let receipt: serde_json::Value =
        serde_json::from_str(&text(&generated, "identity-receipt.json")).unwrap();
    assert_eq!(
        receipt["apiVersion"],
        "id.registrystack.org/formats/platform/identity-receipt/v1"
    );
    let pin = crate::version::ThunderIdPin::load().unwrap();
    assert_eq!(receipt["thunderid"]["version"], pin.version);
    assert_eq!(receipt["thunderid"]["image"], pin.image);
    assert_eq!(receipt["issuer"], "https://id.registry.example");
    assert_eq!(
        receipt["requiredEnvironment"],
        serde_json::json!([
            "FARMER_ONE_PASSWORD",
            "OFFICER_ONE_PASSWORD",
            "STAFF_PORTAL_CLIENT_SECRET"
        ])
    );
    let digest = receipt["inputs"]["deployment"]["digest"].as_str().unwrap();
    assert!(digest.starts_with("sha256:") && digest.len() == 71);
    assert!(receipt["inputs"]["facts"]["breg"]["digest"].is_string());
    assert!(receipt["inputs"]["publicJwks"]["case-portal"]["digest"].is_string());
    let agent = agent_for(&generated, "field-agent");
    assert_eq!(receipt["clients"]["field-agent"]["sub"], agent["id"]);
    assert_eq!(receipt["clients"]["field-agent"]["kind"], "machine");
    assert_eq!(receipt["clients"]["staff-portal"]["kind"], "browser");
    let sid = deployment_session_id("https://id.registry.example");
    for user in ["officer-one", "farmer-one"] {
        assert_eq!(
            receipt["users"][user],
            serde_json::json!({
                "kind": "user",
                "sub": local::derived_uuid(&format!("{sid}:user:{user}"))
            })
        );
    }
    // No path and no secret value in the receipt.
    let raw = text(&generated, "identity-receipt.json");
    assert!(!raw.contains("keys/") && !raw.contains("{{."));
}

fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "registry-identity-generate-{name}-{}",
        crate::container::random_urlsafe(12).unwrap()
    ));
    fs::create_dir(&root).unwrap();
    root
}

#[test]
fn generating_to_a_directory_refuses_an_existing_output_and_matches_the_golden_tree() {
    let root = scratch("directory");
    let facts = [
        Path::new(DIR).join("facts-breg.yaml"),
        Path::new(DIR).join("facts-evidence.yaml"),
    ];
    let existing = root.join("existing");
    fs::create_dir(&existing).unwrap();
    assert!(matches!(
        generate_to_directory(&Path::new(DIR).join("deployment.yaml"), &facts, &existing),
        Err(ToolingError::OutputExists)
    ));
    assert_eq!(fs::read_dir(&existing).unwrap().count(), 0, "output untouched");

    let output = root.join("out");
    let summary =
        generate_to_directory(&Path::new(DIR).join("deployment.yaml"), &facts, &output).unwrap();
    assert_eq!(summary.machine_clients, 3);
    let expected = Path::new(DIR).join("expected");
    if std::env::var_os("REGISTRY_UPDATE_GOLDEN").is_some() {
        for (relative, bytes) in tree(&output) {
            let target = expected.join(&relative);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(target, bytes).unwrap();
        }
    }
    assert_eq!(
        tree(&output),
        tree(&expected),
        "the golden tree differs; regenerate with REGISTRY_UPDATE_GOLDEN=1 and review the diff"
    );
    // A second run into a fresh directory is byte-identical.
    let again = root.join("again");
    generate_to_directory(&Path::new(DIR).join("deployment.yaml"), &facts, &again).unwrap();
    assert_eq!(tree(&output), tree(&again));
}

fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, directory: &Path, found: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, found);
            } else {
                found.insert(
                    path.strip_prefix(root).unwrap().to_string_lossy().into_owned(),
                    fs::read(&path).unwrap(),
                );
            }
        }
    }
    let mut found = BTreeMap::new();
    walk(root, root, &mut found);
    found
}

/// Unpadded base64url of `length` non-zero bytes.
fn member_of(length: usize) -> serde_json::Value {
    use base64::Engine as _;
    serde_json::json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![1u8; length]))
}

#[test]
fn key_file_refusal_allows_only_public_keys_of_a_known_type() {
    let refusal = |keys: serde_json::Value| {
        key_file_refusal(Some(
            serde_json::to_vec(&serde_json::json!({ "keys": keys }))
                .unwrap()
                .as_slice(),
        ))
        .map(|(code, _, _)| code)
    };
    let ec = serde_json::json!({"kty": "EC", "crv": "P-256", "x": member_of(32), "y": member_of(32), "kid": "ec"});
    let rsa = serde_json::json!({"kty": "RSA", "n": member_of(256), "e": "AQAB", "alg": "RS256", "use": "sig", "key_ops": ["verify"], "kid": "rsa"});
    let okp = serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": member_of(32), "kid": "okp"});
    assert_eq!(refusal(serde_json::json!([ec, rsa, okp])), None);

    let with = |mut key: serde_json::Value, member: &str| {
        key[member] = serde_json::json!("AA");
        key
    };
    let private = Some("identity.deployment.private-key-material");
    let invalid = Some("identity.deployment.invalid-key-file");
    // A symmetric key is a secret, not a public key.
    assert_eq!(
        refusal(serde_json::json!([{"kty": "oct", "k": "c2VjcmV0"}])),
        private
    );
    assert_eq!(refusal(serde_json::json!([{"kty": "oct"}])), invalid);
    // RSA multi-prime private material.
    assert_eq!(refusal(serde_json::json!([with(rsa.clone(), "oth")])), private);
    assert_eq!(refusal(serde_json::json!([with(ec.clone(), "k")])), private);
    // A type outside the allowlist, a missing public member, an unknown member.
    assert_eq!(
        refusal(serde_json::json!([{"kty": "AKP", "pub": "AA"}])),
        invalid
    );
    assert_eq!(refusal(serde_json::json!([{"kty": "EC", "crv": "P-256", "x": member_of(32), "kid": "k"}])), invalid);
    assert_eq!(refusal(serde_json::json!([with(rsa.clone(), "surprise")])), invalid);
    assert_eq!(refusal(serde_json::json!([{"crv": "Ed25519", "x": member_of(32), "kid": "k"}])), invalid);
    assert_eq!(refusal(serde_json::json!([with(okp, "y")])), invalid);
    // Public members must be non-empty unpadded base64url strings, on a curve
    // ThunderID verifies, with metadata of the registered types.
    let set = |mut key: serde_json::Value, member: &str, value: serde_json::Value| {
        key[member] = value;
        key
    };
    assert_eq!(refusal(serde_json::json!([{"kty": "RSA", "n": null, "e": null, "kid": "k"}])), invalid);
    assert_eq!(refusal(serde_json::json!([set(rsa.clone(), "n", serde_json::json!(""))])), invalid);
    assert_eq!(refusal(serde_json::json!([set(rsa.clone(), "e", serde_json::json!(65537))])), invalid);
    assert_eq!(refusal(serde_json::json!([set(ec.clone(), "x", serde_json::json!("not base64!"))])), invalid);
    assert_eq!(refusal(serde_json::json!([set(ec.clone(), "x", serde_json::json!("AA=="))])), invalid);
    assert_eq!(refusal(serde_json::json!([set(ec.clone(), "y", serde_json::json!("a+b/"))])), invalid);
    assert_eq!(refusal(serde_json::json!([set(ec.clone(), "crv", serde_json::json!("secp256k1"))])), invalid);
    assert_eq!(refusal(serde_json::json!([set(ec.clone(), "crv", serde_json::json!(7))])), invalid);
    assert_eq!(refusal(serde_json::json!([set(ec.clone(), "crv", serde_json::json!("Ed25519"))])), invalid);
    assert_eq!(refusal(serde_json::json!([{"kty": "OKP", "crv": "X25519", "x": member_of(32), "kid": "k"}])), invalid);
    assert_eq!(refusal(serde_json::json!([set(ec.clone(), "kid", serde_json::json!(5))])), invalid);
    assert_eq!(refusal(serde_json::json!([set(rsa.clone(), "use", serde_json::json!(["sig"]))])), invalid);
    assert_eq!(refusal(serde_json::json!([set(rsa.clone(), "key_ops", serde_json::json!("verify"))])), invalid);
    assert_eq!(refusal(serde_json::json!([set(rsa.clone(), "key_ops", serde_json::json!([1]))])), invalid);
}

#[test]
fn every_key_carries_a_kid_that_is_unique_in_the_file() {
    let refusal = |keys: serde_json::Value| {
        key_file_refusal(Some(
            serde_json::to_vec(&serde_json::json!({ "keys": keys }))
                .unwrap()
                .as_slice(),
        ))
        .map(|(code, _, _)| code)
    };
    let key = |kid: Option<&str>| {
        let mut key = serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": member_of(32)});
        if let Some(kid) = kid {
            key["kid"] = serde_json::json!(kid);
        }
        key
    };
    let invalid = Some("identity.deployment.invalid-key-file");
    assert_eq!(refusal(serde_json::json!([key(Some("a")), key(Some("b"))])), None);
    assert_eq!(refusal(serde_json::json!([key(None)])), invalid);
    assert_eq!(refusal(serde_json::json!([key(Some("a")), key(None)])), invalid);
    assert_eq!(refusal(serde_json::json!([key(Some("a")), key(Some("a"))])), invalid);
    assert_eq!(refusal(serde_json::json!([key(Some(""))])), invalid);
}

#[test]
fn key_lengths_follow_the_rules_thunderid_applies_at_authentication() {
    let refusal = |key: serde_json::Value| {
        let mut key = key;
        key["kid"] = serde_json::json!("k");
        key_file_refusal(Some(
            serde_json::to_vec(&serde_json::json!({ "keys": [key] }))
                .unwrap()
                .as_slice(),
        ))
        .map(|(code, _, _)| code)
    };
    let invalid = Some("identity.deployment.invalid-key-file");
    let ec = |curve: &str, length: usize| {
        serde_json::json!({"kty": "EC", "crv": curve, "x": member_of(length), "y": member_of(length)})
    };
    for (curve, length) in [("P-256", 32), ("P-384", 48), ("P-521", 66)] {
        assert_eq!(refusal(ec(curve, length)), None, "{curve}");
        assert_eq!(refusal(ec(curve, length - 1)), invalid, "{curve} short");
        assert_eq!(refusal(ec(curve, length + 1)), invalid, "{curve} long");
    }
    // One coordinate of the right length is not enough.
    let mut mixed = ec("P-256", 32);
    mixed["y"] = member_of(33);
    assert_eq!(refusal(mixed), invalid);

    let okp = |length: usize| {
        serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": member_of(length)})
    };
    assert_eq!(refusal(okp(32)), None);
    assert_eq!(refusal(okp(31)), invalid);
    assert_eq!(refusal(okp(33)), invalid);

    let rsa = |modulus: serde_json::Value, exponent: &str| {
        serde_json::json!({"kty": "RSA", "n": modulus, "e": exponent})
    };
    assert_eq!(refusal(rsa(member_of(256), "AQAB")), None);
    assert_eq!(refusal(rsa(member_of(1024), "AQAB")), None);
    assert_eq!(refusal(rsa(member_of(255), "AQAB")), invalid);
    assert_eq!(refusal(rsa(member_of(1025), "AQAB")), invalid);
    // A modulus with a leading zero byte is not minimally encoded.
    use base64::Engine as _;
    let mut padded = vec![0u8];
    padded.extend(vec![1u8; 256]);
    let padded = serde_json::json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(padded));
    assert_eq!(refusal(rsa(padded, "AQAB")), invalid);
    // Exponent: 1 to 4 bytes, odd, at least 3.
    let exponent = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    assert_eq!(refusal(rsa(member_of(256), &exponent(&[3]))), None);
    assert_eq!(refusal(rsa(member_of(256), &exponent(&[1, 0, 1, 1]))), None);
    assert_eq!(refusal(rsa(member_of(256), &exponent(&[1]))), invalid);
    assert_eq!(refusal(rsa(member_of(256), &exponent(&[4]))), invalid);
    assert_eq!(refusal(rsa(member_of(256), &exponent(&[1, 0, 0, 0, 1]))), invalid);
    assert_eq!(refusal(rsa(member_of(256), &exponent(&[]))), invalid);
    // An exponent with a leading zero byte is not minimally encoded.
    assert_eq!(refusal(rsa(member_of(256), &exponent(&[0, 1, 0, 1]))), invalid);
}

#[test]
fn generated_output_is_private_and_appears_only_when_complete() {
    use std::os::unix::fs::PermissionsExt;
    let root = scratch("private");
    let facts = [
        Path::new(DIR).join("facts-breg.yaml"),
        Path::new(DIR).join("facts-evidence.yaml"),
    ];
    let output = root.join("out");
    generate_to_directory(&Path::new(DIR).join("deployment.yaml"), &facts, &output).unwrap();
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&output), 0o700);
    for entry in walk_paths(&output) {
        let expected = if entry.is_dir() { 0o700 } else { 0o600 };
        assert_eq!(mode(&entry), expected, "{}", entry.display());
    }
    // Only the finished output remains beside the parent's other entries.
    let names: Vec<_> = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, ["out"]);
    // A refused generation leaves nothing behind.
    let refused = root.join("refused");
    let missing = [root.join("absent.yaml")];
    assert!(generate_to_directory(&Path::new(DIR).join("deployment.yaml"), &missing, &refused).is_err());
    assert!(fs::symlink_metadata(&refused).is_err());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
}

fn walk_paths(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(walk_paths(&path));
        }
        found.push(path);
    }
    found
}

/// BReg facts whose `case-write` profile selects by a renamed scope claim, as
/// Messaging states its own. Users carry only string claims, so no user holds
/// that profile here.
fn scope_claim_case(case_portal_scopes: &str) -> Case {
    let mut case = case();
    case.facts[0].1 = case.facts[0]
        .1
        .replace(
            "  registry_role: string\n",
            "  registry_role: string\n  registry_scopes: string-array\n",
        )
        .replace(
            "    scopes: [records:patch]\n",
            "    scopes: [records:patch]\n    selectedBy:\n      registry_scopes: [records:patch]\n",
        );
    case.deployment = case
        .deployment
        .replacen(
            "    claims:\n      registry_actor_kind: service\n  - id: field-agent",
            &format!(
                "    claims:\n      registry_actor_kind: service\n      registry_scopes: {case_portal_scopes}\n  - id: field-agent"
            ),
            1,
        )
        .replace("accessProfiles: [case-read, case-write]", "accessProfiles: [case-read]");
    case
}

#[test]
fn a_scope_claim_may_carry_only_scopes_the_grants_give() {
    // Exactly the granted profile's scopes.
    scope_claim_case("[records:get, records:search]")
        .run()
        .expect("generates");
    // A scope no granted profile gives, which selects no other profile.
    let excess = scope_claim_case("[records:get, records:delete]");
    assert_eq!(
        excess.refusal(),
        ["identity.deployment.scope-claim-exceeds-grants"]
    );
}

#[test]
fn a_user_facing_an_array_claim_selector_is_told_why() {
    let mut case = scope_claim_case("[records:get, records:search]");
    case.deployment = case.deployment.replacen(
        "      registry_role: officer\n    grants:\n      - product: breg\n        accessProfiles: [case-read]",
        "      registry_role: officer\n    grants:\n      - product: breg\n        accessProfiles: [case-read, case-write]",
        1,
    );
    let Err(refused) = case.run() else {
        panic!("the run was accepted")
    };
    let diagnostics = refused.report().expect("a report").diagnostics();
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        "identity.deployment.user-claim-needs-array"
    );
    assert!(diagnostics[0].path.ends_with("/claims/registry_scopes"));
    assert!(diagnostics[0].message.contains("single strings"));
    assert!(diagnostics[0].suggested_action.contains("machine client"));
}

#[test]
fn a_machine_client_is_never_derived_human() {
    // case-read requires the human kind; case-portal is a machine client that
    // states no kind, so nothing may derive `human` for it.
    let mut case = case();
    case.facts[0].1 = case.facts[0].1.replacen(
        "    scopes: [records:get, records:search]\n",
        "    scopes: [records:get, records:search]\n    selectedBy:\n      registry_actor_kind: [human]\n",
        1,
    );
    case.deployment = case.deployment.replacen(
        "    claims:\n      registry_actor_kind: service\n  - id: field-agent",
        "  - id: field-agent",
        1,
    );
    let Err(refused) = case.run() else {
        panic!("the run was accepted")
    };
    let diagnostics = refused.report().expect("a report").diagnostics();
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    assert_eq!(
        diagnostics[0].code,
        "identity.deployment.machine-requires-human"
    );
    assert!(diagnostics[0].path.starts_with("/clients/0"));
    assert!(diagnostics[0].path.ends_with("case-read"));
}

#[test]
fn template_syntax_in_a_key_file_member_is_refused() {
    for member in [
        json!({"kid": "{{.SIGNING_KEY}}"}),
        json!({"kid": "k}}"}),
        json!({"alg": "{{"}),
    ] {
        let mut key = json!({"kty": "EC", "crv": "P-256", "x": "AA", "y": "BB"});
        key.as_object_mut()
            .unwrap()
            .extend(member.as_object().unwrap().clone());
        let bytes = serde_json::to_vec(&json!({ "keys": [key] })).unwrap();
        assert_eq!(
            key_file_refusal(Some(&bytes)).map(|(code, _, _)| code),
            Some("identity.deployment.template-syntax-in-key-file")
        );
    }
    // A delimiter in a member name counts, at any depth.
    for text in [
        r#"{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"BB","{{name":"v"}]}"#,
        r#"{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"BB","ext":{"a}}b":"v"}}]}"#,
    ] {
        assert_eq!(
            key_file_refusal(Some(text.as_bytes())).map(|(code, _, _)| code),
            Some("identity.deployment.template-syntax-in-key-file"),
            "{text}"
        );
    }
    // A JSON escape does not hide it.
    let bytes = br#"{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"BB","kid":"\u007b\u007bX"}]}"#;
    assert_eq!(
        key_file_refusal(Some(bytes)).map(|(code, _, _)| code),
        Some("identity.deployment.template-syntax-in-key-file")
    );
}

#[test]
fn an_output_that_appears_before_publication_is_refused_and_left_alone() {
    let root = scratch("race");
    let output = root.join("out");
    let files = BTreeMap::from([("a.txt".to_owned(), b"a".to_vec())]);
    let result = write_private_tree_with(&output, &files, || {
        fs::create_dir(&output).unwrap();
    });
    assert!(matches!(result, Err(ToolingError::OutputExists)));
    assert_eq!(fs::read_dir(&output).unwrap().count(), 0, "left untouched");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1, "no staging left");
}

#[test]
fn only_the_keys_member_of_a_key_file_is_accepted() {
    for extra in [
        r#""note": "{{.SIGNING_KEY}}""#,
        r#""note": "plain""#,
        r#""{{name": 1"#,
    ] {
        let text = format!(
            r#"{{"keys":[{{"kty":"EC","crv":"P-256","x":"AA","y":"BB"}}],{extra}}}"#
        );
        assert_eq!(
            key_file_refusal(Some(text.as_bytes())).map(|(code, _, _)| code),
            Some("identity.deployment.unexpected-key-file-member"),
            "{extra}"
        );
    }
}

#[test]
fn every_generated_placeholder_must_appear_exactly_once() {
    let one = |text: &str| BTreeMap::from([("a".to_owned(), text.as_bytes().to_vec())]);
    let names = ["SECRET_A".to_owned()];
    assert!(assert_only_known_placeholders(&one("x: '{{.SECRET_A}}'"), &names).is_ok());
    // A verbatim second copy of a placeholder this run emitted.
    assert!(assert_only_known_placeholders(
        &one("x: '{{.SECRET_A}}' y: '{{.SECRET_A}}'"),
        &names
    )
    .is_err());
    // A placeholder that was meant to be emitted but is missing.
    assert!(assert_only_known_placeholders(&one("x: plain"), &names).is_err());
}

#[test]
fn a_scope_claim_is_bounded_by_the_products_that_select_by_it() {
    // field-agent is granted only Evidence, which does not select by
    // `registry_scopes`; BReg does. An Evidence scope in that claim is a scope
    // no grant of a product reading the claim gives.
    let mut case = scope_claim_case("[records:get, records:search]");
    case.deployment = case.deployment.replacen(
        "      evidence_tags: [field]\n",
        "      evidence_tags: [field]\n      registry_scopes: [evidence:invoke]\n",
        1,
    );
    assert_eq!(
        case.refusal(),
        ["identity.deployment.scope-claim-exceeds-grants"]
    );
}

#[test]
fn the_receipt_is_published_last() {
    let names = ["resources", "identity-receipt.json", "deployment.yaml", "agents"]
        .map(std::ffi::OsString::from)
        .to_vec();
    let ordered: Vec<_> = in_publication_order(names)
        .into_iter()
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        ordered,
        ["agents", "deployment.yaml", "resources", "identity-receipt.json"]
    );
}

#[test]
fn an_exchange_profiles_scope_is_not_a_scope_a_claim_may_carry() {
    // Evidence selects by `registry_scopes`; its exchange profile `task-invoke`
    // gives `evidence:task`, but an exchanged token is not selected by claim.
    let mut case = case();
    case.facts[1].1 = case.facts[1]
        .1
        .replace(
            "  evidence_tags: string-array\n",
            "  evidence_tags: string-array\n  registry_scopes: string-array\n",
        )
        .replace(
            "      evidence_tags: [field]\n",
            "      evidence_tags: [field]\n      registry_scopes: [evidence:invoke]\n",
        );
    case.deployment = case.deployment.replacen(
        "      evidence_tags: [field]\n",
        "      evidence_tags: [field]\n      registry_scopes: [evidence:invoke]\n",
        1,
    );
    case.run().expect("the exact granted scope generates");
    case.deployment = case.deployment.replacen(
        "      registry_actor_kind: agent\n",
        "      registry_actor_kind: agent\n      registry_scopes: [evidence:task]\n",
        1,
    );
    assert_eq!(
        case.refusal(),
        ["identity.deployment.scope-claim-exceeds-grants"]
    );
}

/// BReg-only facts whose profiles state no actor kind and whose runtime
/// declares the actor-kind claim, as `bregctl generate identity-facts` writes
/// them, with a deployment that states no kind for its client.
fn untyped_breg_only_case() -> Case {
    let mut case = case();
    case.facts = vec![(
        "breg".into(),
        "apiVersion: id.registrystack.org/formats/platform/identity-facts/v1\nkind: PlatformIdentityFacts\nproduct: breg\nissuer: https://id.registry.example\naudience: urn:breg:example\nallowedClients:\n- case-portal\nclaims:\n  registry_actor_kind: string\naccessProfiles:\n- id: case-read\n  scopes:\n  - records:get\n".into(),
    )];
    case.deployment = "apiVersion: id.registrystack.org/formats/platform/identity-deployment/v1\nkind: PlatformIdentityDeployment\norganizationUnit:\n  handle: registry\n  name: Registry\n  description: Registry Stack deployment\nclients:\n  - id: case-portal\n    publicJwksFile: keys/case-portal.jwks.json\n    grants:\n      - product: breg\n        accessProfiles: [case-read]\n".into();
    case
}

#[test]
fn a_breg_only_client_of_untyped_profiles_gets_a_service_kind_claim() {
    let generated = untyped_breg_only_case().run().expect("generates");
    let agent = agent_for(&generated, "case-portal");
    assert_eq!(agent["attributes"]["registry_actor_kind"], "service");
}

/// Messaging facts with a renamed scope claim, as `messagingctl generate
/// identity-facts` writes them: two profiles require the same scope and name
/// disjoint requester clients, so the runtime picks one by client id.
const MESSAGING_TWO_SENDERS: &str = "apiVersion: id.registrystack.org/formats/platform/identity-facts/v1\nkind: PlatformIdentityFacts\nproduct: messaging\nissuer: https://id.registry.example\naudience: urn:messaging:example\nallowedClients: unrestricted\nclaims:\n  registry_actor_kind: string\n  messaging_scopes: string-array\naccessProfiles:\n- id: clinic-sender\n  scopes:\n  - messaging:send\n  requesterClients:\n  - case-portal\n  selectedBy:\n    messaging_scopes:\n    - messaging:send\n- id: school-sender\n  scopes:\n  - messaging:send\n  requesterClients:\n  - field-agent\n  selectedBy:\n    messaging_scopes:\n    - messaging:send\n";

#[test]
fn a_profile_whose_requester_clients_exclude_the_client_is_never_selected_for_it() {
    let mut case = case();
    case.facts
        .push(("messaging".into(), MESSAGING_TWO_SENDERS.into()));
    case.deployment = case.deployment.replacen(
        "        accessProfiles: [case-read]\n    claims:\n      registry_actor_kind: service\n",
        "        accessProfiles: [case-read]\n      - product: messaging\n        accessProfiles: [clinic-sender]\n    claims:\n      registry_actor_kind: service\n      messaging_scopes: [messaging:send]\n",
        1,
    );
    // The scopes also match school-sender, which Messaging never resolves
    // for case-portal: it selects the profile by client id first.
    case.run().expect("generates");

    // Once the product's allowed clients exclude case-portal, it is not
    // selected either; a profile that admits it still is.
    let mut admitting = case;
    admitting.facts[2].1 = admitting.facts[2]
        .1
        .replace("  - field-agent\n", "  - field-agent\n  - case-portal\n");
    assert_eq!(
        admitting.refusal(),
        ["identity.deployment.claims-select-ungranted-profile"]
    );
}

#[test]
fn a_user_is_selected_only_through_a_browser_application_the_profile_admits() {
    // `case-review` selects officers but names only the case-portal machine
    // client, so officer-one, who reaches BReg through staff-portal alone,
    // can never be resolved to it.
    let review = |clients: &str| {
        let mut case = case();
        case.facts[0].1 = case.facts[0].1.replace(
            "  - id: case-write\n",
            &format!(
                "  - id: case-review\n    scopes: [records:review]\n    requesterClients: [{clients}]\n    selectedBy:\n      registry_role: [officer]\n  - id: case-write\n"
            ),
        );
        case
    };
    review("case-portal").run().expect("generates");
    assert_eq!(
        review("staff-portal").refusal(),
        ["identity.deployment.claims-select-ungranted-profile"]
    );
}

#[test]
fn a_browser_application_carries_the_actor_kind_its_users_are_given() {
    // BReg refuses a token without registry_actor_kind; the operator lists
    // only registry_role, and the user's kind is derived.
    let mut case = case();
    case.deployment = case
        .deployment
        .replace(
            "tokenAttributes: [registry_actor_kind, registry_role]",
            "tokenAttributes: [registry_role]",
        )
        .replace("      registry_actor_kind: human\n", "");
    let generated = case.run().expect("generates");
    let documents = resources(&generated);
    let app = of_type(&documents, "application")[0];
    let token = &app["inboundAuthConfig"][0]["config"]["token"];
    for projection in [
        &token["accessToken"]["userConfig"]["attributes"],
        &token["idToken"]["userAttributes"],
    ] {
        assert_eq!(
            *projection,
            serde_json::json!(["registry_role", "registry_actor_kind", "registry_purpose"])
        );
    }
    let users = of_type(&documents, "user");
    assert!(users
        .iter()
        .all(|user| user["attributes"]["registry_actor_kind"] == "human"));
}

#[test]
fn a_browser_application_with_no_room_for_the_actor_kind_is_refused() {
    let names: Vec<String> = (1..=16).map(|n| format!("claim_{n:02}")).collect();
    let mut case = case();
    // No BReg profile requires a purpose here, so only the actor kind is
    // missing from the application's tokens.
    case.facts[0].1 = case.facts[0]
        .1
        .replace("    purposes: [eligibility]\n", "");
    case.facts[0].1 = case.facts[0].1.replace(
        "  registry_role: string\n",
        &format!(
            "  registry_role: string\n{}",
            names
                .iter()
                .map(|name| format!("  {name}: string\n"))
                .collect::<String>()
        ),
    );
    case.deployment = case.deployment.replace(
        "tokenAttributes: [registry_actor_kind, registry_role]",
        &format!("tokenAttributes: [{}]", names.join(", ")),
    );
    let Err(refused) = case.run() else {
        panic!("the run was accepted")
    };
    let diagnostics = refused.report().expect("a report").diagnostics();
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].code,
        "identity.deployment.actor-kind-not-projected"
    );
    assert_eq!(diagnostics[0].path, "/browserApps/0/tokenAttributes");
    assert!(diagnostics[0].message.contains("registry_actor_kind"));
}

/// A second BReg application that signs in only `RegistryPerson` users.
const FIELD_PORTAL: &str = "  - id: field-portal\n    clientSecretRef: secret:env/FIELD_PORTAL_CLIENT_SECRET\n    origin: https://field.registry.example\n    redirectUris: [https://field.registry.example/auth/callback]\n    product: breg\n    tokenAttributes: [registry_actor_kind, registry_role]\n    grants:\n      - product: breg\n        accessProfiles: [case-read]\nusers:\n";

#[test]
fn a_user_reaches_a_product_only_through_an_application_that_admits_its_type() {
    // staff-portal is the only BReg application; once it no longer admits
    // farmers, no token of farmer-one's can reach BReg.
    let mut case = case();
    case.deployment = case.deployment.replace("    userTypes: [farmer]\n", "");
    assert_eq!(case.refusal(), ["identity.deployment.client-not-admitted"]);
}

#[test]
fn selection_counts_only_the_applications_that_admit_the_users_type() {
    // `case-review` selects farmers but names only field-portal, which does
    // not admit farmers, so farmer-one can never be resolved to it.
    let review = |clients: &str| {
        let mut case = case();
        case.facts[0].1 = case.facts[0]
            .1
            .replace("  - staff-portal\n", "  - staff-portal\n  - field-portal\n")
            .replace(
                "  - id: case-write\n",
                &format!(
                    "  - id: case-review\n    scopes: [records:review]\n    requesterClients: [{clients}]\n    selectedBy:\n      registry_role: [farmer]\n  - id: case-write\n"
                ),
            );
        case.deployment = case.deployment.replace("users:\n", FIELD_PORTAL);
        case
    };
    review("field-portal").run().expect("generates");
    assert_eq!(
        review("staff-portal").refusal(),
        ["identity.deployment.claims-select-ungranted-profile"]
    );
}

#[test]
fn a_user_carries_the_purpose_its_grants_give_and_its_application_projects_it() {
    // BReg refuses a token for case-read without a registry_purpose it lists.
    let generated = case().run().expect("generates");
    let documents = resources(&generated);
    let users = of_type(&documents, "user");
    assert_eq!(users.len(), 2);
    assert!(users
        .iter()
        .all(|user| user["attributes"]["registry_purpose"] == "eligibility"));
    let app = of_type(&documents, "application")[0];
    let token = &app["inboundAuthConfig"][0]["config"]["token"];
    for projection in [
        &token["accessToken"]["userConfig"]["attributes"],
        &token["idToken"]["userAttributes"],
    ] {
        assert_eq!(
            *projection,
            serde_json::json!(["registry_actor_kind", "registry_role", "registry_purpose"])
        );
    }
}

#[test]
fn a_users_purpose_must_be_one_its_grants_give() {
    let mut case = case();
    case.deployment = case
        .deployment
        .replacen(
            "      registry_role: officer\n",
            "      registry_role: officer\n      registry_purpose: audit\n",
            1,
        );
    assert_eq!(case.refusal(), ["identity.deployment.purpose-not-granted"]);
}

#[test]
fn a_browser_application_with_no_room_for_the_purpose_is_refused() {
    let names: Vec<String> = (1..=15).map(|n| format!("claim_{n:02}")).collect();
    let mut case = case();
    case.facts[0].1 = case.facts[0].1.replace(
        "  registry_role: string\n",
        &format!(
            "  registry_role: string\n{}",
            names
                .iter()
                .map(|name| format!("  {name}: string\n"))
                .collect::<String>()
        ),
    );
    case.deployment = case.deployment.replace(
        "tokenAttributes: [registry_actor_kind, registry_role]",
        &format!("tokenAttributes: [registry_actor_kind, {}]", names.join(", ")),
    );
    let Err(refused) = case.run() else {
        panic!("the run was accepted")
    };
    let diagnostics = refused.report().expect("a report").diagnostics();
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].code, "identity.deployment.purpose-not-projected");
    assert_eq!(diagnostics[0].path, "/browserApps/0/tokenAttributes");
    assert!(diagnostics[0].message.contains("registry_purpose"));
}

#[test]
fn a_deployment_may_state_more_users_and_applications_than_a_development_session() {
    // The deployment file allows 256 of each; a development session's bounds
    // are smaller and stay so.
    let mut case = case();
    case.facts[0].1 = case.facts[0].1.replace(
        "allowedClients:\n  - case-portal\n  - staff-portal\n",
        "allowedClients: unrestricted\n",
    );
    let mut apps = String::new();
    for n in 1..256 {
        apps.push_str(&format!(
            "  - id: portal-{n}\n    clientSecretRef: secret:env/PORTAL_{n}_CLIENT_SECRET\n    origin: https://portal-{n}.registry.example\n    redirectUris: [https://portal-{n}.registry.example/auth/callback]\n    product: breg\n    tokenAttributes: [registry_role]\n    grants:\n      - product: breg\n        accessProfiles: [case-read]\n"
        ));
    }
    let mut users = String::new();
    for n in 1..255 {
        users.push_str(&format!(
            "  - id: person-{n}\n    username: person-{n}\n    email: person.{n}@agency.example\n    passwordRef: secret:env/PERSON_{n}_PASSWORD\n    grants:\n      - product: breg\n        accessProfiles: [case-read]\n"
        ));
    }
    case.deployment = case
        .deployment
        .replace("users:\n", &format!("{apps}users:\n{users}"));
    let generated = case.run().expect("generates");
    let documents = resources(&generated);
    assert_eq!(of_type(&documents, "application").len(), 256);
    assert_eq!(of_type(&documents, "user").len(), 256);
}

/// BReg reading its principal from `registry_principal` on every profile, as
/// a project whose access profiles name that claim does, and a deployment
/// whose principals all carry it.
fn principal_case() -> Case {
    let mut case = case();
    case.facts[0].1 = case.facts[0]
        .1
        .replace(
            "  registry_role: string\n",
            "  registry_principal: string\n  registry_role: string\n",
        )
        .replace(
            "    purposes: [eligibility]\n",
            "    purposes: [eligibility]\n    requiredClaims: [registry_principal]\n",
        )
        .replace(
            "    scopes: [records:patch]\n",
            "    scopes: [records:patch]\n    requiredClaims: [registry_principal]\n",
        );
    case.deployment = case
        .deployment
        .replacen(
            "      registry_actor_kind: service\n",
            "      registry_actor_kind: service\n      registry_principal: case-portal\n",
            1,
        )
        .replace(
            "tokenAttributes: [registry_actor_kind, registry_role]",
            "tokenAttributes: [registry_actor_kind, registry_principal, registry_role]",
        )
        .replace(
            "      registry_role: officer\n",
            "      registry_principal: officer-one\n      registry_role: officer\n",
        )
        .replace(
            "      registry_role: farmer\n",
            "      registry_principal: farmer-one\n      registry_role: farmer\n",
        );
    case
}

/// The one diagnostic a refused run reports, as code and path.
fn only_finding(case: &Case) -> (String, String) {
    let Err(refused) = case.run() else {
        panic!("the run was accepted")
    };
    let diagnostics = refused.report().expect("a report").diagnostics();
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    (diagnostics[0].code.clone(), diagnostics[0].path.clone())
}

#[test]
fn principals_that_carry_every_claim_their_profiles_require_generate() {
    // field-agent carries no registry_principal: it holds no BReg profile.
    let generated = principal_case().run().expect("generates");
    let documents = resources(&generated);
    let app = of_type(&documents, "application")[0];
    let token = &app["inboundAuthConfig"][0]["config"]["token"];
    assert!(token["accessToken"]["userConfig"]["attributes"]
        .as_array()
        .expect("a projection")
        .contains(&serde_json::json!("registry_principal")));
}

#[test]
fn a_machine_client_without_a_claim_its_profile_requires_is_refused() {
    // BReg rejects a token without its principal claim at authentication,
    // after generation and the check would otherwise have passed it.
    let mut case = principal_case();
    case.deployment = case
        .deployment
        .replace("      registry_principal: case-portal\n", "");
    assert_eq!(
        only_finding(&case),
        (
            "identity.deployment.required-claim-missing".to_owned(),
            "/clients/0/claims".to_owned()
        )
    );
}

#[test]
fn a_user_without_a_claim_its_profile_requires_is_refused() {
    let mut case = principal_case();
    case.deployment = case
        .deployment
        .replace("      registry_principal: farmer-one\n", "");
    assert_eq!(
        only_finding(&case),
        (
            "identity.deployment.required-claim-missing".to_owned(),
            "/users/1/claims".to_owned()
        )
    );
}

#[test]
fn a_browser_application_that_does_not_project_a_required_claim_is_refused() {
    let mut case = principal_case();
    case.deployment = case.deployment.replace(
        "tokenAttributes: [registry_actor_kind, registry_principal, registry_role]",
        "tokenAttributes: [registry_actor_kind, registry_role]",
    );
    assert_eq!(
        only_finding(&case),
        (
            "identity.deployment.required-claim-not-projected".to_owned(),
            "/browserApps/0/tokenAttributes".to_owned()
        )
    );
}

#[test]
fn a_required_claim_the_generator_derives_counts_as_carried() {
    // No principal states registry_actor_kind or registry_purpose, and the
    // application lists neither: the generator derives and projects both.
    let mut case = case();
    case.facts[0].1 = case.facts[0].1.replace(
        "    purposes: [eligibility]\n",
        "    purposes: [eligibility]\n    requiredClaims: [registry_actor_kind, registry_purpose]\n",
    );
    case.deployment = case
        .deployment
        .replace(
            "tokenAttributes: [registry_actor_kind, registry_role]",
            "tokenAttributes: [registry_role]",
        )
        .replace("      registry_actor_kind: human\n", "")
        .replacen("    claims:\n      registry_actor_kind: service\n", "", 1);
    case.run().expect("generates");
}

#[test]
fn an_exchange_profiles_required_claims_are_not_asked_of_the_client() {
    // The exchanged token's claims come from the assertion, not from the
    // client that presents it. The Evidence fixture states the requirement
    // on its exchange profile and the agent client carries neither Evidence claim.
    let case = case();
    assert!(case.facts[1].1.contains(
        "      registry_actor_kind: [agent]\n    requiredClaims: [evidence_audience, evidence_tags, registry_actor_kind]\n    exchange:"
    ));
    let agent = case.deployment.split("id: task-agent").nth(1).unwrap();
    assert!(!agent.split("browserApps:").next().unwrap().contains("evidence_"));
    case.run().expect("generates");
}

/// Casework's facts with the assertion endpoint the task agent bootstraps
/// at: Casework refuses the client's own token there unless it is an agent.
const CASEWORK_TASK_ASSERT: &str = "apiVersion: id.registrystack.org/formats/platform/identity-facts/v1\nkind: PlatformIdentityFacts\nproduct: casework\nissuer: https://id.registry.example\naudience: urn:casework:example\nallowedClients: unrestricted\nclaims:\n  registry_actor_kind: string\naccessProfiles:\n- id: task-assert\n  scopes:\n  - casework:grants:assert\n  actorKind: agent\n  exchange:\n    assertionIssuerId: authority\n    bootstrapAudience: urn:casework:example\n    bootstrapScope: casework:grants:assert\nassertionIssuers:\n- id: authority\n  issuer: https://authority.example\n  jwksUrl: https://authority.example/jwks\n  mapping: institutional-grant\n";

const TASK_AGENT_GRANT: &str =
    "        accessProfiles: [task-invoke]\n    claims:\n      registry_actor_kind: agent\n";

/// The fixture with task-agent also granted Casework's task-assert, with
/// `claims` in place of its stated claims.
fn case_with_task_assert(claims: &str) -> Case {
    let mut case = case();
    case.facts
        .push(("casework".into(), CASEWORK_TASK_ASSERT.into()));
    assert!(case.deployment.contains(TASK_AGENT_GRANT));
    case.deployment = case.deployment.replacen(
        TASK_AGENT_GRANT,
        &format!("        accessProfiles: [task-invoke]\n      - product: casework\n        accessProfiles: [task-assert]\n{claims}"),
        1,
    );
    case
}

#[test]
fn an_exchange_profiles_actor_kind_is_required_of_the_clients_own_token() {
    // The client's bootstrap token is its own, so the kind an exchange
    // profile requires settles the client's kind when it states none.
    let generated = case_with_task_assert("").run().expect("generates");
    let agent = agent_for(&generated, "task-agent");
    assert_eq!(agent["attributes"]["registry_actor_kind"], "agent");

    // A client of another kind would be refused at the assertion endpoint.
    let service =
        case_with_task_assert("    claims:\n      registry_actor_kind: service\n");
    assert_eq!(
        service.refusal(),
        ["identity.deployment.profile-requires-actor-kind"]
    );
}
