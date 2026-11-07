use super::*;

pub(crate) const DEPLOYMENT: &str =
    "apiVersion: id.registrystack.org/formats/platform/identity-deployment/v1
kind: PlatformIdentityDeployment
organizationUnit:
  handle: registry
  name: Registry
clients:
  - id: case-portal
    publicJwksFile: keys/case-portal.jwks.json
    grants:
      - product: breg
        accessProfiles: [case-read]
    claims:
      registry_actor_kind: service
  - id: field-agent
    publicJwksFile: keys/field-agent.jwks.json
    grants:
      - product: evidence
        accessProfiles: [invoke]
browserApps:
  - id: staff-portal
    clientSecretRef: secret:env/STAFF_PORTAL_CLIENT_SECRET
    origin: https://staff.registry.example
    redirectUris: [https://staff.registry.example/auth/callback]
    product: breg
    tokenAttributes: [registry_actor_kind]
    grants:
      - product: breg
        accessProfiles: [case-read]
users:
  - id: officer-one
    username: officer-one
    email: officer.one@agency.example
    passwordRef: secret:env/OFFICER_ONE_PASSWORD
    claims:
      registry_actor_kind: human
    grants:
      - product: breg
        accessProfiles: [case-read]
";

fn read_text(text: &str) -> Result<(IdentityDeployment, Document), ToolingError> {
    read("deployment.yaml", text.as_bytes())
}

fn codes(text: &str) -> Vec<String> {
    match read_text(text) {
        Ok(_) => Vec::new(),
        Err(error) => error
            .report()
            .expect("a refused file")
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.clone())
            .collect(),
    }
}

#[test]
fn a_complete_deployment_reads() {
    let (deployment, _) = read_text(DEPLOYMENT).expect("reads");
    assert_eq!(deployment.organization_unit.handle, "registry");
    assert_eq!(deployment.clients.len(), 2);
    assert_eq!(
        deployment.clients[0].public_jwks_file,
        "keys/case-portal.jwks.json"
    );
    assert_eq!(deployment.browser_apps[0].product, "breg");
    assert_eq!(deployment.users[0].grants[0].access_profiles, ["case-read"]);
    assert_eq!(
        deployment.jwks_files(),
        ["keys/case-portal.jwks.json", "keys/field-agent.jwks.json"]
    );
    assert_eq!(
        deployment.required_environment(),
        [
            "OFFICER_ONE_PASSWORD".to_owned(),
            "STAFF_PORTAL_CLIENT_SECRET".to_owned()
        ]
    );
}

#[test]
fn secrets_are_environment_references_only() {
    for bad in [
        DEPLOYMENT.replace("secret:env/STAFF_PORTAL_CLIENT_SECRET", "secret:file/app"),
        DEPLOYMENT.replace("clientSecretRef: secret:env/STAFF_PORTAL_CLIENT_SECRET", "clientSecret: plain-text-value"),
        DEPLOYMENT.replace("secret:env/OFFICER_ONE_PASSWORD", "hunter2hunter2"),
    ] {
        assert!(read_text(&bad).is_err(), "accepted:\n{bad}");
    }
    assert!(codes(&DEPLOYMENT.replace("secret:env/STAFF_PORTAL_CLIENT_SECRET", "secret:file/app"))
        .contains(&"identity.deployment.environment-secret-only".to_owned()));
}

#[test]
fn one_secret_name_cannot_serve_two_secrets() {
    let bad = DEPLOYMENT.replace("OFFICER_ONE_PASSWORD", "STAFF_PORTAL_CLIENT_SECRET");
    assert!(codes(&bad).contains(&"identity.deployment.duplicate-secret".to_owned()));
}

#[test]
fn key_files_are_relative_paths_inside_the_deployment_directory() {
    for path in ["/etc/keys/a.json", "../keys/a.json", "keys/../../a.json", "keys\\a.json", ""] {
        let bad = DEPLOYMENT.replace("keys/case-portal.jwks.json", path);
        assert!(
            codes(&bad).contains(&"identity.deployment.invalid-path".to_owned())
                || read_text(&bad).is_err(),
            "accepted {path}"
        );
    }
}

#[test]
fn identities_are_unique_and_every_principal_is_granted_something() {
    let duplicate = DEPLOYMENT.replace("id: field-agent", "id: case-portal");
    assert!(codes(&duplicate).contains(&"identity.deployment.duplicate-client".to_owned()));
    let ungranted = DEPLOYMENT.replace(
        "    grants:\n      - product: evidence\n        accessProfiles: [invoke]\n",
        "    grants: []\n",
    );
    assert!(codes(&ungranted).contains(&"identity.deployment.no-grants".to_owned()));
    let reused = DEPLOYMENT.replace("id: staff-portal", "id: case-portal");
    assert!(codes(&reused).contains(&"identity.deployment.duplicate-client".to_owned()));
}

#[test]
fn browser_apps_need_https_and_users_need_a_real_email() {
    let http = DEPLOYMENT.replace("origin: https://staff.registry.example", "origin: http://staff.registry.example");
    assert!(codes(&http).contains(&"identity.deployment.invalid-origin".to_owned()));
    let email = DEPLOYMENT.replace("officer.one@agency.example", "not-an-email");
    assert!(codes(&email).contains(&"identity.deployment.invalid-email".to_owned()));
}

#[test]
fn unknown_keys_and_wrong_kinds_are_refused() {
    assert!(read_text(&format!("{DEPLOYMENT}issuer: https://id.example\n")).is_err());
    assert!(read_text(&DEPLOYMENT.replace("PlatformIdentityDeployment", "PlatformIdentityFacts")).is_err());
}

#[test]
fn template_syntax_is_refused_in_every_copied_string() {
    for bad in [
        DEPLOYMENT.replace("name: Registry", "name: \"{{.DATABASE_PASSWORD}}\""),
        DEPLOYMENT.replace(
            "registry_actor_kind: service",
            "registry_actor_kind: \"{{.SIGNING_KEY}}\"",
        ),
        DEPLOYMENT.replace("officer.one@agency.example", "officer{{.X}}@agency.example"),
        DEPLOYMENT.replace("https://staff.registry.example/auth/callback", "https://staff.registry.example/{{cb"),
        DEPLOYMENT.replace("name: Registry", "name: \"\\x7b\\x7bX\""),
    ] {
        assert!(
            read("deployment.yaml", bad.as_bytes()).is_err(),
            "accepted:\n{bad}"
        );
    }
}

#[test]
fn an_explicit_actor_kind_is_one_the_runtime_parses() {
    for bad in [
        DEPLOYMENT.replace("registry_actor_kind: service", "registry_actor_kind: robot"),
        DEPLOYMENT.replace("registry_actor_kind: service", "registry_actor_kind: Service"),
        DEPLOYMENT.replace("registry_actor_kind: service", "registry_actor_kind: [service]"),
        DEPLOYMENT.replace("registry_actor_kind: human", "registry_actor_kind: robot"),
    ] {
        assert!(
            codes(&bad).contains(&"identity.deployment.unknown-actor-kind".to_owned()),
            "accepted:\n{bad}"
        );
    }
    for kind in ["human", "agent", "service"] {
        let good = DEPLOYMENT.replace(
            "registry_actor_kind: service",
            &format!("registry_actor_kind: {kind}"),
        );
        assert!(read_text(&good).is_ok(), "refused {kind}");
    }
}

/// Every list the format states as a set refuses a repeat at the repeat,
/// naming the first, as every set does (CFG-ID-6).
#[test]
fn every_set_list_refuses_a_repeat_at_the_repeat() {
    let sets = DEPLOYMENT
        .replace(
            "    tokenAttributes: [registry_actor_kind]\n",
            "    tokenAttributes: [registry_actor_kind]\n    userTypes: [farmer]\n",
        )
        .replace(
            "users:\n",
            "userTypes:\n  - id: farmer\n    name: Farmer\n    attributes: [national_id]\nusers:\n",
        );
    read_text(&sets).expect("reads");
    for (from, to, at) in [
        (
            "        accessProfiles: [invoke]\n",
            "        accessProfiles: [invoke, invoke]\n",
            "/clients/1/grants/0/accessProfiles/1",
        ),
        (
            "redirectUris: [https://staff.registry.example/auth/callback]",
            "redirectUris: [https://staff.registry.example/auth/callback, https://staff.registry.example/auth/callback]",
            "/browserApps/0/redirectUris/1",
        ),
        (
            "tokenAttributes: [registry_actor_kind]",
            "tokenAttributes: [registry_actor_kind, registry_actor_kind]",
            "/browserApps/0/tokenAttributes/1",
        ),
        ("userTypes: [farmer]", "userTypes: [farmer, farmer]", "/browserApps/0/userTypes/1"),
        (
            "attributes: [national_id]",
            "attributes: [national_id, national_id]",
            "/userTypes/0/attributes/1",
        ),
    ] {
        assert!(sets.contains(from), "{from}");
        let Err(error) = read_text(&sets.replace(from, to)) else {
            panic!("{at}: accepted");
        };
        let found: Vec<(String, Vec<String>)> = error
            .report()
            .expect("a refused file")
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code == "config.duplicate-item")
            .map(|diagnostic| {
                (
                    diagnostic.path.clone(),
                    diagnostic.related.iter().map(|related| related.path.clone()).collect(),
                )
            })
            .collect();
        let first = format!("{}/0", at.rsplit_once('/').expect("an index").0);
        assert_eq!(found, [(at.to_owned(), vec![first])], "{at}");
    }
}
