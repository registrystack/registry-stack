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

/// `DEPLOYMENT` with child units `north` and `south`, the officer placed in
/// `north` and the case portal in `south`.
fn with_units() -> String {
    DEPLOYMENT
        .replace(
            "  name: Registry\n",
            "  name: Registry\n  units:\n    - handle: north\n      name: North district\n    - handle: south\n",
        )
        .replace(
            "      registry_actor_kind: service\n",
            "      registry_actor_kind: service\n      ouHandle: south\n",
        )
        .replace(
            "      registry_actor_kind: human\n",
            "      registry_actor_kind: human\n      ouHandle: north\n",
        )
}

fn units_of(text: &str) -> Vec<String> {
    let units = codes(text);
    units
        .into_iter()
        .filter(|code| code == "identity.deployment.invalid-unit")
        .collect()
}

#[test]
fn units_read_with_a_name_or_without_one() {
    let (deployment, _) = read_text(&with_units()).expect("reads");
    let units = &deployment.organization_unit.units;
    assert_eq!(units.len(), 2);
    assert_eq!(units[0].handle, "north");
    assert_eq!(units[0].name.as_deref(), Some("North district"));
    assert_eq!(units[1].handle, "south");
    assert_eq!(units[1].name, None);
    assert_eq!(units[1].name_or_handle(), "south");
    assert_eq!(deployment.users[0].claims["ouHandle"], "north");
}

#[test]
fn units_must_be_valid_distinct_and_differ_from_the_deployment_unit() {
    for handle in [
        "",
        "has space",
        "slash/inside",
        "caf\u{e9}",
        "default",
        "registry",
        &"a".repeat(65),
    ] {
        let bad = with_units().replace("handle: south", &format!("handle: \"{handle}\""));
        // The placed client names `south`, which no longer exists.
        let found = units_of(&bad);
        assert_eq!(found, ["identity.deployment.invalid-unit"], "accepted {handle:?}");
    }
    for handle in ["South", "zone-a", "zone_b", "d.1", &"a".repeat(64)] {
        let good = with_units()
            .replace("handle: south", &format!("handle: {handle}"))
            .replace("ouHandle: south", &format!("ouHandle: {handle}"));
        assert!(read_text(&good).is_ok(), "refused {handle:?}");
    }
    let named_twice = with_units().replace(
        "    - handle: south\n",
        "    - handle: south\n      name: North district\n",
    );
    assert_eq!(units_of(&named_twice), ["identity.deployment.invalid-unit"]);
    let empty_name = with_units().replace("name: North district", "name: \"\"");
    assert_eq!(units_of(&empty_name), ["identity.deployment.invalid-unit"]);
    let long_name = with_units().replace("North district", &"n".repeat(101));
    assert_eq!(units_of(&long_name), ["identity.deployment.invalid-unit"]);
    let mut many = String::from("  name: Registry\n  units:\n");
    for index in 0..257 {
        many.push_str(&format!("    - handle: unit-{index}\n"));
    }
    let too_many = DEPLOYMENT.replace("  name: Registry\n", &many);
    assert_eq!(units_of(&too_many), ["identity.deployment.invalid-unit"]);
    let mut at_most = String::from("  name: Registry\n  units:\n");
    for index in 0..256 {
        at_most.push_str(&format!("    - handle: unit-{index}\n"));
    }
    assert!(read_text(&DEPLOYMENT.replace("  name: Registry\n", &at_most)).is_ok());
}

#[test]
fn leaf_unit_handles_must_be_unique_across_the_deployment() {
    let repeated = with_units().replace("handle: south", "handle: north");
    let (code, pointer) = {
        let Err(error) = read_text(&repeated) else {
            panic!("accepted a repeated leaf handle")
        };
        let found: Vec<_> = error
            .report()
            .expect("a refused file")
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code == "identity.deployment.invalid-unit")
            .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
            .collect();
        assert_eq!(found.len(), 1, "{found:?}");
        found[0].clone()
    };
    assert_eq!(code, "identity.deployment.invalid-unit");
    assert_eq!(pointer, "/organizationUnit/units/1");
    // Handles that differ only by case are different values and both read.
    let cased = with_units()
        .replace("handle: south", "handle: North")
        .replace("ouHandle: south", "ouHandle: North");
    assert!(read_text(&cased).is_ok());
}

#[test]
fn a_unit_claim_naming_no_unit_is_refused() {
    let user = with_units().replace("ouHandle: north", "ouHandle: east");
    let client = with_units().replace("ouHandle: south", "ouHandle: east");
    for (bad, pointer) in [
        (user, "/users/0/claims/ouHandle"),
        (client, "/clients/0/claims/ouHandle"),
    ] {
        let Err(error) = read_text(&bad) else {
            panic!("accepted a unit claim naming no unit")
        };
        let found: Vec<_> = error
            .report()
            .expect("a refused file")
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
            .collect();
        assert_eq!(
            found,
            [("identity.deployment.unknown-unit".to_owned(), pointer.to_owned())]
        );
    }
    // A deployment that states no units has no unit a claim could name.
    let none = DEPLOYMENT.replace(
        "      registry_actor_kind: human\n",
        "      registry_actor_kind: human\n      ouHandle: north\n",
    );
    assert!(codes(&none).contains(&"identity.deployment.unknown-unit".to_owned()));
    // A client claim holding a list cannot name one unit.
    let list = with_units().replace("ouHandle: south", "ouHandle: [south]");
    assert!(codes(&list).contains(&"identity.deployment.unknown-unit".to_owned()));
}

#[test]
fn user_types_cannot_declare_the_unit_claim() {
    let with_type = |attributes: &str| {
        with_units().replace(
            "users:\n",
            &format!(
                "userTypes:\n  - id: farmer\n    name: Farmer\n    attributes: {attributes}\nusers:\n"
            ),
        )
    };
    read_text(&with_type("[national_id]")).expect("a type without the unit claim reads");
    let bad = with_type("[national_id, ouHandle]");
    assert_eq!(codes(&bad), ["identity.deployment.invalid-user-type"]);
}
