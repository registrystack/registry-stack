use super::*;
use registry_platform_config::{
    AllowedClients, PackageClients, RuntimeConfigLoader, RuntimeEnvelope,
};
use serde::Deserialize;

const ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: "registry.registrystack.org/example-runtime/v1alpha1",
    kind: "ExampleRuntimeConfig",
};

const HEAD: &str =
    "apiVersion: registry.registrystack.org/example-runtime/v1alpha1\nkind: ExampleRuntimeConfig\n";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Doc<C> {
    entry: Entry<C>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry<C> {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuer-core"))]
    core: CallerIssuerCore<C>,
}

fn core<C: for<'de> Deserialize<'de>>(members: &str) -> CallerIssuerCore<C> {
    let text = format!(
        "{HEAD}entry:\n  issuer: https://id.example.org/realms/registry\n  audience: registry-api\n{members}"
    );
    RuntimeConfigLoader::new_without_posture(ENVELOPE)
        .parse_str::<Doc<C>>(&text, |_| None)
        .unwrap_or_else(|error| panic!("loads: {:?}", error.diagnostics()))
        .config
        .entry
        .core
}

const ALGORITHMS: [Algorithm; 1] = [Algorithm::RS256];

#[test]
fn a_declared_kind_converts_to_the_verifier_s_kind() {
    for (declared, kind) in [
        (DeclaredActorKind::Human, ActorKind::Human),
        (DeclaredActorKind::Agent, ActorKind::Agent),
        (DeclaredActorKind::Service, ActorKind::Service),
    ] {
        assert_eq!(ActorKind::from(declared), kind);
    }
}

#[test]
fn the_access_token_type_selects_the_typ_set() {
    assert_eq!(
        access_token_types(AccessTokenType::AtJwt),
        ["at+jwt", "application/at+jwt"]
    );
    assert_eq!(access_token_types(AccessTokenType::Jwt), ["JWT"]);
}

#[test]
fn the_declared_kinds_follow_actor_kind_or_client_actor_kinds() {
    let none = core::<AllowedClients>("  allowedClients: [case-portal]\n");
    assert_eq!(DeclaredKinds::from_core(&none), Ok(DeclaredKinds::None));
    let issuer = core::<AllowedClients>("  allowedClients: [case-portal]\n  actorKind: service\n");
    assert_eq!(
        DeclaredKinds::from_core(&issuer),
        Ok(DeclaredKinds::Issuer(ActorKind::Service))
    );
    let clients = core::<AllowedClients>(
        "  allowedClients: [case-portal, nightly-sync]\n  clientActorKinds:\n    case-portal: human\n    nightly-sync: service\n",
    );
    assert_eq!(
        DeclaredKinds::from_core(&clients),
        Ok(DeclaredKinds::Clients(
            [
                ("case-portal".to_owned(), ActorKind::Human),
                ("nightly-sync".to_owned(), ActorKind::Service),
            ]
            .into_iter()
            .collect()
        ))
    );
    let both = core::<AllowedClients>(
        "  allowedClients: [case-portal]\n  actorKind: service\n  clientActorKinds:\n    case-portal: human\n",
    );
    assert_eq!(DeclaredKinds::from_core(&both), Err(ActorKindTwice));
}

#[test]
fn the_verifier_profile_carries_the_entry_s_issuer_audience_type_scope_claim_and_clients() {
    let entry = core::<AllowedClients>(
        "  accessTokenType: JWT\n  scopeClaim: scp\n  allowedClients: [case-portal, nightly-sync]\n",
    );
    let config = TokenVerifierConfig::for_caller_issuer(&entry, ALGORITHMS.to_vec(), None)
        .expect("a listed entry needs no resolved clients");
    assert_eq!(config.issuer, "https://id.example.org/realms/registry");
    assert_eq!(config.audiences, ["registry-api"]);
    assert_eq!(config.allowed_algorithms, ALGORITHMS);
    assert_eq!(config.allowed_typ, ["JWT"]);
    assert_eq!(config.scope_claim, "scp");
    assert_eq!(config.allowed_clients, ["case-portal", "nightly-sync"]);
}

#[test]
fn the_derived_profile_refuses_id_token_markers_exactly_under_jwt() {
    for (members, refuses) in [
        ("  allowedClients: [a]\n", false),
        ("  accessTokenType: at+jwt\n  allowedClients: [a]\n", false),
        ("  accessTokenType: JWT\n  allowedClients: [a]\n", true),
    ] {
        let entry = core::<AllowedClients>(members);
        let config =
            TokenVerifierConfig::for_caller_issuer(&entry, ALGORITHMS.to_vec(), None).unwrap();
        assert_eq!(config.refuses_id_token_markers(), refuses, "{members}");
    }
}

#[test]
fn the_defaults_give_the_rfc_9068_pair_and_the_scope_claim() {
    let entry = core::<AllowedClients>("  allowedClients: unrestricted\n");
    let config = TokenVerifierConfig::for_caller_issuer(&entry, ALGORITHMS.to_vec(), None).unwrap();
    assert_eq!(config.allowed_typ, ["at+jwt", "application/at+jwt"]);
    assert_eq!(config.scope_claim, "scope");
    assert!(
        config.allowed_clients.is_empty(),
        "unrestricted admits every client"
    );
}

#[test]
fn clients_from_the_package_need_the_resolved_list() {
    let entry = core::<PackageClients>("  allowedClients: from-package\n");
    assert_eq!(
        TokenVerifierConfig::for_caller_issuer(&entry, ALGORITHMS.to_vec(), None).unwrap_err(),
        UnresolvedClients
    );
    let resolved =
        AdmittedClients::new(vec!["wallet".to_owned(), "portal".to_owned()]).expect("two clients");
    let config =
        TokenVerifierConfig::for_caller_issuer(&entry, ALGORITHMS.to_vec(), Some(&resolved))
            .unwrap();
    assert_eq!(config.allowed_clients, ["portal", "wallet"]);
}
