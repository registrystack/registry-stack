use super::*;
use serde_json::{json, Value};

fn claims(value: Value) -> Claims {
    serde_json::from_value(value).expect("claims")
}

fn clients(entries: &[(&str, ActorKind)]) -> DeclaredKinds {
    DeclaredKinds::Clients(
        entries
            .iter()
            .map(|(client, kind)| ((*client).to_owned(), *kind))
            .collect(),
    )
}

#[test]
fn a_declared_client_kind_is_the_kind_when_the_token_names_none() {
    let kind = caller_kind(
        &clients(&[("case-portal", ActorKind::Human)]),
        Some("case-portal"),
        &claims(json!({})),
        &ClaimNames::default(),
    )
    .unwrap();
    assert_eq!(kind, CallerKind::Declared(ActorKind::Human));
    assert_eq!(kind.kind(), Some(ActorKind::Human));
}

#[test]
fn the_issuer_kind_applies_to_every_client_of_the_entry() {
    for client in [Some("a"), Some("b"), None] {
        let kind = caller_kind(
            &DeclaredKinds::Issuer(ActorKind::Service),
            client,
            &claims(json!({})),
            &ClaimNames::default(),
        )
        .unwrap();
        assert_eq!(kind, CallerKind::Declared(ActorKind::Service));
    }
}

#[test]
fn a_client_kind_applies_only_to_the_named_client() {
    let declared = clients(&[("case-portal", ActorKind::Human)]);
    let kind = caller_kind(
        &declared,
        Some("nightly-sync"),
        &claims(json!({})),
        &ClaimNames::default(),
    )
    .unwrap();
    assert_eq!(kind, CallerKind::Unspecified);
    assert_eq!(kind.kind(), None);
}

#[test]
fn a_claimed_kind_is_used_when_nothing_is_declared() {
    let kind = caller_kind(
        &DeclaredKinds::None,
        Some("a"),
        &claims(json!({"registry_actor_kind": "agent"})),
        &ClaimNames::default(),
    )
    .unwrap();
    assert_eq!(kind, CallerKind::Claimed(ActorKind::Agent));
}

#[test]
fn a_token_with_no_kind_and_no_declaration_is_unspecified() {
    let kind = caller_kind(
        &DeclaredKinds::None,
        None,
        &claims(json!({"sub": "u"})),
        &ClaimNames::default(),
    )
    .unwrap();
    assert_eq!(kind, CallerKind::Unspecified);
}

#[test]
fn a_claim_that_agrees_with_the_declaration_is_fine_and_the_kind_stays_declared() {
    let kind = caller_kind(
        &DeclaredKinds::Issuer(ActorKind::Service),
        Some("a"),
        &claims(json!({"registry_actor_kind": "service"})),
        &ClaimNames::default(),
    )
    .unwrap();
    assert_eq!(kind, CallerKind::Declared(ActorKind::Service));
}

#[test]
fn a_claim_that_contradicts_the_declaration_is_refused_never_ignored() {
    for declared in [
        DeclaredKinds::Issuer(ActorKind::Human),
        clients(&[("a", ActorKind::Human)]),
    ] {
        let refused = caller_kind(
            &declared,
            Some("a"),
            &claims(json!({"registry_actor_kind": "service"})),
            &ClaimNames::default(),
        );
        assert_eq!(refused, Err(CallerKindError::Conflict));
    }
}

#[test]
fn a_malformed_kind_claim_is_refused_even_when_a_kind_is_declared() {
    for declared in [DeclaredKinds::None, DeclaredKinds::Issuer(ActorKind::Human)] {
        for malformed in [json!("robot"), json!(7), json!(["human"])] {
            let refused = caller_kind(
                &declared,
                None,
                &claims(json!({"registry_actor_kind": malformed})),
                &ClaimNames::default(),
            );
            assert!(
                matches!(refused, Err(CallerKindError::Claim(_))),
                "{refused:?}"
            );
        }
    }
}

#[test]
fn the_kind_claim_name_comes_from_the_claim_names() {
    let names = ClaimNames {
        actor_kind: "kind".to_owned(),
        ..ClaimNames::default()
    };
    let kind = caller_kind(
        &DeclaredKinds::None,
        None,
        &claims(json!({"kind": "human", "registry_actor_kind": "service"})),
        &names,
    )
    .unwrap();
    assert_eq!(kind, CallerKind::Claimed(ActorKind::Human));
}

fn scopes(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn identity_only_is_a_token_with_no_scope_and_no_declared_kind() {
    assert!(refuse_identity_only(&CallerKind::Unspecified, &[]).is_err());
    assert!(refuse_identity_only(&CallerKind::Unspecified, &scopes(&["records.read"])).is_ok());
    assert!(refuse_identity_only(&CallerKind::Declared(ActorKind::Human), &[]).is_ok());
}

#[test]
fn a_claimed_kind_does_not_admit_a_token_with_no_scope() {
    for kind in [ActorKind::Human, ActorKind::Agent, ActorKind::Service] {
        let refused = refuse_identity_only(&CallerKind::Claimed(kind), &[]);
        assert!(matches!(refused, Err(OidcError::IdentityOnly)), "{kind:?}");
        assert!(
            refuse_identity_only(&CallerKind::Claimed(kind), &scopes(&["records.read"])).is_ok()
        );
    }
}

#[test]
fn openid_connect_scopes_do_not_count_as_a_grant() {
    let identity = scopes(&[
        "openid",
        "profile",
        "email",
        "address",
        "phone",
        "offline_access",
    ]);
    for kind in [
        CallerKind::Unspecified,
        CallerKind::Claimed(ActorKind::Human),
    ] {
        for single in &identity {
            assert!(
                refuse_identity_only(&kind, std::slice::from_ref(single)).is_err(),
                "{kind:?} {single}"
            );
        }
        assert!(refuse_identity_only(&kind, &identity).is_err(), "{kind:?}");
        assert!(refuse_identity_only(&kind, &scopes(&["openid", "records.read"])).is_ok());
    }
    assert!(refuse_identity_only(&CallerKind::Declared(ActorKind::Human), &identity).is_ok());
}

#[test]
fn a_scope_that_only_resembles_an_openid_connect_scope_is_a_grant() {
    for grant in ["OpenID", "openid:extra", "profile.read", " email"] {
        assert!(
            refuse_identity_only(&CallerKind::Unspecified, &scopes(&[grant])).is_ok(),
            "{grant}"
        );
    }
}

#[test]
fn the_identity_only_refusal_names_the_actor_kind_check() {
    let refused = refuse_identity_only(&CallerKind::Unspecified, &[]).unwrap_err();
    assert!(matches!(refused, OidcError::IdentityOnly));
    assert_eq!(
        refused.failed_check(),
        registry_platform_authcommon::FailedCheck::ActorKind
    );
}
