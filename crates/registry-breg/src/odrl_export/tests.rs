// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use registry_manifest_core::odrl::{Constraint, Operand};
use registry_platform_oidc::{grant_claims, ActorKind, Audience, ClaimNames, Claims, GrantClaims};
use serde_json::{json, Map, Value};

use super::{constraints, ODRL_EQ, ODRL_HAS_PART, ODRL_IS_PART_OF, VOCAB};
use crate::api::{authorize_profile_claims, VerifiedRequestClaims};
use crate::contract::{AccessProfileSource, ActorKindSource, Operation};

fn profile(id: &str, actor_kind: Option<ActorKindSource>) -> AccessProfileSource {
    let mut value = json!({
        "id": id,
        "principalClaim": "registry_principal",
        "requiredScopes": ["registry:directory:read", "registry:records:read"],
        "requiredPurposes": ["directory-administration", "service-delivery"],
        "operations": ["get"],
        "readableFields": ["email", "name"],
        "rowBoundaries": []
    });
    if let Some(actor_kind) = actor_kind {
        value["actorKind"] = json!(match actor_kind {
            ActorKindSource::Human => "human",
            ActorKindSource::Agent => "agent",
            ActorKindSource::Service => "service",
        });
        value["requesterClients"] = json!(["registry-console"]);
    }
    serde_json::from_value(value).unwrap()
}

fn task_grant() -> GrantClaims {
    let extra = json!({
        "registry_actor_kind": "agent",
        "registry_grant_id": "grant-canary",
        "registry_grant_source_issuer": "https://casework.example",
        "registry_grant_client": "registry-console",
        "registry_grant_resource": "urn:registry:breg",
        "registry_grant_exp": 1_900,
        "registry_grant_bounds": {
            "type": "evidence",
            "requirement": "urn:requirement:one"
        },
        "registry_purpose": "directory-administration",
        "registry_approver": "h:approver-canary"
    });
    grant_claims(
        &Claims {
            sub: Some("principal-canary".to_owned()),
            iss: Some("https://issuer.example".to_owned()),
            aud: Some(Audience::One("urn:registry:breg".to_owned())),
            exp: Some(2_000),
            iat: Some(1_000),
            nbf: None,
            azp: Some("registry-console".to_owned()),
            client_id: None,
            extra: extra.as_object().cloned().unwrap_or_else(Map::new),
        },
        &ClaimNames::default(),
        1_500,
    )
    .unwrap()
    .unwrap()
}

struct Scenario<'a> {
    selected_profile: &'a str,
    operation: Operation,
    principal_claim: &'a str,
    scopes: &'a [&'a str],
    purpose: Option<&'a str>,
    actor_kind: Option<ActorKind>,
    requester_client: Option<&'a str>,
    actor_subject: Option<&'a str>,
    task_grant_present: bool,
}

fn verified(scenario: &Scenario<'_>) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        scenario.principal_claim,
        "principal-canary",
        scenario
            .scopes
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect::<BTreeSet<_>>(),
        scenario.purpose.map(str::to_owned),
        BTreeMap::new(),
    )
    .unwrap()
    .with_contextual_authority(
        scenario.actor_kind,
        scenario.requester_client.map(str::to_owned),
        scenario.actor_subject.map(str::to_owned),
        scenario.task_grant_present.then(task_grant),
        BTreeMap::new(),
    )
    .unwrap()
}

fn value<'a>(operand: &'a Operand, expected_operator: &str, constraint: &Constraint) -> &'a Value {
    assert_eq!(constraint.operator, expected_operator);
    let Operand::Literal(value) = operand else {
        panic!("expected literal operand")
    };
    value
}

fn values<'a>(
    operand: &'a Operand,
    expected_operator: &str,
    constraint: &Constraint,
) -> &'a [Value] {
    assert_eq!(constraint.operator, expected_operator);
    let Operand::Set(values) = operand else {
        panic!("expected set operand")
    };
    values
}

fn emitted_admits(
    profile: &AccessProfileSource,
    scenario: &Scenario<'_>,
    claims: &VerifiedRequestClaims,
) -> bool {
    constraints(profile, &profile.id, "get")
        .iter()
        .all(|constraint| {
            let term = constraint.left_operand.strip_prefix(VOCAB).unwrap();
            match term {
                "authenticated" => {
                    value(&constraint.right_operand, ODRL_EQ, constraint) == &json!(true)
                        && claims.principal().is_some()
                }
                "verifiedNonemptyClaims" => {
                    let required = values(&constraint.right_operand, ODRL_HAS_PART, constraint);
                    required.iter().all(|name| {
                        name.as_str() == claims.principal_claim() && claims.principal().is_some()
                    })
                }
                "accessProfile" => {
                    value(&constraint.right_operand, ODRL_EQ, constraint)
                        == &json!(scenario.selected_profile)
                }
                "operation" => {
                    value(&constraint.right_operand, ODRL_EQ, constraint)
                        == &json!(match scenario.operation {
                            Operation::Get => "get",
                            Operation::List => "list",
                            _ => "other",
                        })
                }
                "delegatedActor" => {
                    value(&constraint.right_operand, ODRL_EQ, constraint)
                        == &json!(claims.actor_subject().is_some())
                }
                "taskGrantPresent" => {
                    value(&constraint.right_operand, ODRL_EQ, constraint)
                        == &json!(claims.grant().is_some())
                }
                "tokenScopes" => values(&constraint.right_operand, ODRL_HAS_PART, constraint)
                    .iter()
                    .all(|scope| scope.as_str().is_some_and(|scope| claims.has_scope(scope))),
                "tokenPurpose" => values(&constraint.right_operand, ODRL_IS_PART_OF, constraint)
                    .iter()
                    .any(|purpose| purpose.as_str() == claims.purpose()),
                "requesterClient" => values(&constraint.right_operand, ODRL_IS_PART_OF, constraint)
                    .iter()
                    .any(|client| client.as_str() == claims.requester_client()),
                "actorKind" => {
                    let actual = claims.actor_kind().map(|actor_kind| match actor_kind {
                        ActorKind::Human => "human",
                        ActorKind::Agent => "agent",
                        ActorKind::Service => "service",
                    });
                    value(&constraint.right_operand, ODRL_EQ, constraint).as_str() == actual
                }
                other => panic!("unexpected constraint {other}"),
            }
        })
}

fn native_admits(
    profile: &AccessProfileSource,
    scenario: &Scenario<'_>,
    claims: &VerifiedRequestClaims,
) -> bool {
    scenario.selected_profile == profile.id
        && profile.operations.contains(&scenario.operation)
        && authorize_profile_claims(profile, claims).is_ok()
}

fn assert_differential(profile: &AccessProfileSource, scenario: Scenario<'_>) {
    let claims = verified(&scenario);
    assert_eq!(
        emitted_admits(profile, &scenario, &claims),
        native_admits(profile, &scenario, &claims),
        "profile={} selected={} operation={:?} actor={:?} client={:?} delegated={} grant={}",
        profile.id,
        scenario.selected_profile,
        scenario.operation,
        scenario.actor_kind,
        scenario.requester_client,
        scenario.actor_subject.is_some(),
        scenario.task_grant_present,
    );
}

fn valid<'a>(profile: &'a AccessProfileSource) -> Scenario<'a> {
    Scenario {
        selected_profile: &profile.id,
        operation: Operation::Get,
        principal_claim: "registry_principal",
        scopes: &["registry:directory:read", "registry:records:read"],
        purpose: Some("directory-administration"),
        actor_kind: match profile.actor_kind {
            Some(ActorKindSource::Human) => Some(ActorKind::Human),
            Some(ActorKindSource::Agent) => Some(ActorKind::Agent),
            Some(ActorKindSource::Service) => Some(ActorKind::Service),
            None => None,
        },
        requester_client: profile.actor_kind.is_some().then_some("registry-console"),
        actor_subject: (profile.actor_kind == Some(ActorKindSource::Agent))
            .then_some("delegating-subject"),
        task_grant_present: false,
    }
}

#[test]
fn emitted_constraints_match_native_profile_admission() {
    for actor_kind in [
        None,
        Some(ActorKindSource::Human),
        Some(ActorKindSource::Service),
        Some(ActorKindSource::Agent),
    ] {
        let id = match actor_kind {
            None => "unspecified-reader",
            Some(ActorKindSource::Human) => "human-reader",
            Some(ActorKindSource::Service) => "service-reader",
            Some(ActorKindSource::Agent) => "agent-reader",
        };
        let profile = profile(id, actor_kind);

        let allowed = valid(&profile);
        let claims = verified(&allowed);
        assert!(native_admits(&profile, &allowed, &claims));
        assert!(emitted_admits(&profile, &allowed, &claims));
        assert_differential(&profile, allowed);

        let mut second_allowed_purpose = valid(&profile);
        second_allowed_purpose.purpose = Some("service-delivery");
        assert_differential(&profile, second_allowed_purpose);

        let mut missing_scope = valid(&profile);
        missing_scope.scopes = &["registry:directory:read"];
        assert_differential(&profile, missing_scope);

        let mut wrong_purpose = valid(&profile);
        wrong_purpose.purpose = Some("unrelated-purpose");
        assert_differential(&profile, wrong_purpose);

        let mut wrong_profile = valid(&profile);
        wrong_profile.selected_profile = "another-profile";
        assert_differential(&profile, wrong_profile);

        let mut wrong_operation = valid(&profile);
        wrong_operation.operation = Operation::List;
        assert_differential(&profile, wrong_operation);

        let mut wrong_principal_claim = valid(&profile);
        wrong_principal_claim.principal_claim = "another_principal";
        assert_differential(&profile, wrong_principal_claim);

        let mut grant_present = valid(&profile);
        grant_present.task_grant_present = true;
        assert_differential(&profile, grant_present);

        if actor_kind.is_some() {
            let mut wrong_actor = valid(&profile);
            wrong_actor.actor_kind = Some(ActorKind::Human);
            if actor_kind == Some(ActorKindSource::Human) {
                wrong_actor.actor_kind = Some(ActorKind::Service);
            }
            assert_differential(&profile, wrong_actor);

            let mut wrong_client = valid(&profile);
            wrong_client.requester_client = Some("other-client");
            assert_differential(&profile, wrong_client);
        }

        if actor_kind == Some(ActorKindSource::Agent) {
            let mut standing_actor_missing = valid(&profile);
            standing_actor_missing.actor_subject = None;
            assert_differential(&profile, standing_actor_missing);
        } else {
            let mut unexpected_delegation = valid(&profile);
            unexpected_delegation.actor_subject = Some("delegating-subject");
            assert_differential(&profile, unexpected_delegation);
        }
    }
}
