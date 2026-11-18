// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use registry_casework::{AuthenticationError, CaseworkAuthenticator, HumanIdentityConfig};
use registry_casework_core::{
    AccessProfile, CaseworkActsAs, CaseworkProject, InboxPolicy, ProjectIdentity, QueuePolicy,
    CASEWORK_API_VERSION, CASEWORK_KIND,
};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use serde_json::{json, Value};

const AUDIENCE: &str = "urn:test:casework";
const QUEUE_MEMBER_PRINCIPAL: &str = "urn:test:person:queue-member";

#[tokio::test]
async fn trusted_human_assertion_gates_human_profiles_and_requester_accepts_service_identity() {
    let idp = MockIdp::start().await;
    assert_eq!(project().check(), Ok(()));
    let authenticator = authenticator(&idp);

    for (profile, scope, role) in [
        ("staff", "casework:staff", CaseworkActsAs::Staff),
        (
            "supervisor",
            "casework:supervisor",
            CaseworkActsAs::Supervisor,
        ),
        (
            "administrator",
            "casework:admin",
            CaseworkActsAs::Administrator,
        ),
    ] {
        let actor = authenticator
            .authenticate(&token(&idp, scope, Some(json!("human"))), profile)
            .await
            .expect("the trusted issuer's human assertion is accepted");
        assert_eq!(actor.principal.subject, QUEUE_MEMBER_PRINCIPAL);
        assert_eq!(actor.role, role);
    }

    for asserted_kind in [
        Some(json!("service")),
        None,
        Some(json!(true)),
        Some(json!([])),
        Some(json!({})),
        Some(json!("")),
    ] {
        let refusal = authenticator
            .authenticate(&token(&idp, "casework:staff", asserted_kind), "staff")
            .await
            .expect_err(
                "a service, missing, or non-string actor kind cannot produce an ActorContext",
            );
        assert_eq!(refusal, AuthenticationError::NotHuman);
    }

    let requester = authenticator
        .authenticate(
            &token(&idp, "casework:request", Some(json!("service"))),
            "requester",
        )
        .await
        .expect("the explicitly configured Requester profile accepts a service identity");
    assert_eq!(requester.role, CaseworkActsAs::Requester);
    assert_eq!(requester.principal.subject, QUEUE_MEMBER_PRINCIPAL);

    let requester_with_human_assertion = token(&idp, "casework:request", Some(json!("human")));
    let requester = authenticator
        .authenticate(&requester_with_human_assertion, "requester")
        .await
        .expect("a human assertion does not prevent selecting the Requester profile");
    assert_eq!(requester.role, CaseworkActsAs::Requester);
    for human_profile in ["staff", "supervisor", "administrator"] {
        assert_eq!(
            authenticator
                .authenticate(&requester_with_human_assertion, human_profile)
                .await
                .expect_err("the dedicated Requester scope cannot select a human profile"),
            AuthenticationError::Profile
        );
    }

    assert_eq!(
        authenticator
            .authenticate(
                &token(&idp, "casework:request", Some(json!("service"))),
                "staff"
            )
            .await
            .expect_err("selecting Staff does not union the Requester scope or identity class"),
        AuthenticationError::Profile
    );

    let wrong_audience = idp.mint_token(json!({
        "aud": "urn:test:other-service",
        "registry_principal": QUEUE_MEMBER_PRINCIPAL,
        "scope": "casework:staff",
        "registry_actor_kind": "human"
    }));
    assert_eq!(
        authenticator
            .authenticate(&wrong_audience, "staff")
            .await
            .expect_err("the verifier preserves audience enforcement"),
        AuthenticationError::Refused
    );

    let expired = idp.mint_token(json!({
        "aud": AUDIENCE,
        "registry_principal": QUEUE_MEMBER_PRINCIPAL,
        "scope": "casework:staff",
        "registry_actor_kind": "human",
        "exp": chrono::Utc::now().timestamp() - 120
    }));
    assert_eq!(
        authenticator
            .authenticate(&expired, "staff")
            .await
            .expect_err("the verifier preserves expiry enforcement"),
        AuthenticationError::Refused
    );

    assert_eq!(
        authenticator
            .authenticate(
                &token(&idp, "casework:unrelated", Some(json!("human"))),
                "staff",
            )
            .await
            .expect_err("the selected profile still requires its configured scope"),
        AuthenticationError::Profile
    );

    let missing_principal = idp.mint_token(json!({
        "aud": AUDIENCE,
        "scope": "casework:staff",
        "registry_actor_kind": "human"
    }));
    assert_eq!(
        authenticator
            .authenticate(&missing_principal, "staff")
            .await
            .expect_err("a human assertion cannot replace the configured principal claim"),
        AuthenticationError::Claims
    );

    let custom_authenticator = authenticator_with_human_identity(
        &idp,
        HumanIdentityConfig {
            claim: "session_kind".to_owned(),
            value: "person".to_owned(),
        },
    );
    let custom_human = idp.mint_token(json!({
        "aud": AUDIENCE,
        "registry_principal": QUEUE_MEMBER_PRINCIPAL,
        "scope": "casework:staff",
        "session_kind": "person"
    }));
    custom_authenticator
        .authenticate(&custom_human, "staff")
        .await
        .expect("the configured custom human claim and value are accepted");

    let default_assertion_only = token(&idp, "casework:staff", Some(json!("human")));
    assert_eq!(
        custom_authenticator
            .authenticate(&default_assertion_only, "staff")
            .await
            .expect_err("the default assertion cannot satisfy a custom claim contract"),
        AuthenticationError::NotHuman
    );

    idp.stop().await;
}

#[tokio::test]
async fn delegated_or_grant_bearing_tokens_are_refused_for_officer_profiles_only() {
    let idp = MockIdp::start().await;
    let authenticator = authenticator(&idp);

    for extra in [
        json!({"act": {"sub": "agent"}}),
        json!({"registry_grant_id": "delegated-grant"}),
    ] {
        for (profile, scope) in [
            ("staff", "casework:staff"),
            ("supervisor", "casework:supervisor"),
            ("administrator", "casework:admin"),
        ] {
            let mut claims = json!({
                "aud": AUDIENCE,
                "registry_principal": QUEUE_MEMBER_PRINCIPAL,
                "scope": scope,
                "registry_actor_kind": "human"
            });
            claims
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert_eq!(
                authenticator
                    .authenticate(&idp.mint_token(claims), profile)
                    .await
                    .expect_err("delegated authority cannot enter an officer session"),
                AuthenticationError::Refused
            );
        }

        let mut requester_claims = json!({
            "aud": AUDIENCE,
            "registry_principal": QUEUE_MEMBER_PRINCIPAL,
            "scope": "casework:request",
            "registry_actor_kind": "service"
        });
        requester_claims
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let requester = authenticator
            .authenticate(&idp.mint_token(requester_claims), "requester")
            .await
            .expect("the Requester profile may carry delegated request context");
        assert_eq!(requester.role, CaseworkActsAs::Requester);
    }

    idp.stop().await;
}

#[test]
fn human_profiles_naming_different_principal_claims_are_refused_at_load() {
    // One issuer, one person, one principal: a second human profile that reads
    // the principal from another claim would let one person hold two seats.
    let mut mixed = project();
    let mut alternate = profile(
        "staff-by-employee",
        "casework:staff-by-employee",
        CaseworkActsAs::Staff,
    );
    alternate.principal_claim = "employee_id".to_owned();
    mixed.access_profiles.push(alternate);
    let findings = mixed
        .findings()
        .into_iter()
        .map(|finding| (finding.code, finding.pointer))
        .collect::<Vec<_>>();
    assert_eq!(
        findings,
        [(
            "casework.access-profile.mixed-principal-claims",
            "/accessProfiles/staff-by-employee/principalClaim".to_owned()
        )]
    );

    let mut one_claim = project();
    one_claim.access_profiles.push(profile(
        "staff-by-employee",
        "casework:staff-by-employee",
        CaseworkActsAs::Staff,
    ));
    assert_eq!(one_claim.check(), Ok(()));
}

#[test]
fn same_role_profiles_require_distinct_scopes() {
    let mut overlapping = project();
    overlapping.access_profiles.push(profile(
        "staff-by-employee",
        "casework:staff",
        CaseworkActsAs::Staff,
    ));
    let findings = overlapping
        .findings()
        .into_iter()
        .map(|finding| (finding.code, finding.pointer))
        .collect::<Vec<_>>();
    assert_eq!(
        findings,
        [
            (
                "casework.access-profile.shared-scopes",
                "/accessProfiles/staff/requiredScopes".to_owned()
            ),
            (
                "casework.access-profile.shared-scopes",
                "/accessProfiles/staff-by-employee/requiredScopes".to_owned()
            ),
        ]
    );
}

#[tokio::test]
async fn same_role_profiles_on_one_principal_claim_are_selected_by_their_own_scope() {
    let idp = MockIdp::start().await;
    let mut two_staff = project();
    two_staff.access_profiles.push(profile(
        "staff-by-employee",
        "casework:staff-by-employee",
        CaseworkActsAs::Staff,
    ));
    assert_eq!(two_staff.check(), Ok(()));
    let authenticator = authenticator_for_project_with_human_identity(
        &idp,
        &two_staff,
        HumanIdentityConfig::default(),
    );

    assert_eq!(
        authenticator
            .authenticate(
                &token(&idp, "casework:staff", Some(json!("human"))),
                "staff-by-employee"
            )
            .await
            .expect_err("the scope of one staff profile cannot select the other"),
        AuthenticationError::Profile
    );
    let selected = authenticator
        .authenticate(
            &token(&idp, "casework:staff-by-employee", Some(json!("human"))),
            "staff-by-employee",
        )
        .await
        .expect("the profile's own scope selects it");
    assert_eq!(selected.profile_id, "staff-by-employee");
    assert_eq!(selected.role, CaseworkActsAs::Staff);
    idp.stop().await;
}

fn authenticator(idp: &MockIdp) -> CaseworkAuthenticator {
    authenticator_with_human_identity(idp, HumanIdentityConfig::default())
}

fn authenticator_with_human_identity(
    idp: &MockIdp,
    human_identity: HumanIdentityConfig,
) -> CaseworkAuthenticator {
    authenticator_for_project_with_human_identity(idp, &project(), human_identity)
}

fn authenticator_for_project_with_human_identity(
    idp: &MockIdp,
    project: &CaseworkProject,
    human_identity: HumanIdentityConfig,
) -> CaseworkAuthenticator {
    let keys = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        idp.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    CaseworkAuthenticator::new(
        project,
        oidc_verifier_config(idp.issuer(), vec![AUDIENCE.to_owned()]),
        keys,
        human_identity,
    )
}

fn token(idp: &MockIdp, scope: &str, asserted_kind: Option<Value>) -> String {
    let mut claims = json!({
        "aud": AUDIENCE,
        "registry_principal": QUEUE_MEMBER_PRINCIPAL,
        "scope": scope,
    });
    if let Some(asserted_kind) = asserted_kind {
        claims["registry_actor_kind"] = asserted_kind;
    }
    idp.mint_token(claims)
}

fn project() -> CaseworkProject {
    let starter = CaseworkProject::from_slice(include_bytes!(
        "../../../products/casework/examples/standalone-decision/casework.yaml"
    ))
    .expect("canonical review fixture");
    CaseworkProject {
        task_templates: Vec::new(),
        api_version: CASEWORK_API_VERSION.to_owned(),
        kind: CASEWORK_KIND.to_owned(),
        project: ProjectIdentity {
            id: "human-identity-auth-test".parse().unwrap(),
            version: "1".to_owned(),
        },
        access_profiles: vec![
            profile("staff", "casework:staff", CaseworkActsAs::Staff),
            profile(
                "supervisor",
                "casework:supervisor",
                CaseworkActsAs::Supervisor,
            ),
            profile(
                "administrator",
                "casework:admin",
                CaseworkActsAs::Administrator,
            ),
            AccessProfile {
                id: "requester".to_owned(),
                label: None,
                description: None,
                principal_claim: "registry_principal".to_owned(),
                required_scopes: vec!["casework:request".to_owned()],
                acts_as: CaseworkActsAs::Requester,
            },
        ],
        queues: vec![QueuePolicy {
            id: "decisions".to_owned(),
            label: "Decisions".to_owned(),
        }],
        teams: starter.teams,
        context_providers: Vec::new(),
        review_policies: starter.review_policies,
        trusted_producers: starter.trusted_producers,
        calendars: Vec::new(),
        clocks: Vec::new(),
        inbox: InboxPolicy::default(),
    }
}

fn profile(id: &str, scope: &str, role: CaseworkActsAs) -> AccessProfile {
    AccessProfile {
        id: id.to_owned(),
        label: None,
        description: None,
        principal_claim: "registry_principal".to_owned(),
        required_scopes: vec![scope.to_owned()],
        acts_as: role,
    }
}
