// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use registry_casework::{AuthenticationError, CaseworkAuthenticator, HumanIdentityConfig};
use registry_casework_core::{
    standalone_decision_starter_kind, AccessProfile, CaseworkIdentity, CaseworkProject,
    CaseworkRole, InboxPolicy, QueuePolicy, CASEWORK_API_VERSION, CASEWORK_KIND,
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
        ("staff", "casework:staff", CaseworkRole::Staff),
        (
            "supervisor",
            "casework:supervisor",
            CaseworkRole::Supervisor,
        ),
        (
            "administrator",
            "casework:admin",
            CaseworkRole::Administrator,
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
    assert_eq!(requester.role, CaseworkRole::Requester);
    assert_eq!(requester.principal.subject, QUEUE_MEMBER_PRINCIPAL);

    let requester_with_human_assertion = token(&idp, "casework:request", Some(json!("human")));
    let requester = authenticator
        .authenticate(&requester_with_human_assertion, "requester")
        .await
        .expect("a human assertion does not prevent selecting the Requester profile");
    assert_eq!(requester.role, CaseworkRole::Requester);
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
async fn same_role_profiles_with_distinct_principals_require_distinct_scopes() {
    let idp = MockIdp::start().await;

    let mut overlapping = project();
    let mut alternate = profile("staff-by-employee", "casework:staff", CaseworkRole::Staff);
    alternate.principal_claim = "employee_id".to_owned();
    overlapping.access_profiles.push(alternate);
    overlapping.hosted_kinds[0]
        .deciding_profiles
        .push("staff-by-employee".to_owned());
    assert_eq!(
        overlapping.check(),
        Err(registry_casework_core::ConfigError::AccessProfileScopes)
    );

    let mut separated = project();
    let mut alternate = profile(
        "staff-by-employee",
        "casework:staff-by-employee",
        CaseworkRole::Staff,
    );
    alternate.principal_claim = "employee_id".to_owned();
    separated.access_profiles.push(alternate);
    separated.hosted_kinds[0]
        .deciding_profiles
        .push("staff-by-employee".to_owned());
    assert_eq!(separated.check(), Ok(()));
    let authenticator = authenticator_for_project(&idp, &separated);

    let original_scope = idp.mint_token(json!({
        "aud": AUDIENCE,
        "registry_principal": QUEUE_MEMBER_PRINCIPAL,
        "employee_id": "employee-123",
        "scope": "casework:staff",
        "registry_actor_kind": "human"
    }));
    assert_eq!(
        authenticator
            .authenticate(&original_scope, "staff-by-employee")
            .await
            .expect_err("one valid claim cannot replace the alternate profile's scope"),
        AuthenticationError::Profile
    );

    let alternate_scope = idp.mint_token(json!({
        "aud": AUDIENCE,
        "registry_principal": QUEUE_MEMBER_PRINCIPAL,
        "employee_id": "employee-123",
        "scope": "casework:staff-by-employee",
        "registry_actor_kind": "human"
    }));
    let actor = authenticator
        .authenticate(&alternate_scope, "staff-by-employee")
        .await
        .expect("the independently scoped alternate principal is accepted");
    assert_eq!(actor.principal.subject, "employee-123");
    assert_eq!(actor.profile_id, "staff-by-employee");
    assert_eq!(actor.role, CaseworkRole::Staff);

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

fn authenticator_for_project(idp: &MockIdp, project: &CaseworkProject) -> CaseworkAuthenticator {
    authenticator_for_project_with_human_identity(idp, project, HumanIdentityConfig::default())
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
    CaseworkProject {
        api_version: CASEWORK_API_VERSION.to_owned(),
        kind: CASEWORK_KIND.to_owned(),
        casework: CaseworkIdentity {
            id: "human-identity-auth-test".to_owned(),
            version: "1".to_owned(),
        },
        access_profiles: vec![
            profile("staff", "casework:staff", CaseworkRole::Staff),
            profile(
                "supervisor",
                "casework:supervisor",
                CaseworkRole::Supervisor,
            ),
            profile(
                "administrator",
                "casework:admin",
                CaseworkRole::Administrator,
            ),
            AccessProfile {
                id: "requester".to_owned(),
                principal_claim: "registry_principal".to_owned(),
                required_scopes: vec!["casework:request".to_owned()],
                role: CaseworkRole::Requester,
                kinds: vec!["decision".to_owned()],
            },
        ],
        queues: vec![QueuePolicy {
            id: "decisions".to_owned(),
            label: "Decisions".to_owned(),
        }],
        sources: Vec::new(),
        hosted_kinds: vec![standalone_decision_starter_kind()],
        calendars: Vec::new(),
        clocks: Vec::new(),
        inbox: InboxPolicy::default(),
    }
}

fn profile(id: &str, scope: &str, role: CaseworkRole) -> AccessProfile {
    AccessProfile {
        id: id.to_owned(),
        principal_claim: "registry_principal".to_owned(),
        required_scopes: vec![scope.to_owned()],
        role,
        kinds: Vec::new(),
    }
}
