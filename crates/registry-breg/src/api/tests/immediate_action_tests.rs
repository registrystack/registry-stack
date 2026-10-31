// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::auth::{AuthorityClaimConfig, RegistryAuthenticator};
use crate::compiler::{compile_project, CompileProfile};
use crate::contract::parse_project_yaml;
use crate::cursor::CursorCodec;
use crate::model::{CompiledAction, CompiledRegistry};
use crate::postgres::{
    ConnectionConfig, ExpectedRegistryIdentity, PoolBounds, PostgresRecordMutationService,
    RegistryLockKey,
};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{ClaimNames, JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const PROJECT: &str = r#"
apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project: {id: action-admission, version: "1", defaultLanguage: en, canonicalBaseIri: https://action-admission.example.test}
datasets: [{id: test-dataset}]
recordTypes:
  - id: case
    primaryDataset: test-dataset
    route: cases
    mutationMode: mutable
    classification: restricted
    fields:
      - {id: label, type: string, maximumLength: 40, required: true, classification: restricted}
      - {id: region, type: string, maximumLength: 20, required: true, classification: internal}
actions:
  - id: rename-case
    execution: {mode: immediate}
    inputs:
      - {id: case-ref, apiName: caseId, type: reference, target: case, required: true, classification: restricted}
      - {id: case-label, apiName: newLabel, type: string, maximumLength: 40, required: true, classification: restricted}
    plan:
      type: fixed
      effects:
        - id: renamed
          target: {fromInput: case-ref}
          operation: patch
          set: {label: {fromInput: case-label}}
accessProfiles:
  - id: registrar
    default: true
    principalClaim: registry_principal
    requiredScopes: [case.rename]
    requiredPurposes: [case-management]
    permissions:
      actions:
        - action: rename-case
          operations: [invoke]
          targets:
            - recordType: case
              rowBoundaries: [{field: region, claim: regions, operator: in}]
          results: [renamed]
  - id: supervisor
    principalClaim: registry_principal
    requiredScopes: [case.supervise]
    requiredPurposes: [case-management]
    permissions:
      actions:
        - action: rename-case
          operations: [invoke]
          targets: [{recordType: case, rowBoundaries: unrestricted}]
          results: []
  - id: client-human
    principalClaim: registry_principal
    actorKind: human
    requesterClients: [agent-client]
    requiredScopes: [case.rename]
    requiredPurposes: [case-management]
    permissions:
      actions:
        - action: rename-case
          operations: [invoke]
          targets:
            - recordType: case
              rowBoundaries: [{field: region, claim: regions, operator: in}]
          results: [renamed]
"#;

fn compiled() -> Arc<CompiledRegistry> {
    let project = parse_project_yaml(PROJECT.as_bytes()).expect("action fixture parses");
    Arc::new(
        compile_project(&project, &[], CompileProfile::Authoring).expect("action fixture compiles"),
    )
}

fn task_action_registry() -> Arc<CompiledRegistry> {
    let mut project = parse_project_yaml(PROJECT.as_bytes()).unwrap();
    project.access_profiles.push(serde_json::from_value(json!({
        "id":"task-invoker", "principalClaim":"registry_principal", "actorKind":"agent",
        "requesterClients":["agent-client"], "requiredScopes":["case.rename"],
        "requiredPurposes":["case-management"], "taskGrant":{"sourceIssuer":"https://casework.example"},
        "permissions":{"actions":[{"action":"rename-case","operations":["invoke"],
            "targets":[{"recordType":"case","rowBoundaries":[{"field":"region","claim":"grantRegion","operator":"equals"}]}],
            "results":["renamed"]}]}
    })).unwrap());
    Arc::new(compile_project(&project, &[], CompileProfile::Authoring).unwrap())
}

#[tokio::test]
async fn task_granted_invoke_uses_exact_action_scope_and_frozen_subjects() {
    let registry = task_action_registry();
    assert!(registry
        .entities()
        .values()
        .flat_map(|entity| entity.access_profiles.values())
        .all(|profile| profile.task_grant.is_none()));
    assert_eq!(
        crate::task_grant::required_source_issuers(&registry),
        BTreeSet::from(["https://casework.example"]),
        "Action-only grants require their startup status binding"
    );
    let idp = MockIdp::start().await;
    let audience = "urn:example:breg";
    let mut verifier = oidc_verifier_config(idp.issuer(), vec![audience.into()]);
    verifier.allowed_clients = vec!["agent-client".into()];
    let auth = RegistryAuthenticator::new(
        &registry,
        verifier,
        Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        )),
        AuthorityClaimConfig::new("registry_principal", Some("registry_purpose".into())),
    )
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = json!({"aud":audience,"sub":"citizen","azp":"agent-client","registry_principal":"citizen",
        "registry_actor_kind":"agent","registry_purpose":"case-management","scope":"case.rename",
        "registry_grant_id":"00000000-0000-4000-8000-0000000000bb","registry_approver":"h:approver",
        "registry_grant_source_issuer":"https://casework.example","registry_grant_client":"agent-client",
        "registry_grant_resource":audience,"registry_grant_exp":now+600,
        "registry_grant_bounds":{"type":"breg","permissions":[{"collection":"action:rename-case","operations":["invoke"]}]},
        "identity":{"grantRegion":"north"},"grantRegion":"south"});
    let claims = auth
        .authenticate(&idp.mint_token(token.clone()))
        .await
        .unwrap();
    let service = service_for(registry.clone(), true);
    let route = registry
        .actions()
        .routes
        .iter()
        .find(|route| route.kind == ActionRouteKind::Invoke)
        .unwrap();
    let options = QueryOptions::parse(Some("accessProfile=task-invoker"), false).unwrap();
    let surface = authorize_action(&service, route, &claims, &options).unwrap();
    assert_eq!(
        surface.context.target_authority()["case"][0].values(),
        &BTreeSet::from(["north".into()])
    );
    assert_eq!(
        surface.context.task_grant().unwrap().subjects()["grantRegion"],
        "north"
    );
    assert!(
        authorize_action(&service, route, &claims, &QueryOptions::default()).is_none(),
        "ordinary profile cannot accept task authority"
    );
    for (collection, operation) in [
        ("action:other", "invoke"),
        ("action:rename-case", "start"),
        ("cases", "patch"),
    ] {
        let mut wrong = token.clone();
        wrong["registry_grant_bounds"]["permissions"] =
            json!([{"collection":collection,"operations":[operation]}]);
        let claims = auth.authenticate(&idp.mint_token(wrong)).await.unwrap();
        assert!(authorize_action(&service, route, &claims, &options).is_none());
    }
    let mut wrong_issuer = token.clone();
    wrong_issuer["registry_grant_source_issuer"] = json!("https://other.example");
    let wrong = auth
        .authenticate(&idp.mint_token(wrong_issuer))
        .await
        .unwrap();
    assert!(authorize_action(&service, route, &wrong, &options).is_none());
    let mut missing_subject = token;
    missing_subject["identity"] = json!({"other":"north"});
    let missing = auth
        .authenticate(&idp.mint_token(missing_subject))
        .await
        .unwrap();
    assert!(authorize_action(&service, route, &missing, &options).is_none());

    // The service must check live task status before trying this unavailable pool.
    let checker = Arc::new(RefusedTaskStatus(std::sync::atomic::AtomicUsize::new(0)));
    let mutations = (**service.mutations.as_ref().unwrap())
        .clone()
        .with_task_status(checker.clone());
    for _ in 0..2 {
        let correlation = crate::correlation::RequestCorrelation::breg_created();
        let result = mutations
            .invoke_action(ImmediateActionInput {
                route_id: &route.id,
                action_id: &route.action_id,
                idempotency_key: "task-status-before-pool",
                context: &surface.context,
                input: Map::new(),
                preconditions: BTreeMap::new(),
                body_bytes: 2,
                correlation: &correlation,
            })
            .await;
        assert!(matches!(
            result,
            Err(crate::mutation::MutationError::PreconditionFailed)
        ));
    }
    assert_eq!(
        checker.0.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "positive or negative status cannot be reused across invocations"
    );
}

struct RefusedTaskStatus(std::sync::atomic::AtomicUsize);
impl crate::task_grant::TaskGrantStatusChecker for RefusedTaskStatus {
    fn check<'a>(
        &'a self,
        _: &'a crate::task_grant::TaskGrantBinding,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), crate::task_grant::TaskGrantError>>
                + Send
                + 'a,
        >,
    > {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Err(crate::task_grant::TaskGrantError::Refused) })
    }
}

#[test]
fn standing_agent_cannot_use_an_untyped_immediate_profile() {
    let registry = compiled();
    let service = service_for(registry.clone(), true);
    let route = registry
        .actions()
        .routes
        .iter()
        .find(|route| route.kind == ActionRouteKind::Invoke)
        .unwrap();
    let agent = claims(
        "registry_principal",
        ["case.rename"],
        Some("case-management"),
        true,
    )
    .with_contextual_authority(
        Some(registry_platform_oidc::ActorKind::Agent),
        None,
        None,
        None,
        BTreeMap::new(),
    )
    .unwrap();
    assert!(authorize_action(&service, route, &agent, &QueryOptions::default()).is_none());
}

#[tokio::test]
async fn proposal_task_scopes_and_standing_agent_draft_and_context_permissions_are_exact() {
    use crate::{model::ProposalOperation, postgres::ProposalAuthorityOperation};
    let mut project = parse_project_yaml(PROJECT.as_bytes()).unwrap();
    let mut proposed = project.actions[0].clone();
    proposed.id = "propose-rename".into();
    proposed.execution=serde_json::from_value(json!({"mode":"proposal","proposal":{"review":{"type":"none"},"application":{"mode":"manual"},"retention":{"mode":"retain"}}})).unwrap();
    project.actions.push(proposed);
    let mut task_profile = json!({"id":"task-proposer","principalClaim":"registry_principal","actorKind":"agent","requesterClients":["agent-client"],
        "requiredScopes":["case.rename"],"requiredPurposes":["case-management"],"taskGrant":{"sourceIssuer":"https://casework.example"},
        "permissions":{"actions":[{"action":"propose-rename","operations":["start"],"targets":[{"recordType":"case","rowBoundaries":[{"field":"region","claim":"grantRegion","operator":"equals"}]}]}],
            "proposals":[{"action":"propose-rename","operations":["get","list","edit","submit","revise","cancel","apply","rebase","retry","get-review-status"],"ownership":"caller",
                "targets":[{"recordType":"case","rowBoundaries":[{"field":"region","claim":"grantRegion","operator":"equals"}]}]}]}});
    project
        .access_profiles
        .push(serde_json::from_value(task_profile.clone()).unwrap());
    task_profile["id"] = json!("standing-proposer");
    task_profile.as_object_mut().unwrap().remove("taskGrant");
    task_profile["permissions"]["proposals"][0]["operations"] = json!(["edit"]);
    project
        .access_profiles
        .push(serde_json::from_value(task_profile).unwrap());
    let registry = compile_project(&project, &[], CompileProfile::Authoring).unwrap();
    let mut proposal_only = project.clone();
    for profile in &mut proposal_only.access_profiles {
        if profile.id == "task-proposer" {
            profile.permissions.actions.clear();
        }
    }
    let proposal_only = compile_project(&proposal_only, &[], CompileProfile::Authoring).unwrap();
    assert_eq!(
        crate::task_grant::required_source_issuers(&proposal_only),
        BTreeSet::from(["https://casework.example"]),
        "Proposal-only grants require their startup status binding"
    );
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "propose-rename")
        .unwrap();
    let idp = MockIdp::start().await;
    let audience = "urn:example:breg";
    let mut verifier = oidc_verifier_config(idp.issuer(), vec![audience.into()]);
    verifier.allowed_clients = vec!["agent-client".into()];
    let auth = RegistryAuthenticator::new(
        &registry,
        verifier,
        Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        )),
        AuthorityClaimConfig::new("registry_principal", Some("registry_purpose".into())),
    )
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = json!({"aud":audience,"sub":"citizen","azp":"agent-client","registry_principal":"citizen","registry_actor_kind":"agent",
        "registry_purpose":"case-management","scope":"case.rename","registry_grant_id":"00000000-0000-4000-8000-0000000000bb",
        "registry_approver":"h:approver","registry_grant_source_issuer":"https://casework.example","registry_grant_client":"agent-client",
        "registry_grant_resource":audience,"registry_grant_exp":now+600,"identity":{"grantRegion":"north"},
        "registry_grant_bounds":{"type":"breg","permissions":[{"collection":"action:propose-rename","operations":["start"]}]}});
    let start = auth
        .authenticate(&idp.mint_token(token.clone()))
        .await
        .unwrap();
    let admit = |claims: &VerifiedRequestClaims, profile: &str, operation, id| {
        super::super::proposals::authorize(&registry, action, claims, Some(profile), operation, id)
    };
    assert!(admit(
        &start,
        "task-proposer",
        ProposalAuthorityOperation::Start,
        None
    )
    .is_some());
    let proposal_id = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
    let other = Uuid::parse_str("00000000-0000-4000-8000-000000000002").unwrap();
    assert!(admit(
        &start,
        "task-proposer",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Submit),
        Some(proposal_id)
    )
    .is_none());
    let mut lifecycle_token = token.clone();
    lifecycle_token["registry_grant_bounds"]["permissions"] =
        json!([{"collection":format!("proposal:{proposal_id}"),"operations":["submit","list"]}]);
    let lifecycle = auth
        .authenticate(&idp.mint_token(lifecycle_token.clone()))
        .await
        .unwrap();
    assert!(admit(
        &lifecycle,
        "task-proposer",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Submit),
        Some(proposal_id)
    )
    .is_some());
    assert!(admit(
        &lifecycle,
        "task-proposer",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Submit),
        Some(other)
    )
    .is_none());
    assert!(admit(
        &lifecycle,
        "task-proposer",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Apply),
        Some(proposal_id)
    )
    .is_none());
    let list = admit(
        &lifecycle,
        "task-proposer",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::List),
        None,
    )
    .unwrap();
    assert_eq!(list.proposal_scope, Some(BTreeSet::from([proposal_id])));
    lifecycle_token["registry_grant_source_issuer"] = json!("https://other.example");
    let wrong = auth
        .authenticate(&idp.mint_token(lifecycle_token))
        .await
        .unwrap();
    assert!(admit(
        &wrong,
        "task-proposer",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Submit),
        Some(proposal_id)
    )
    .is_none());
    let mut standing = token;
    standing
        .as_object_mut()
        .unwrap()
        .retain(|name, _| !name.starts_with("registry_grant_") && name != "registry_approver");
    standing["grantRegion"] = json!("north");
    let standing = auth.authenticate(&idp.mint_token(standing)).await.unwrap();
    assert!(standing.actor_subject().is_none() && standing.grant().is_none());
    assert!(admit(
        &standing,
        "standing-proposer",
        ProposalAuthorityOperation::Start,
        None
    )
    .is_some());
    assert!(admit(
        &standing,
        "standing-proposer",
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Edit),
        Some(proposal_id)
    )
    .is_some());
    let discovery = service_for(Arc::new(registry.clone()), true);
    let selected = QueryOptions::parse(Some("accessProfile=standing-proposer"), false).unwrap();
    assert!(
        visible_actions(&discovery, &standing, &selected)
            .iter()
            .any(|surface| surface.action.id == "propose-rename"
                && surface.route.operation == Operation::Start),
        "the permitted draft Start is also discoverable"
    );
    for operation in [
        ProposalOperation::Get,
        ProposalOperation::List,
        ProposalOperation::Submit,
        ProposalOperation::Apply,
    ] {
        assert!(admit(
            &standing,
            "standing-proposer",
            ProposalAuthorityOperation::Lifecycle(operation),
            Some(proposal_id)
        )
        .is_none());
    }
}

#[test]
fn delegated_standing_agent_reads_only_its_bounded_review_context() {
    use crate::{model::ProposalOperation, postgres::ProposalAuthorityOperation};

    let mut project = parse_project_yaml(PROJECT.as_bytes()).unwrap();
    let mut proposed = project.actions[0].clone();
    proposed.id = "propose-rename".into();
    proposed.execution = serde_json::from_value(json!({
        "mode":"proposal",
        "proposal":{
            "review":{"type":"none"},
            "application":{"mode":"manual"},
            "retention":{"mode":"retain"},
            "reviewContext":{
                "id":"rename-context",
                "fields":{
                    "currentLabel":{"type":"record","input":"case-ref","field":"label"},
                    "proposedLabel":{"type":"input","input":"case-label"}
                }
            }
        }
    }))
    .unwrap();
    project.actions.push(proposed);
    project.access_profiles[0].permissions.actions.push(
        serde_json::from_value(json!({
            "action":"propose-rename",
            "operations":["start"],
            "targets":[{
                "recordType":"case",
                "rowBoundaries":[{"field":"region","claim":"regions","operator":"in"}]
            }]
        }))
        .unwrap(),
    );
    project.access_profiles.push(
        serde_json::from_value(json!({
            "id":"casework-source-reader",
            "principalClaim":"registry_principal",
            "actorKind":"agent",
            "requesterClients":["casework-source-reader"],
            "requiredScopes":["case.review"],
            "requiredPurposes":["case-management"],
            "permissions":{
                "records":[{
                    "recordType":"case",
                    "operations":["get"],
                    "readableFields":["label"],
                    "rowBoundaries":[{"field":"region","claim":"regions","operator":"in"}]
                }],
                "proposals":[{
                    "action":"propose-rename",
                    "operations":["get-review-context"],
                    "readableContextFields":["currentLabel","proposedLabel"],
                    "targets":[{
                        "recordType":"case",
                        "rowBoundaries":[{"field":"region","claim":"regions","operator":"in"}]
                    }]
                }]
            }
        }))
        .unwrap(),
    );
    let registry = compile_project(&project, &[], CompileProfile::Authoring).unwrap();
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "propose-rename")
        .unwrap();
    let delegated = claims(
        "registry_principal",
        ["case.review"],
        Some("case-management"),
        true,
    )
    .with_contextual_authority(
        Some(registry_platform_oidc::ActorKind::Agent),
        Some("casework-source-reader".into()),
        Some("00000000-0000-4000-8000-0000000000c7".into()),
        None,
        BTreeMap::new(),
    )
    .unwrap();
    let admit = |claims: &VerifiedRequestClaims, operation| {
        super::super::proposals::authorize(
            &registry,
            action,
            claims,
            Some("casework-source-reader"),
            ProposalAuthorityOperation::Lifecycle(operation),
            Some(Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap()),
        )
    };
    let authority = admit(&delegated, ProposalOperation::GetReviewContext)
        .expect("verified delegated actor receives bounded context authority");
    assert!(
        delegated.human_identity().is_none(),
        "agent disclosure is not evidence of human viewing or approval"
    );
    assert_eq!(
        authority.operation,
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::GetReviewContext)
    );
    for operation in [
        ProposalOperation::Get,
        ProposalOperation::List,
        ProposalOperation::Edit,
        ProposalOperation::Submit,
        ProposalOperation::Apply,
    ] {
        assert!(admit(&delegated, operation).is_none(), "{operation:?}");
    }

    let direct_agent = claims(
        "registry_principal",
        ["case.review"],
        Some("case-management"),
        true,
    )
    .with_contextual_authority(
        Some(registry_platform_oidc::ActorKind::Agent),
        Some("casework-source-reader".into()),
        None,
        None,
        BTreeMap::new(),
    )
    .unwrap();
    assert!(admit(&direct_agent, ProposalOperation::GetReviewContext).is_none());

    for (label, scopes, purpose, client, boundary) in [
        (
            "purpose missing",
            vec!["case.review"],
            None,
            "casework-source-reader",
            true,
        ),
        (
            "purpose mismatched",
            vec!["case.review"],
            Some("other-purpose"),
            "casework-source-reader",
            true,
        ),
        (
            "scope missing",
            vec![],
            Some("case-management"),
            "casework-source-reader",
            true,
        ),
        (
            "foreign trusted actor client",
            vec!["case.review"],
            Some("case-management"),
            "other-source-reader",
            true,
        ),
        (
            "row claim missing",
            vec!["case.review"],
            Some("case-management"),
            "casework-source-reader",
            false,
        ),
    ] {
        let claims = VerifiedRequestClaims::authenticated(
            "registry_principal",
            "synthetic-registrar",
            scopes.into_iter().map(str::to_owned).collect(),
            purpose.map(str::to_owned),
            if boundary {
                BTreeMap::from([(
                    "regions".to_owned(),
                    VerifiedClaimValue::direct_string_set(["north"]).unwrap(),
                )])
            } else {
                BTreeMap::new()
            },
        )
        .unwrap()
        .with_contextual_authority(
            Some(registry_platform_oidc::ActorKind::Agent),
            Some(client.into()),
            Some("00000000-0000-4000-8000-0000000000c7".into()),
            None,
            BTreeMap::new(),
        )
        .unwrap();
        assert!(
            admit(&claims, ProposalOperation::GetReviewContext).is_none(),
            "{label}"
        );
    }
}

#[tokio::test]
async fn signed_task_token_cannot_discover_or_invoke_an_ordinary_immediate_action() {
    let registry = compiled();
    let idp = MockIdp::start().await;
    let audience = "urn:example:breg";
    let mut verifier = oidc_verifier_config(idp.issuer(), vec![audience.to_owned()]);
    verifier.allowed_clients = vec!["agent-client".to_owned()];
    let auth = RegistryAuthenticator::new(
        &registry,
        verifier,
        Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        )),
        AuthorityClaimConfig::new("registry_principal", Some("registry_purpose".to_owned())),
    )
    .expect("action verifier config is valid");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = idp.mint_token(json!({
        "aud": audience,
        "sub": "citizen-sub",
        "azp": "agent-client",
        "registry_principal": "citizen-sub",
        "registry_actor_kind": "agent",
        "registry_purpose": "case-management",
        "registry_grant_id": "00000000-0000-4000-8000-0000000000bb",
        "registry_approver": "h:synthetic-approver",
        "registry_grant_source_issuer": "https://casework.example",
        "registry_grant_client": "agent-client",
        "registry_grant_resource": audience,
        "registry_grant_exp": now + 600,
        "registry_grant_bounds": {"type":"breg","permissions":[{"collection":"cases","operations":["get"]}]},
        "identity": {"tenant": "tenant-a"},
        "scope": "case.rename"
    }));
    let claims = auth
        .authenticate(&token)
        .await
        .expect("signed task token verifies");
    let service = service_for(registry.clone(), true);
    let route = &registry.actions().routes[0];
    assert!(authorize_action(&service, route, &claims, &QueryOptions::default()).is_none());
    assert!(visible_actions(&service, &claims, &QueryOptions::default()).is_empty());
}

#[test]
fn invocation_uses_public_names_and_a_closed_typed_envelope() {
    let registry = compiled();
    let action = &registry.actions().actions[0];
    let body = br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}}}"#;
    let parsed = parse_body(action, ActionRouteKind::Invoke, body).unwrap();
    assert_eq!(parsed.input["case-label"], "Changed");
    assert!(parsed.input.contains_key("case-ref"));
    assert_eq!(parsed.preconditions["case-ref"], "\"opaque\"");

    for refused in [
        br#"{"input":{"case-ref":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}}}"#.as_slice(),
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":4},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}}}"#,
        br#"{"input":{"caseId":null,"newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}}}"#,
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":null},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}}}"#,
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"}}"#,
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"\"opaque\"","revision":1}}}"#,
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"*"}}}"#,
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}},"results":["renamed"]}"#,
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed","newLabel":"Duplicate"},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}}}"#,
    ] {
        assert!(parse_body(action, ActionRouteKind::Invoke, refused).is_err());
    }
}

#[test]
fn a_fixed_patch_target_remains_required_when_its_input_is_declared_optional() {
    let mut project = parse_project_yaml(PROJECT.as_bytes()).unwrap();
    project.actions[0].inputs[0].required = false;
    let registry = compile_project(&project, &[], CompileProfile::Authoring).unwrap();
    let action = &registry.actions().actions[0];
    assert!(
        !action
            .inputs
            .iter()
            .find(|input| input.id == "case-ref")
            .unwrap()
            .required
    );
    let complete = br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}}}"#;
    assert!(parse_body(action, ActionRouteKind::Invoke, complete).is_ok());
    for refused in [
        br#"{"input":{"newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}}}"#.as_slice(),
        br#"{"input":{"caseId":null,"newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}}}"#,
    ] {
        assert_eq!(
            parse_error_path(action, ActionRouteKind::Invoke, refused),
            "/input/caseId"
        );
    }
    for refused in [
        br#"{"input":{}}"#.as_slice(),
        br#"{"input":{"caseId":null}}"#,
    ] {
        assert_eq!(
            parse_error_path(action, ActionRouteKind::TargetConditions, refused),
            "/input/caseId"
        );
    }
}

#[test]
fn fixed_optional_from_input_is_typed_and_rejects_null_at_http_admission() {
    let project = parse_project_yaml(include_bytes!(
        "../../../tests/fixtures/fixed-optional-action-input.yaml"
    ))
    .unwrap();
    let registry = compile_project(&project, &[], CompileProfile::Authoring).unwrap();
    let action = &registry.actions().actions[0];
    assert!(action.handler.is_none());
    let complete = br#"{"input":{"displayLabel":"A label"}}"#;
    let null = br#"{"input":{"displayLabel":null}}"#;
    let schema = crate::artifacts::openapi_action_input_schema(action);
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    assert!(validator.is_valid(&serde_json::from_slice::<Value>(complete).unwrap()));
    assert!(!validator.is_valid(&serde_json::from_slice::<Value>(null).unwrap()));
    assert!(parse_body(action, ActionRouteKind::Invoke, complete).is_ok());
    assert_eq!(
        parse_error_path(action, ActionRouteKind::Invoke, null),
        "/input/displayLabel"
    );
}

#[test]
fn handler_timestamp_admission_enforces_the_kernel_string_bound_without_changing_fixed_inputs() {
    let mut project = parse_project_yaml(include_bytes!(
        "../../../tests/fixtures/fixed-optional-action-input.yaml"
    ))
    .unwrap();
    project.actions[0].inputs[0].field_type = crate::contract::FieldTypeSource::Timestamp;
    project.entities[0].fields[0].field_type = crate::contract::FieldTypeSource::Timestamp;
    let oversized = serde_json::to_vec(&json!({
        "input": {"displayLabel": format!("2026-09-08T10:20:30.{}Z", "1".repeat(16_384))}
    }))
    .unwrap();
    let fixed = compile_project(&project, &[], CompileProfile::Authoring).unwrap();
    assert!(parse_body(
        &fixed.actions().actions[0],
        ActionRouteKind::Invoke,
        &oversized
    )
    .is_ok());

    project.functions.push(
        serde_json::from_value(json!({
            "id":"create-entry-plan", "runtime":"rhai", "source":"handlers/create-entry.rhai",
            "entrypoint":"plan", "abi":"registry.action-plan/v1"
        }))
        .unwrap(),
    );
    project.actions[0].plan = serde_json::from_value(json!({
        "type":"function", "function":"create-entry-plan", "inputs":["label"],
        "writes": [{"id": "created", "target": {"recordType": "entry"}, "operation": "create", "fields": ["label"]}]
    })).unwrap();
    let handler = crate::compiler::compile_project_with_assets(
        &project,
        &[],
        &[crate::contract::ModuleAssetSource {
            module: None,
            path: "handlers/create-entry.rhai".to_owned(),
            bytes: br#"fn plan(ctx) { #{effects:[#{id:"created",set:#{label:"2026-09-08T10:20:30Z"}}]} }"#.to_vec(),
        }],
        CompileProfile::Authoring,
    ).unwrap();
    let action = &handler.actions().actions[0];
    for accepted in [
        br#"{"input":{"displayLabel":"2026-09-08T10:20:30.123Z"}}"#.as_slice(),
        br#"{"input":{"displayLabel":null}}"#,
        br#"{"input":{}}"#,
    ] {
        assert!(parse_body(action, ActionRouteKind::Invoke, accepted).is_ok());
    }
    assert_eq!(
        parse_error_path(action, ActionRouteKind::Invoke, &oversized),
        "/input/displayLabel"
    );
}

#[test]
fn malformed_action_body_reports_only_safe_field_paths() {
    let registry = compiled();
    let action = &registry.actions().actions[0];

    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001"}}"#
        ),
        "/input/newLabel"
    );
    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":4},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}}}"#
        ),
        "/input/newLabel"
    );
    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed","secret_claim":"north"},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}}}"#
        ),
        "/input"
    );
    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"}}"#
        ),
        "/preconditions"
    );
    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"*"}}}"#
        ),
        "/preconditions/caseId/ifMatch"
    );
    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"\"opaque\"","secret_claim":"north"}}}"#
        ),
        "/preconditions/caseId"
    );
    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"secret_claim":"north"}}}"#
        ),
        "/preconditions/caseId"
    );
    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"secret_claim":{"ifMatch":"\"opaque\""}}}"#
        ),
        "/preconditions"
    );
    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}},"secret_claim":"north"}"#
        ),
        ""
    );
}

#[test]
fn field_paths_escape_declared_public_input_names() {
    assert_eq!(
        json_pointer(["input", "declared/name~with~tilde"]),
        "/input/declared~1name~0with~0tilde"
    );
}

#[tokio::test]
async fn correlated_action_problem_preserves_safe_field_path() {
    let response = invalid_action_request(ParseActionError::at("/input/newLabel"));
    let correlation = crate::correlation::RequestCorrelation::breg_created();
    let response =
        crate::correlation::finish_response(response, &correlation, "POST", Instant::now());
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let body = parse_json_strict(&bytes).unwrap();
    assert_eq!(body["code"], "request.invalid");
    assert_eq!(body["fieldPath"], "/input/newLabel");
    assert_eq!(body["traceId"], correlation.trace_id().as_str());
}

#[test]
fn condition_read_accepts_only_exact_patch_role_identifiers() {
    let registry = compiled();
    let action = &registry.actions().actions[0];
    let parsed = parse_body(
        action,
        ActionRouteKind::TargetConditions,
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001"}}"#,
    )
    .unwrap();
    assert_eq!(parsed.input.len(), 1);
    assert!(parsed.preconditions.is_empty());
    for refused in [
        br#"{"input":{}}"#.as_slice(),
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"}}"#,
        br#"{"input":{"caseId":"not-a-record"}}"#,
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001"},"preconditions":{}}"#,
        br#"{"input":{"caseId":["00000000-0000-4000-8000-000000000001"]}}"#,
    ] {
        assert!(parse_body(action, ActionRouteKind::TargetConditions, refused).is_err());
    }
}

fn parse_error_path(action: &CompiledAction, kind: ActionRouteKind, body: &[u8]) -> String {
    match parse_body(action, kind, body) {
        Ok(_) => panic!("body is refused"),
        Err(error) => error.field_path,
    }
}

#[test]
fn action_authority_has_no_crud_requirement_or_profile_fallback() {
    let registry = compiled();
    assert!(registry.routes().routes.is_empty());
    let service = service_for(registry.clone(), true);
    let route = registry
        .actions()
        .routes
        .iter()
        .find(|route| route.kind == ActionRouteKind::Invoke)
        .unwrap();
    let authorized_claims = claims(
        "registry_principal",
        ["case.rename"],
        Some("case-management"),
        true,
    );
    let surface = authorize_action(
        &service,
        route,
        &authorized_claims,
        &QueryOptions::default(),
    )
    .unwrap();
    assert_eq!(surface.context.selected_profile(), "registrar");
    assert_eq!(
        surface.context.result_effects(),
        &BTreeSet::from(["renamed".to_owned()])
    );
    assert_eq!(
        surface.context.target_authority()["case"][0].field(),
        "region"
    );
    let supervisor = claims(
        "registry_principal",
        ["case.supervise"],
        Some("case-management"),
        false,
    );
    assert!(authorize_action(&service, route, &supervisor, &QueryOptions::default()).is_none());
    let explicit = QueryOptions::parse(Some("accessProfile=supervisor"), false).unwrap();
    assert!(authorize_action(&service, route, &supervisor, &explicit)
        .unwrap()
        .context
        .result_effects()
        .is_empty());
    for denied in [
        claims("sub", ["case.rename"], Some("case-management"), true),
        claims("registry_principal", ["case.rename"], None, true),
        claims(
            "registry_principal",
            ["case.rename"],
            Some("other-purpose"),
            true,
        ),
        claims(
            "registry_principal",
            ["case.rename"],
            Some("case-management"),
            false,
        ),
    ] {
        assert!(authorize_action(&service, route, &denied, &QueryOptions::default()).is_none());
    }
    let mut forged = route.clone();
    forged.path.push_str("/forged");
    assert!(authorize_action(
        &service,
        &forged,
        &authorized_claims,
        &QueryOptions::default()
    )
    .is_none());
    assert!(visible_actions(
        &service_for(registry, false),
        &authorized_claims,
        &QueryOptions::default()
    )
    .is_empty());
}

#[tokio::test]
async fn human_identity_is_the_principal_claim_and_a_human_token_without_it_is_refused() {
    let registry = compiled();
    let idp = MockIdp::start().await;
    let audience = "urn:example:breg";
    let mut verifier = oidc_verifier_config(idp.issuer(), vec![audience.to_owned()]);
    verifier.allowed_clients = vec!["agent-client".to_owned()];
    let auth = RegistryAuthenticator::new(
        &registry,
        verifier,
        Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        )),
        AuthorityClaimConfig::new("registry_principal", Some("registry_purpose".to_owned())),
    )
    .expect("human verifier config is valid");
    let claims = json!({
        "aud": audience,
        "azp": "agent-client",
        "registry_principal": "reviewer-principal",
        "registry_actor_kind": "human",
        "registry_purpose": "case-management",
        "regions": ["north"],
        "scope": "case.rename"
    });

    // The person is named by the principal claim, with no `sub` needed.
    let named = auth
        .authenticate(&idp.mint_token(claims.clone()))
        .await
        .expect("a human token with its principal claim authenticates");
    let identity = named
        .human_identity()
        .expect("a human token names a person");
    assert_eq!(identity.issuer, idp.issuer());
    assert_eq!(identity.subject, "reviewer-principal");

    // A human token without the principal claim is refused before it can
    // name anyone, even when it carries `sub`.
    let mut unnamed = claims;
    unnamed
        .as_object_mut()
        .unwrap()
        .remove("registry_principal");
    unnamed["sub"] = json!("reviewer-principal");
    assert!(matches!(
        auth.authenticate(&idp.mint_token(unnamed)).await,
        Err(crate::auth::AuthenticationError::InvalidClaims)
    ));
}

/// A delegated actor without an explicit task grant cannot invoke an Action,
/// including through a profile declaring no `actorKind` or a human kind.
#[tokio::test]
async fn delegated_token_is_refused_at_immediate_action_admission() {
    let registry = compiled();
    let idp = MockIdp::start().await;
    let audience = "urn:example:breg";
    let actor = "00000000-0000-4000-8000-0000000000aa";
    let mut verifier = oidc_verifier_config(idp.issuer(), vec![audience.to_owned()]);
    verifier.allowed_clients = vec!["agent-client".to_owned()];
    let auth = RegistryAuthenticator::new(
        &registry,
        verifier,
        Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        )),
        AuthorityClaimConfig::new("registry_principal", Some("registry_purpose".to_owned()))
            .with_contextual_claims(
                ClaimNames::default(),
                BTreeMap::from([("agent-client".to_owned(), actor.to_owned())]),
            ),
    )
    .expect("delegated verifier config is valid");
    let service = service_for(registry.clone(), true);
    let route = registry
        .actions()
        .routes
        .iter()
        .find(|route| route.kind == ActionRouteKind::Invoke)
        .unwrap();
    // `registrar` declares no actorKind and admits every kind of direct token.
    let registrar = QueryOptions::parse(Some("accessProfile=registrar"), false).unwrap();
    // `client-human` binds the same client to a human actor.
    let client_human = QueryOptions::parse(Some("accessProfile=client-human"), false).unwrap();
    // A token exchange copies the citizen's kind claim from the subject token.
    let claims = json!({
        "aud": audience,
        "sub": "citizen-sub",
        "azp": "agent-client",
        "registry_principal": "citizen-sub",
        "registry_actor_kind": "human",
        "registry_purpose": "case-management",
        "regions": ["north"],
        "scope": "case.rename"
    });
    let direct = auth
        .authenticate(&idp.mint_token(claims.clone()))
        .await
        .expect("token without act authenticates");
    assert!(authorize_action(&service, route, &direct, &registrar).is_some());
    assert!(authorize_action(&service, route, &direct, &client_human).is_some());

    for act in [
        json!({"sub": actor}),
        json!({"sub": actor, "iss": idp.issuer()}),
    ] {
        let mut delegated_claims = claims.clone();
        delegated_claims["act"] = act;
        let delegated = auth
            .authenticate(&idp.mint_token(delegated_claims))
            .await
            .expect("registered client and actor pair authenticates");
        assert!(authorize_action(&service, route, &delegated, &registrar).is_none());
        assert!(authorize_action(&service, route, &delegated, &client_human).is_none());
    }
}

#[tokio::test]
async fn action_only_discovery_is_profile_filtered_without_entity_read_access() {
    let registry = compiled();
    let service = Arc::new(service_for(registry, true));
    let registrar = claims(
        "registry_principal",
        ["case.rename"],
        Some("case-management"),
        true,
    );
    let supervisor = claims(
        "registry_principal",
        ["case.supervise"],
        Some("case-management"),
        false,
    );

    let response = super::super::registry_metadata(
        State(service.clone()),
        Authenticated(registrar),
        RawQuery(None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["recordTypes"], json!([]));
    assert_eq!(body["actions"][0]["id"], "rename-case");
    assert_eq!(
        body["actions"][0]["requiredConditionKeys"],
        json!(["caseId"])
    );
    assert!(!body.to_string().contains("registry_principal"));
    assert!(!body.to_string().contains("rowBoundaries"));

    let response = super::super::openapi(
        State(service.clone()),
        Authenticated(supervisor),
        RawQuery(Some("accessProfile=supervisor".to_owned())),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert!(body["paths"]["/v1/actions/rename-case"]["post"].is_object());
    assert!(body["paths"]["/v1/actions/rename-case/target-conditions"]["post"].is_object());
    assert!(body["paths"]
        .as_object()
        .unwrap()
        .keys()
        .all(|path| path.starts_with("/v1/actions/")));
    let result_schema = crate::artifacts::openapi_action_response_schema_id("rename-case");
    assert_eq!(
        body["components"]["schemas"][&result_schema]["properties"]["results"]["properties"],
        json!({})
    );
    assert!(!body.to_string().contains("registrar"));

    // A caller whose token matches no profile has no visible operation or
    // action and receives the same value-free 404 as on record routes.
    let unmatched = claims("sub", ["case.rename"], Some("case-management"), true);
    let hidden = super::super::registry_metadata(
        State(service.clone()),
        Authenticated(unmatched.clone()),
        RawQuery(None),
    )
    .await;
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);
    let refused = super::super::openapi(
        State(service),
        Authenticated(unmatched),
        RawQuery(Some("accessProfile=supervisor".to_owned())),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn proposal_metadata_roundtrips_exact_profile_inventory_and_document_requirements() {
    use registry_breg_client::BRegMetadata;
    use tower::ServiceExt;

    let mut project = parse_project_yaml(PROJECT.as_bytes()).unwrap();
    project.actions[0].execution = serde_json::from_value(json!({
        "mode":"proposal", "proposal": {
            "review":{"type":"none"}, "application":{"mode":"manual"}, "retention":{"mode":"retain"},
            "attachments":[
                {"id":"supporting-file","required":true,"maximumBytes":1024,"contentTypes":["application/pdf"],"classification":"restricted"},
                {"id":"private-file","required":false,"maximumBytes":2048,"contentTypes":["image/png"],"classification":"restricted"}
            ]
        }
    })).unwrap();
    let mut hidden = project.actions[0].clone();
    hidden.id = "hidden-rename".into();
    project.actions.push(hidden);
    project.access_profiles.clear();
    for (profile, starts, operations, readable, slots) in [
        (
            "author",
            true,
            json!(["get"]),
            json!(["case-ref"]),
            json!(["supporting-file"]),
        ),
        ("starter", true, json!([]), json!([]), json!([])),
        (
            "reader",
            false,
            json!(["get"]),
            json!(["case-ref"]),
            json!(["supporting-file"]),
        ),
        ("queue", false, json!(["list"]), json!([]), json!([])),
        ("executor", false, json!(["apply"]), json!([]), json!([])),
        ("hidden", true, json!(["get"]), json!([]), json!([])),
    ] {
        let action = if profile == "hidden" {
            "hidden-rename"
        } else {
            "rename-case"
        };
        let targets = json!([{"recordType":"case","rowBoundaries":"unrestricted"}]);
        let actions = if starts {
            json!([{"action":action,"operations":["start"],"targets":targets}])
        } else {
            json!([])
        };
        let proposals = if operations.as_array().unwrap().is_empty() {
            json!([])
        } else {
            json!([{"action":action,"operations":operations,"ownership":"caller","targets":targets,
                "readableInputs":readable,"readableAttachments":slots}])
        };
        project.access_profiles.push(serde_json::from_value(json!({
            "id":profile,"principalClaim":"registry_principal",
            "requiredScopes":[if profile == "hidden" { "case.hidden" } else { "case.rename" }],
            "requiredPurposes":["case-management"], "permissions":{"actions":actions,"proposals":proposals}
        })).unwrap());
    }
    let registry = Arc::new(compile_project(&project, &[], CompileProfile::Authoring).unwrap());
    let service = Arc::new(service_for(registry, true));
    let caller = claims(
        "registry_principal",
        ["case.rename"],
        Some("case-management"),
        true,
    );
    for profile in ["author", "starter", "reader", "queue", "executor"] {
        let mut request = axum::http::Request::builder()
            .uri(format!("/v1/registry?accessProfile={profile}"))
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(caller.clone());
        let response = super::super::router(service.clone())
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{profile}");
        assert_eq!(response.headers()["cache-control"], "no-store");
        let document = response_json(response).await;
        assert_eq!(document["metadataVersion"], "2");
        let rendered = document.to_string();
        for hidden in [
            "hidden-rename",
            "case.hidden",
            "rowBoundaries",
            "reviewPolicy",
            "registry_principal",
        ] {
            assert!(!rendered.contains(hidden), "{profile} leaked {hidden}");
        }
        let metadata = BRegMetadata::from_slice(&serde_json::to_vec(&document).unwrap()).unwrap();
        if profile == "starter" {
            assert!(metadata.proposal_actions().is_empty());
            assert!(document.get("proposals").is_none());
        } else {
            let inventory = metadata.proposal_actions();
            assert_eq!(inventory.len(), 1);
            assert_eq!(inventory[0].access_profile(), profile);
            assert_eq!(inventory[0].action_identifier(), "rename-case");
            assert_eq!(
                inventory[0].operations(),
                [match profile {
                    "queue" => "list",
                    "executor" => "apply",
                    _ => "get",
                }]
            );
            assert_eq!(
                inventory[0].readable_inputs(),
                if matches!(profile, "author" | "reader") {
                    vec!["case-ref"]
                } else {
                    vec![]
                }
            );
        }
        if matches!(profile, "queue" | "executor") {
            assert!(metadata.actions().is_empty());
            assert!(document.get("actions").is_none());
        } else {
            let action = &metadata.actions()[0];
            assert_eq!(action.access_profile(), profile);
            if profile == "reader" {
                assert_eq!(action.inputs().len(), 1);
                assert_eq!(action.inputs()[0].identifier(), "case-ref");
                assert_eq!(action.attachments().len(), 1);
                assert!(action.invoke_path().is_none());
                assert!(!rendered.contains("private-file"));
            } else {
                assert_eq!(action.inputs().len(), 2);
                assert_eq!(action.attachments().len(), 2);
                assert!(action.invoke_path().is_some());
            }
            let slot = action
                .attachments()
                .iter()
                .find(|slot| slot.identifier() == "supporting-file")
                .unwrap();
            assert!(slot.required());
            assert_eq!(slot.maximum_bytes(), 1024);
            assert_eq!(slot.content_types(), ["application/pdf"]);
        }
    }
    let mut request = axum::http::Request::builder()
        .uri("/v1/registry?accessProfile=hidden")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(caller);
    assert_eq!(
        super::super::router(service)
            .oneshot(request)
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}

async fn response_json(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    parse_json_strict(&bytes).unwrap()
}

fn claims<const N: usize>(
    name: &str,
    scopes: [&str; N],
    purpose: Option<&str>,
    boundary: bool,
) -> VerifiedRequestClaims {
    let direct = if boundary {
        BTreeMap::from([(
            "regions".to_owned(),
            VerifiedClaimValue::direct_string_set(["north"]).unwrap(),
        )])
    } else {
        BTreeMap::new()
    };
    VerifiedRequestClaims::authenticated(
        name,
        "synthetic-registrar",
        scopes.into_iter().map(str::to_owned).collect(),
        purpose.map(str::to_owned),
        direct,
    )
    .unwrap()
}

fn service_for(registry: Arc<CompiledRegistry>, mutations: bool) -> HttpService {
    let duration = Duration::from_secs(1);
    let service = HttpService::new(
        registry.clone(),
        ReadRuntimeIdentity {
            package_revision: "package-revision".to_owned(),
            schema_fingerprint: "schema-fingerprint".to_owned(),
        },
        Arc::new(NoopRecords),
        Arc::new(Ready),
        Arc::new(CursorCodec::new(Zeroizing::new(vec![7; 32]), duration).unwrap()),
    );
    if !mutations {
        return service;
    }
    // Pool construction performs no database I/O. HTTP execution is tested by
    // the real PostgreSQL action journey; these tests exercise admission only.
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let pool = ConnectionConfig::require_tls_with_custom_ca(
        "postgresql://action_test@localhost/action-admission",
        certificate.cert.der(),
        PoolBounds::new(1, duration, duration, duration).unwrap(),
    )
    .unwrap()
    .build_pool()
    .unwrap();
    service.with_postgres_mutations(Arc::new(PostgresRecordMutationService::new(
        pool,
        registry,
        ExpectedRegistryIdentity {
            package_id: "test".to_owned(),
            database_id: "test".to_owned(),
            package_digest: "package-digest".to_owned(),
            activation_id: "3f2a7c1e-9b4d-4e8a-a1c6-5d0e7f9b2c41".to_owned(),
            schema_fingerprint: "schema-fingerprint".to_owned(),
        },
        "test",
        RegistryLockKey::derive("action-admission").unwrap(),
        duration,
        crate::audit::test_support::capturing(
            registry_platform_audit::AuditProfile::production_from_secret_bytes(
                vec![0x81; 32].into(),
            )
            .unwrap(),
        )
        .0,
    )))
}

struct Ready;
impl ReadinessProbe for Ready {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
struct NoopRecords;
impl RecordReadService for NoopRecords {
    fn get(
        &self,
        _: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        Box::pin(async { Ok(None) })
    }
    fn list(
        &self,
        _: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
        Box::pin(async { Err(ReadServiceError::Unavailable) })
    }
    fn lookup(
        &self,
        _: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        Box::pin(async { Ok(None) })
    }
    fn refusal(&self, _: RecordReadRefusal) -> ServiceFuture<'_, Result<(), ReadServiceError>> {
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn action_without_default_requires_explicit_profile_even_when_token_has_authority() {
    let source = PROJECT.replace("    default: true\n", "");
    let project = parse_project_yaml(source.as_bytes()).unwrap();
    let registry = Arc::new(compile_project(&project, &[], CompileProfile::Authoring).unwrap());
    let service = service_for(registry.clone(), true);
    let route = registry
        .actions()
        .routes
        .iter()
        .find(|route| route.kind == ActionRouteKind::Invoke)
        .unwrap();
    assert!(route.default_access_profile.is_none());
    let authorized = claims(
        "registry_principal",
        ["case.rename"],
        Some("case-management"),
        true,
    );
    assert!(authorize_action(&service, route, &authorized, &QueryOptions::default()).is_none());
    let explicit = QueryOptions::parse(Some("accessProfile=registrar"), false).unwrap();
    assert_eq!(
        authorize_action(&service, route, &authorized, &explicit)
            .unwrap()
            .context
            .selected_profile(),
        "registrar"
    );
}

#[test]
fn fixed_action_optional_values_reject_explicit_null_in_schema_and_admission() {
    let mut project = parse_project_yaml(PROJECT.as_bytes()).unwrap();
    project.actions[0].inputs[1].required = false;
    project.entities[0].fields[0].required = false;
    let registry = compile_project(&project, &[], CompileProfile::Authoring).unwrap();
    let action = &registry.actions().actions[0];
    let schema = crate::artifacts::openapi_action_input_schema(action);
    let validator = jsonschema::JSONSchema::compile(&schema).unwrap();
    let mut body = json!({
        "input": {"caseId": "00000000-0000-4000-8000-000000000001"},
        "preconditions": {"caseId": {"ifMatch": "\"opaque\""}}
    });
    assert!(validator.is_valid(&body));
    assert!(parse_body(
        action,
        ActionRouteKind::Invoke,
        &serde_json::to_vec(&body).unwrap()
    )
    .is_ok());
    body["input"]["newLabel"] = json!("Changed");
    assert!(validator.is_valid(&body));
    assert!(parse_body(
        action,
        ActionRouteKind::Invoke,
        &serde_json::to_vec(&body).unwrap()
    )
    .is_ok());
    body["input"]["newLabel"] = Value::Null;
    assert!(!validator.is_valid(&body));
    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            &serde_json::to_vec(&body).unwrap()
        ),
        "/input/newLabel"
    );
}

#[tokio::test]
async fn correlated_evidence_problem_exposes_only_a_safe_declared_capability_path() {
    for capability in [Some("declared-status".to_owned()), None] {
        let response = mutation_problem(MutationError::ActionEvidenceFailure {
            capability: capability.clone(),
        });
        let correlation = crate::correlation::RequestCorrelation::breg_created();
        let response =
            crate::correlation::finish_response(response, &correlation, "POST", Instant::now());
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = parse_json_strict(&bytes).unwrap();
        assert_eq!(body["code"], "action.evidence_failed");
        assert_eq!(
            body["detail"],
            "The declared Evidence dependency could not be accepted."
        );
        assert_eq!(body["traceId"], correlation.trace_id().as_str());
        if capability.is_some() {
            assert_eq!(body["fieldPath"], "/evidence/declared-status");
        } else {
            assert!(body.get("fieldPath").is_none());
        }
        assert!(body.get("selectors").is_none());
        assert!(body.get("provider").is_none());
    }
}

#[tokio::test]
async fn task_record_reads_intersect_profile_with_composed_proposal_scope() {
    let mut project = parse_project_yaml(PROJECT.as_bytes()).unwrap();
    project.access_profiles.push(serde_json::from_value(json!({
        "id":"task-reader","principalClaim":"registry_principal","actorKind":"agent",
        "requesterClients":["agent-client"],"requiredScopes":["case.read"],"requiredPurposes":["case-management"],
        "taskGrant":{"sourceIssuer":"https://casework.example"},"permissions":{"records":[{
            "recordType":"case","operations":["get","list"],"readableFields":["label","region"],
            "rowBoundaries":[{"field":"region","claim":"grantRegion","operator":"equals"}]}]}
    })).unwrap());
    let registry = Arc::new(compile_project(&project, &[], CompileProfile::Authoring).unwrap());
    let service = service_for(registry.clone(), true);
    let idp = MockIdp::start().await;
    let audience = "urn:example:breg";
    let mut verifier = oidc_verifier_config(idp.issuer(), vec![audience.into()]);
    verifier.allowed_clients = vec!["agent-client".into()];
    let auth = RegistryAuthenticator::new(
        &registry,
        verifier,
        Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        )),
        AuthorityClaimConfig::new("registry_principal", Some("registry_purpose".into())),
    )
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = json!({"aud":audience,"sub":"citizen","azp":"agent-client","registry_principal":"citizen",
        "registry_actor_kind":"agent","registry_purpose":"case-management","scope":"case.read",
        "registry_grant_id":"00000000-0000-4000-8000-0000000000bc","registry_approver":"h:approver",
        "registry_grant_source_issuer":"https://casework.example","registry_grant_client":"agent-client",
        "registry_grant_resource":audience,"registry_grant_exp":now+600,
        "registry_grant_bounds":{"type":"breg","permissions":[
            {"collection":"cases","operations":["get","list"]},
            {"collection":"proposal:00000000-0000-4000-8000-0000000000bd","operations":["get","edit","list"]}]},
        "identity":{"grantRegion":"north"},"grantRegion":"south"});
    let claims = auth
        .authenticate(&idp.mint_token(token.clone()))
        .await
        .unwrap();
    let profile = &registry.entities()["case"].access_profiles["task-reader"];
    let binding = task_grant_binding(profile, &claims)
        .expect("composed independently scoped bounds are admitted")
        .unwrap();
    assert_eq!(binding.subjects()["grantRegion"], json!("north"));
    let route = registry
        .routes()
        .routes
        .iter()
        .find(|route| route.entity_id == "case" && route.operation == Operation::Get)
        .unwrap();
    let options = QueryOptions::parse(Some("accessProfile=task-reader"), false).unwrap();
    assert!(authorize_route(&service, route, &claims, &options).is_some());
    let patch = registry
        .routes()
        .routes
        .iter()
        .find(|route| route.entity_id == "case" && route.operation == Operation::Patch);
    assert!(
        patch.is_none_or(|route| authorize_route(&service, route, &claims, &options).is_none()),
        "extra bounds cannot create profile permissions"
    );
    for permissions in [
        json!([{"collection":"proposal:00000000-0000-4000-8000-0000000000bd","operations":["get","edit"]}]),
        json!([{"collection":"cases","operations":["get"]}]),
    ] {
        let mut wrong = token.clone();
        wrong["registry_grant_bounds"]["permissions"] = permissions;
        let claims = auth.authenticate(&idp.mint_token(wrong)).await.unwrap();
        assert!(
            task_grant_binding(profile, &claims).is_err(),
            "missing profile powers remain refused"
        );
    }
    let mut wrong = token;
    wrong["registry_grant_source_issuer"] = json!("https://other.example");
    let claims = auth.authenticate(&idp.mint_token(wrong)).await.unwrap();
    assert!(task_grant_binding(profile, &claims).is_err());
}

#[test]
fn availability_accepts_partial_inputs_but_requires_one_declared_reference() {
    let registry = compiled();
    let action = &registry.actions().actions[0];
    let id = "00000000-0000-4000-8000-000000000101";
    let valid = json!({"targetInput":"caseId","input":{"caseId":id}});
    let parsed = parse_body(
        action,
        ActionRouteKind::Availability,
        &serde_json::to_vec(&valid).unwrap(),
    )
    .unwrap();
    assert_eq!(parsed.target_input.as_deref(), Some("case-ref"));
    assert_eq!(
        parsed.input,
        json!({"case-ref":id}).as_object().unwrap().clone()
    );
    assert!(parsed.preconditions.is_empty());
    for (body, path) in [
        (json!({"input":{"caseId":id}}), "/targetInput"),
        (
            json!({"targetInput":"case-ref","input":{"caseId":id}}),
            "/targetInput",
        ),
        (
            json!({"targetInput":"newLabel","input":{"caseId":id}}),
            "/targetInput",
        ),
        (json!({"targetInput":"caseId","input":{}}), "/input/caseId"),
        (
            json!({"targetInput":"caseId","input":{"caseId":null}}),
            "/input/caseId",
        ),
        (
            json!({"targetInput":"caseId","input":{"caseId":"wrong"}}),
            "/input/caseId",
        ),
        (
            json!({"targetInput":"caseId","input":{"caseId":id,"newLabel":42}}),
            "/input/newLabel",
        ),
        (
            json!({"targetInput":"caseId","input":{"caseId":id,"secret":"value"}}),
            "/input",
        ),
        (
            json!({"targetInput":"caseId","input":{"caseId":id},"preconditions":{}}),
            "",
        ),
    ] {
        assert_eq!(
            parse_error_path(
                action,
                ActionRouteKind::Availability,
                &serde_json::to_vec(&body).unwrap()
            ),
            path
        );
    }
}

struct AvailabilityReadProbe {
    calls: std::sync::atomic::AtomicUsize,
    selected_fields: BTreeSet<String>,
    response: Result<Option<HeldReadResponse>, ReadServiceError>,
}
impl RecordReadService for AvailabilityReadProbe {
    fn get(
        &self,
        request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(request.context.selected_profile(), "registrar");
        assert_eq!(request.operation_id, "records.case.get");
        assert_eq!(request.representation, CursorRepresentation::Json);
        assert_eq!(request.selected_fields, self.selected_fields);
        let response = self.response.clone();
        Box::pin(async move { response })
    }
    fn list(
        &self,
        _: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
        panic!("availability must never list records")
    }
    fn lookup(
        &self,
        _: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        panic!("availability must use the authorized direct GET")
    }
}

#[tokio::test]
async fn availability_compares_a_current_date_guard_against_the_registry_local_date() {
    let id = "00000000-0000-4000-8000-000000000102";
    let source = PROJECT
        .replace("canonicalBaseIri: https://action-admission.example.test}", "canonicalBaseIri: https://action-admission.example.test, timezone: Asia/Colombo}")
        .replace("      - {id: region, type: string, maximumLength: 20, required: true, classification: internal}\n",
            "      - {id: region, type: string, maximumLength: 20, required: true, classification: internal}\n      - {id: opens-on, apiName: opensOn, type: date, required: true, classification: internal}\n")
        .replace("    plan:\n", "    commitGuards:\n      targets: [{input: case-ref, field: opens-on, currentDate: on-or-after}]\n    plan:\n");
    let mut project = parse_project_yaml(source.as_bytes()).unwrap();
    let permission = json!({"recordType":"case","operations":["get"],"readableFields":["label","region","opens-on"],"rowBoundaries":"unrestricted"});
    let mut profile = serde_json::to_value(&project.access_profiles[0]).unwrap();
    profile["permissions"]["records"] = json!([permission]);
    project.access_profiles[0] = serde_json::from_value(profile).unwrap();
    let registry = Arc::new(compile_project(&project, &[], CompileProfile::Authoring).unwrap());
    let late_evening_utc = time::macros::datetime!(2026-10-30 23:30 UTC);
    // Colombo is already on 31 October at 23:30 UTC.
    for (opens_on, expected) in [("2026-10-31", true), ("2026-10-30", false)] {
        let mut service = service_for(registry.clone(), true);
        service.records = Arc::new(AvailabilityReadProbe {
            calls: std::sync::atomic::AtomicUsize::new(0),
            selected_fields: BTreeSet::from(["opens-on".into(), "region".into()]),
            response: Ok(Some(
                HeldReadResponse::from_json(&json!({"data":{
                    "recordIdentifier":id,"revisionIdentifier":"7",
                    "domainData":{"label":"Ready","region":"north","opensOn":opens_on}
                }}))
                .unwrap(),
            )),
        });
        let claims = claims(
            "registry_principal",
            ["case.rename", "case.supervise"],
            Some("case-management"),
            true,
        );
        let route = registry
            .actions()
            .routes
            .iter()
            .find(|route| route.kind == ActionRouteKind::Availability)
            .unwrap();
        let options = QueryOptions::default();
        let surface = authorize_action(&service, route, &claims, &options).unwrap();
        let result = availability::observe(
            &service,
            &surface,
            &claims,
            &HeaderMap::new(),
            json!({"case-ref":id}).as_object().unwrap(),
            "case-ref",
            &RequestCorrelation::breg_created(),
            late_evening_utc,
        )
        .await
        .unwrap();
        assert_eq!(result.value()["available"], json!(expected), "{opens_on}");
    }
}

#[tokio::test]
async fn availability_never_probes_hidden_fields_or_borrows_another_profiles_reads() {
    let id = "00000000-0000-4000-8000-000000000101";
    // Keep wire field names different from logical IDs to exercise both mappings.
    let source = PROJECT.replace("{id: label, type:", "{id: label, apiName: displayLabel, type:")
        .replace("    plan:\n", "    commitGuards:\n      targets: [{input: case-ref, field: label, equals: Ready}]\n    plan:\n");
    for (reads, readable, expected, expected_reads) in [
        (true, vec!["label", "region"], Some(true), 1),
        (true, vec!["label"], None, 0),
        (true, vec!["region"], None, 0),
        (false, vec!["label", "region"], None, 0),
    ] {
        let mut project = parse_project_yaml(source.as_bytes()).unwrap();
        let permission = json!({"recordType":"case","operations":["get"],"readableFields":readable,"rowBoundaries":"unrestricted"});
        let owner = if reads { 0 } else { 1 };
        let mut profile = serde_json::to_value(&project.access_profiles[owner]).unwrap();
        profile["permissions"]["records"] = json!([permission]);
        project.access_profiles[owner] = serde_json::from_value(profile).unwrap();
        let registry = Arc::new(compile_project(&project, &[], CompileProfile::Authoring).unwrap());
        let mut service = service_for(registry.clone(), true);
        let probe = Arc::new(AvailabilityReadProbe {
            calls: std::sync::atomic::AtomicUsize::new(0),
            selected_fields: BTreeSet::from(["label".into(), "region".into()]),
            response: Ok(Some(
                HeldReadResponse::from_json(&json!({"data":{
                    "recordIdentifier":id,"revisionIdentifier":"7",
                    "domainData":{"displayLabel":"Ready","region":"north"}
                }}))
                .unwrap(),
            )),
        });
        service.records = probe.clone();
        let claims = claims(
            "registry_principal",
            ["case.rename", "case.supervise"],
            Some("case-management"),
            true,
        );
        let route = registry
            .actions()
            .routes
            .iter()
            .find(|route| route.kind == ActionRouteKind::Availability)
            .unwrap();
        let options = QueryOptions::default();
        let surface = authorize_action(&service, route, &claims, &options).unwrap();
        let result = availability::observe(
            &service,
            &surface,
            &claims,
            &HeaderMap::new(),
            json!({"case-ref":id}).as_object().unwrap(),
            "case-ref",
            &RequestCorrelation::breg_created(),
            time::OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
        assert_eq!(result.value()["available"], json!(expected));
        assert_eq!(
            result.value()["observedRevision"],
            if expected.is_some() {
                json!(7)
            } else {
                Value::Null
            }
        );
        assert_eq!(
            probe.calls.load(std::sync::atomic::Ordering::SeqCst),
            expected_reads
        );
    }
}
