// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroizing;

use super::context::{AuthorizedRequestContext, VerifiedClaimValue, VerifiedRequestClaims};
use super::service::{
    HeldReadResponse, ReadRuntimeIdentity, ReadServiceError, ReadinessProbe, RecordReadRefusal,
    RecordReadRequest, RecordReadService, ServiceFuture,
};
use super::{
    access_entry_for_route, parse_request_action_body, request_action_target_authority,
    RequestActionBody,
};
use crate::compiler::{compile_project, CompileProfile};
use crate::contract::{parse_project_json, Operation};
use crate::cursor::CursorCodec;
use crate::model::{CompiledRegistry, CompiledRoute};

#[test]
fn request_action_bodies_are_narrow_and_operation_bound() {
    let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    assert_eq!(
        parse_request_action_body(Operation::SubmitRequest, None, br#"{}"#),
        Ok(RequestActionBody::Submit)
    );
    assert_eq!(
        parse_request_action_body(
            Operation::ApproveRequest,
            Some("review"),
            format!(r#"{{"proposalVersion":1,"effectDigest":"{digest}"}}"#).as_bytes(),
        ),
        Ok(RequestActionBody::Approve {
            proposal_version: 1,
            effect_digest: digest.to_owned(),
        })
    );
    assert_eq!(
        parse_request_action_body(Operation::ReviseRequest, None, br#"{"rebase":true}"#),
        Ok(RequestActionBody::Revise { rebase: true })
    );

    assert!(
        parse_request_action_body(Operation::SubmitRequest, None, br#"{"state":"submitted"}"#)
            .is_err()
    );
    assert!(
        parse_request_action_body(Operation::CancelRequest, None, br#"{"actor":"forged"}"#)
            .is_err()
    );
    assert!(parse_request_action_body(
        Operation::ApproveRequest,
        Some("review"),
        br#"{"proposalVersion":1}"#
    )
    .is_err());
    assert!(parse_request_action_body(
        Operation::ApproveRequest,
        Some("review"),
        br#"{"proposalVersion":1,"effectDigest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789ABCDEF"}"#
    )
    .is_err());
    assert!(parse_request_action_body(
        Operation::ApproveRequest,
        None,
        format!(r#"{{"proposalVersion":1,"effectDigest":"{digest}"}}"#).as_bytes(),
    )
    .is_err());
}

#[test]
fn request_action_access_uses_exact_finite_route_id() {
    let registry = compiled_registry();
    let service = service_for(registry.clone());
    let route = route(
        &registry,
        "records.placement-correction-request.request.stages.review.approve",
    );
    assert!(access_entry_for_route(&service, route).is_some());

    let mut forged = route.clone();
    forged.id = "records.placement-correction-request.request.stages.hidden.approve".to_owned();
    forged.request_stage = Some("hidden".to_owned());
    assert!(access_entry_for_route(&service, &forged).is_none());
}

#[test]
fn request_action_preconditions_bind_operation_actor_profile_and_target_projection() {
    use crate::postgres::ClaimContext;
    use crate::request_workflow::{
        EntityId, RecordId, RequestKey, RequestWorkflow, StateRevision, TrustedActorRef,
    };
    let registry = compiled_registry();
    let entity_id = "placement-correction-request";
    let record_id = "00000000-0000-4000-8000-000000000001";
    let profile =
        registry_platform_audit::AuditProfile::production_from_secret_bytes(vec![0x92; 32].into())
            .unwrap();
    let reviewer = ClaimContext::for_compiled(
        &registry,
        entity_id,
        Some("reviewer".to_owned()),
        "request-reviewer",
        None,
        Vec::new(),
    )
    .unwrap();
    let other_actor = ClaimContext::for_compiled(
        &registry,
        entity_id,
        Some("other-reviewer".to_owned()),
        "request-reviewer",
        None,
        Vec::new(),
    )
    .unwrap();
    let applier = ClaimContext::for_compiled(
        &registry,
        entity_id,
        Some("reviewer".to_owned()),
        "request-applier",
        None,
        Vec::new(),
    )
    .unwrap();
    let workflow = RequestWorkflow::new_draft(
        RequestKey::new(
            EntityId::new(entity_id).unwrap(),
            RecordId::new(record_id).unwrap(),
        ),
        TrustedActorRef::from_verified_context("owner-reference").unwrap(),
        StateRevision::new(1).unwrap(),
    );
    let approve = route(
        &registry,
        "records.placement-correction-request.request.stages.review.approve",
    );
    let reject = route(
        &registry,
        "records.placement-correction-request.request.stages.review.reject",
    );
    let fields = BTreeSet::from(["placement".to_owned()]);
    let tag = |claims: &ClaimContext,
               route: &CompiledRoute,
               projection: &BTreeSet<String>,
               authority: &[super::RequestActionTargetAuthority]| {
        crate::mutation::request_action_etag(
            &profile,
            claims,
            "package-one",
            route,
            record_id,
            3,
            &workflow,
            projection,
            authority,
        )
        .unwrap()
    };
    let baseline = tag(&reviewer, approve, &fields, &[]);
    assert_eq!(baseline, tag(&reviewer, approve, &fields, &[]));
    assert_ne!(baseline, tag(&other_actor, approve, &fields, &[]));
    assert_ne!(baseline, tag(&applier, approve, &fields, &[]));
    assert_ne!(baseline, tag(&reviewer, reject, &fields, &[]));
    assert_ne!(baseline, tag(&reviewer, approve, &BTreeSet::new(), &[]));
    let authority = [super::RequestActionTargetAuthority {
        target_entity_id: "placement".to_owned(),
        readable_fields: BTreeSet::from(["site".to_owned()]),
        row_boundaries: Vec::new(),
    }];
    assert_ne!(baseline, tag(&reviewer, approve, &fields, &authority));
}

#[test]
fn request_action_target_authority_uses_verified_target_claims() {
    let registry = compiled_registry();
    let entity = registry
        .entities()
        .get("placement-correction-request")
        .expect("request entity compiles");
    let route = route(
        &registry,
        "records.placement-correction-request.request.stages.review.approve",
    );
    let context = AuthorizedRequestContext::new(
        Some("reviewer".to_owned()),
        None,
        "request-reviewer".to_owned(),
        Vec::new(),
    );
    let missing_claim = VerifiedRequestClaims::authenticated(
        "principal",
        "reviewer",
        BTreeSet::new(),
        None,
        BTreeMap::new(),
    )
    .expect("verified principal is valid");
    assert!(request_action_target_authority(entity, route, &context, &missing_claim).is_none());

    let claims = VerifiedRequestClaims::authenticated(
        "principal",
        "reviewer",
        BTreeSet::new(),
        None,
        BTreeMap::from([(
            "site_claim".to_owned(),
            VerifiedClaimValue::direct_string("site-1").expect("claim value is valid"),
        )]),
    )
    .expect("verified claims are valid");
    let authority = request_action_target_authority(entity, route, &context, &claims)
        .expect("target authority is selected");
    assert_eq!(authority.len(), 1);
    assert_eq!(authority[0].target_entity_id, "placement");
    assert_eq!(
        authority[0].readable_fields,
        BTreeSet::from(["site".to_owned()])
    );
    assert_eq!(authority[0].row_boundaries.len(), 1);
    assert_eq!(authority[0].row_boundaries[0].field(), "site");
}

fn compiled_registry() -> Arc<CompiledRegistry> {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"change-request-http","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"create_only",
            "fields":[{"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"}]
          },{
            "id":"placement","primaryDataset":"test-dataset","route":"placements","mutationMode":"mutable",
            "changeControl":{"requiredFor":["patch"]},
            "fields":[
              {"id":"site","type":"reference","target":"site","required":true,"classification":"internal"},
              {"id":"label","type":"string","maxLength":64,"classification":"internal"}
            ]
          },{
            "id":"placement-correction-request","primaryDataset":"test-dataset","route":"placement-correction-requests","mutationMode":"mutable",
            "fields":[
              {"id":"placement","type":"reference","target":"placement","required":true,"classification":"internal"},
              {"id":"proposed-site","type":"reference","target":"site","required":true,"classification":"internal"}
            ],
            "changeRequest":{
              "effects":[{
                "target":{"fromField":"placement"},
                "operation":"patch",
                "set":{"site":{"fromField":"proposed-site"}}
              }],
              "review":{"stages":[{"id":"review","approvals":1,"excludeSubmitter":true}]}
            }
          }],
          "accessProfiles":[{
            "id":"request-reviewer","default":true,"principalClaim":"principal","grants":[{
              "entity":"placement-correction-request",
              "operations":["get","submit_request","approve_request","reject_request","request_revision"],
              "readableFields":["placement","proposed-site"],
              "reviewStages":[{
                "stage":"review",
                "targets":[{
                  "entity":"placement",
                  "readableFields":["site"],
                  "rowBoundaries":[{"field":"site","claim":"site_claim","operator":"equals"}]
                }]
              }]
            }]
          },{
            "id":"request-applier","principalClaim":"principal","grants":[{
              "entity":"placement-correction-request",
              "operations":["get","apply_request"],
              "readableFields":["placement"],
              "applyTargets":[{"entity":"placement"}]
            }]
          }]
        }"#,
    )
    .expect("fixture parses");
    Arc::new(compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles"))
}

fn route<'a>(registry: &'a CompiledRegistry, route_id: &str) -> &'a CompiledRoute {
    registry
        .routes()
        .routes
        .iter()
        .find(|route| route.id == route_id)
        .expect("compiled route exists")
}

fn service_for(registry: Arc<CompiledRegistry>) -> super::HttpService {
    super::HttpService::new(
        registry,
        ReadRuntimeIdentity {
            package_revision: "package-revision".to_owned(),
            schema_fingerprint: "schema-fingerprint".to_owned(),
        },
        Arc::new(NoopRecords),
        Arc::new(Ready),
        Arc::new(CursorCodec::new(Zeroizing::new(vec![7; 32]), Duration::from_secs(60)).unwrap()),
    )
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
        _request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        Box::pin(async { Ok(None) })
    }

    fn list(
        &self,
        _request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
        Box::pin(async { Err(ReadServiceError::Unavailable) })
    }

    fn lookup(
        &self,
        _request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        Box::pin(async { Ok(None) })
    }

    fn refusal(
        &self,
        _request: RecordReadRefusal,
    ) -> ServiceFuture<'_, Result<(), ReadServiceError>> {
        Box::pin(async { Ok(()) })
    }
}
