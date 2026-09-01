// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroizing;

use super::service::{
    HeldReadResponse, ReadRuntimeIdentity, ReadServiceError, ReadinessProbe, RecordReadRefusal,
    RecordReadRequest, RecordReadService, ServiceFuture,
};
use super::{authorize_route, metadata_change_control, QueryOptions};
use crate::compiler::{compile_project, CompileProfile};
use crate::contract::{parse_project_json, Operation};
use crate::cursor::CursorCodec;
use crate::model::{CompiledRegistry, CompiledRoute};

#[test]
fn request_history_continuation_refuses_unbound_or_noncanonical_values() {
    for query in [
        "requestHistoryAfterProposalVersion=0",
        "requestHistoryAfterProposalVersion=-1",
        "requestHistoryAfterProposalVersion=01",
        "requestHistoryAfterProposalVersion=4294967296",
        "requestHistoryAfterProposalVersion=1&requestHistoryAfterProposalVersion=2",
        "requestHistoryAfterProposalVersion=1&$skiptoken=opaque",
    ] {
        assert!(QueryOptions::parse(Some(query), true).is_err());
    }
    let query = "requestHistoryAfterProposalVersion=1";
    let options = QueryOptions::parse(Some(query), true).expect("positive version parses");
    assert_eq!(options.request_history_after_proposal_version, Some(1));
    assert!(options.has_non_projection_query_members());
    assert!(!options.has_non_history_query_members());
    assert!(QueryOptions::parse(Some(query), false).is_err());
}

#[test]
fn request_get_omits_optional_review_action_when_target_claim_is_absent() {
    let registry = compiled_registry();
    let service = service_for(registry.clone());
    let route = route(&registry, "records.placement-correction-request.get");
    let missing_claims = super::VerifiedRequestClaims::authenticated(
        "principal",
        "reviewer",
        BTreeSet::new(),
        None,
        BTreeMap::new(),
    )
    .expect("verified claims are valid");

    let surface = authorize_route(&service, route, &missing_claims, &QueryOptions::default())
        .expect("request GET itself is authorized");
    assert!(
        surface.context.request_actions().is_empty(),
        "missing optional target authority omits action discovery instead of failing request GET"
    );

    let claims = super::VerifiedRequestClaims::authenticated(
        "principal",
        "reviewer",
        BTreeSet::new(),
        None,
        BTreeMap::from([(
            "site_claim".to_owned(),
            super::VerifiedClaimValue::direct_string("00000000-0000-4000-8000-000000000010")
                .expect("claim value is valid"),
        )]),
    )
    .expect("verified claims are valid");
    let surface = authorize_route(&service, route, &claims, &QueryOptions::default())
        .expect("request GET is authorized with target claims");
    assert_eq!(surface.context.request_actions().len(), 3);
    let approve = surface
        .context
        .request_actions()
        .iter()
        .find(|action| action.operation() == Operation::ApproveRequest)
        .expect("approve action is discoverable");
    assert_eq!(
        approve.route_id(),
        "records.placement-correction-request.request.stages.review.approve"
    );
    assert_eq!(approve.review_stage(), Some("review"));
    assert_eq!(approve.target_authority().len(), 1);
    assert_eq!(
        approve.target_authority()[0].target_entity_id(),
        "placement"
    );
    assert_eq!(
        approve.target_authority()[0].readable_fields(),
        &BTreeSet::from(["site".to_owned()])
    );
}

#[test]
fn target_presence_uses_presence_grant_without_request_get_authority() {
    let registry = compiled_registry();
    let service = service_for(registry.clone());
    let route = route(&registry, "records.placement.get");
    let missing_claims = super::VerifiedRequestClaims::authenticated(
        "principal",
        "viewer",
        BTreeSet::new(),
        None,
        BTreeMap::new(),
    )
    .expect("verified claims are valid");
    let surface = authorize_route(&service, route, &missing_claims, &QueryOptions::default())
        .expect("target GET is authorized");
    assert!(
        surface.context.request_presence().is_empty(),
        "missing request row-boundary claim omits the optional pending indicator"
    );

    let claims = super::VerifiedRequestClaims::authenticated(
        "principal",
        "viewer",
        BTreeSet::new(),
        None,
        BTreeMap::from([(
            "placement_claim".to_owned(),
            super::VerifiedClaimValue::direct_string("00000000-0000-4000-8000-000000000020")
                .expect("claim value is valid"),
        )]),
    )
    .expect("verified claims are valid");
    let surface = authorize_route(&service, route, &claims, &QueryOptions::default())
        .expect("target GET is authorized with presence claims");
    assert_eq!(surface.context.request_presence().len(), 1);
    assert_eq!(
        surface.context.request_presence()[0].request_entity_id(),
        "placement-correction-request"
    );
}

#[test]
fn metadata_advertises_controlled_operations_separately_from_crud() {
    let registry = compiled_registry();
    let service = service_for(registry.clone());
    let placement = registry.entities().get("placement").expect("entity exists");
    let metadata = metadata_change_control(
        &service,
        placement,
        &BTreeSet::from(["placement-correction-request".to_owned()]),
    );
    assert_eq!(
        metadata["controlledOperations"],
        serde_json::json!(["patch"])
    );
    assert_eq!(
        metadata["eligibleRequestTypes"][0]["id"],
        "placement-correction-request"
    );
    let hidden = metadata_change_control(&service, placement, &BTreeSet::new());
    assert_eq!(hidden["eligibleRequestTypes"], serde_json::json!([]));
}

#[test]
fn served_schemas_do_not_disclose_hidden_request_types_or_full_authoring_grants() {
    let registry = compiled_registry();
    let service = service_for(registry.clone());
    let target = super::filtered_schema(
        &service,
        "placement",
        &BTreeSet::from(["site".to_owned()]),
        &BTreeSet::new(),
    )
    .unwrap();
    assert_eq!(
        target["x-registry-changeControl"]["eligibleRequestTypes"],
        serde_json::json!([])
    );
    assert!(!target.to_string().contains("placement-correction-request"));
    let request = super::filtered_schema(
        &service,
        "placement-correction-request",
        &BTreeSet::from(["placement".to_owned()]),
        &BTreeSet::from(["placement-correction-request".to_owned()]),
    )
    .unwrap();
    let capability = request["x-registry-changeRequest"].as_object().unwrap();
    assert!(capability.contains_key("stateEnvelope"));
    assert!(!capability.contains_key("effects"));
    assert!(!request.to_string().contains("site_claim"));
    assert!(!request.to_string().contains("proposedSite"));
}

fn compiled_registry() -> Arc<CompiledRegistry> {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"change-request-read","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
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
              {"id":"proposed-site","apiName":"proposedSite","type":"reference","target":"site","required":true,"classification":"internal"}
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
              "operations":["get","approve_request","reject_request","request_revision"],
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
            "id":"request-submitter","principalClaim":"principal","grants":[{
              "entity":"placement-correction-request",
              "operations":["get","create","patch","submit_request"],
              "readableFields":["placement","proposed-site"],
              "writableFields":["placement","proposed-site"]
            }]
          },{
            "id":"request-applier","principalClaim":"principal","grants":[{
              "entity":"placement-correction-request",
              "operations":["get","apply_request"],
              "readableFields":["placement"],
              "applyTargets":[{"entity":"placement"}]
            }]
          },{
            "id":"placement-viewer","principalClaim":"principal","grants":[{
              "entity":"placement",
              "operations":["get"],
              "readableFields":["site"],
              "requestPresence":[{
                "requestType":"placement-correction-request",
                "rowBoundaries":[{"field":"placement","claim":"placement_claim","operator":"equals"}]
              }]
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
