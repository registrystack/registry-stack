// SPDX-License-Identifier: Apache-2.0
#![recursion_limit = "256"]

use std::sync::Arc;

use registry_breg_client::{BaseRegistryClient, BaseRegistryClientConfig, StaticToken};
use registry_casework_breg::{BregAdapter, BregReviewStage, BregSourceConfig};
use registry_casework_core::*;
use serde_json::{json, Value};
use wiremock::{
    matchers::{body_json, header, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

const ID: &str = "00000000-0000-4000-8000-000000000001";
const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ACTION_ETAG: &str =
    "\"breg-action-hmac-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"";

fn adapter(base: &str) -> BregAdapter {
    BregAdapter::new(
        BregSourceConfig {
            source_id: "source".into(),
            entity: "company".into(),
            route: "companies".into(),
            stages: vec![BregReviewStage {
                id: "review".into(),
                approvals: 1,
                exclude_submitter: false,
                exclude_previous_reviewers: false,
            }],
            routing_metadata: RoutingSourceMetadata {
                stages: vec!["review".into()],
                fields: vec![],
            },
            expected_registry_revision: REVISION.into(),
            binding_generation: "generation-1".into(),
            reader_profile: "reader".into(),
            event_source: "urn:registrystack:registry:test:instance:test".into(),
            event_type: "casework-lifecycle-v1".into(),
        },
        BaseRegistryClient::new(
            BaseRegistryClientConfig::new(base.parse().unwrap())
                .with_token_provider(Arc::new(StaticToken::new("reader-service-token").unwrap())),
        )
        .unwrap(),
        vec![42; 32],
    )
    .unwrap()
}

fn subject() -> SubjectRef {
    SubjectRef {
        source_id: "source".into(),
        kind: "company".into(),
        id: ID.into(),
    }
}

fn actor(subject: &str) -> ActorContext {
    ActorContext {
        principal: IssuerPrincipal {
            issuer: "https://idp.example".into(),
            subject: subject.into(),
        },
        profile_id: "staff".into(),
        role: CaseworkRole::Staff,
    }
}

fn metadata() -> Value {
    json!({
        "id": "business-registry",
        "version": "1.2.3",
        "revision": REVISION,
        "metadataVersion": "1",
        "entities": [{
            "id": "company", "datasetIdentifier": "legal-entities", "route": "companies",
            "operations": [{"operation": "apply_request", "accessProfile": "reviewer"}],
            "readableFields": ["legal-name"], "schema": "/v1/schemas/company"
        }],
        "operations": [{
            "id": "records.company.request.apply", "method": "POST",
            "path": "/v1/records/companies/{record_id}/actions/apply",
            "operation": "apply_request", "sourceEntity": "company", "responseEntity": "company",
            "accessProfile": "reviewer", "requiredCapabilities": ["change_request_lifecycle"],
            "entityLabel": "Companies", "identifier": {"apiName": "id", "location": "envelope"},
            "titleFields": ["legal-name"],
            "fields": [{"id":"legal-name","apiName":"legalName","label":"Legal name","schema":{"type":"string"},"required":true,"nullable":true,"readOnly":false,"removable":true}],
            "readableFields": ["legal-name"], "createWritableFields": [], "patchWritableFields": [],
            "selectors": [], "query": null,
            "request": {
                "fieldNames": "api", "queryParameters": [], "body": "change_request_action",
                "contentType": "application/json", "ifMatchRequired": true,
                "idempotencyKeyRequired": true, "mutationSemantics": "change_request_lifecycle",
                "schema": {"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["proposalVersion","effectDigest"],"properties":{"proposalVersion":{"type":"integer","format":"int64","minimum":1,"maximum":4294967295_u64},"effectDigest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","description":"Digest of the immutable proposal effects displayed to the actor."}}}
            }
        }]
    })
}

fn record() -> Value {
    json!({
        "data": {
            "recordIdentifier": ID, "revisionIdentifier": "7",
            "domainData": {"secretProposalBody": "PROPOSAL-BODY-CANARY"},
            "request": {
                "bregState": "approved", "proposalVersion": 7, "effectDigest": DIGEST,
                "editable": false,
                "actions": [{
                    "operation": "apply_request", "method": "POST",
                    "href": format!("/v1/records/companies/{ID}/actions/apply?accessProfile=reviewer"),
                    "ifMatch": ACTION_ETAG, "proposalVersion": 7, "effectDigest": DIGEST
                }]
            }
        },
        "meta": {"registryIdentifier":"business-registry","datasetIdentifier":"legal-entities","entityTypeIdentifier":"company"}
    })
}

fn json_response(value: Value) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_json(value)
        .insert_header(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )
}

async fn prepare_for_recovery(
    server: &MockServer,
) -> (BregAdapter, ActorContext, PreparedSourceAttempt) {
    Mock::given(method("GET"))
        .and(path(format!("/v1/records/companies/{ID}")))
        .and(header("authorization", "Bearer first-human-token"))
        .respond_with(
            json_response(record())
                .insert_header("etag", "\"breg-record-7\"")
                .insert_header("cache-control", "no-store")
                .insert_header("link", "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/company>; rel=\"describedby\""),
        )
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/registry"))
        .and(header("authorization", "Bearer first-human-token"))
        .respond_with(json_response(metadata()))
        .expect(1)
        .mount(server)
        .await;
    let source = adapter(&server.uri());
    let actor = actor("alice");
    let displayed = SourceBinding {
        source_revision: "7".into(),
        version: "7".into(),
        integrity: Some(DIGEST.into()),
        generation: "generation-1".into(),
    };
    let prepared = source
        .prepare_action(PrepareActionRequest {
            subject: &subject(),
            displayed_binding: &displayed,
            operation: OperationName::parse("apply").expect("apply operation"),
            reason: None,
            actor: &actor,
            source_profile_id: "reviewer",
            idempotency_key: "casework-attempt-1",
            credential: EphemeralCredential::new("first-human-token"),
        })
        .await
        .unwrap();
    (source, actor, prepared)
}

async fn mount_recovery_metadata(server: &MockServer, response: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path("/v1/registry"))
        .and(header("authorization", "Bearer refreshed-human-token"))
        .respond_with(response)
        .expect(1)
        .mount(server)
        .await;
}

async fn execute_recovery(
    source: &BregAdapter,
    actor: &ActorContext,
    prepared: &PreparedSourceAttempt,
) -> Result<SourceReceipt, SourceAdapterError> {
    source
        .execute_prepared(ExecutePreparedRequest {
            prepared,
            execution: PreparedExecution::Recovery,
            actor,
            source_profile_id: "reviewer",
            idempotency_key: "casework-attempt-1",
            credential: EphemeralCredential::new("refreshed-human-token"),
        })
        .await
}

#[tokio::test]
async fn current_authentication_refusal_during_recovery_does_not_prove_the_original_outcome() {
    let server = MockServer::start().await;
    let (source, actor, prepared) = prepare_for_recovery(&server).await;
    mount_recovery_metadata(&server, json_response(metadata())).await;
    Mock::given(method("POST"))
        .and(path(format!("/v1/records/companies/{ID}/actions/apply")))
        .respond_with(ResponseTemplate::new(401)
            .set_body_raw(serde_json::to_vec(&json!({"type":"https://id.registrystack.org/problems/registry-breg/authentication/refused","title":"Unauthorized","status":401,"detail":"The bearer credential is missing or refused.","code":"authentication.refused","traceId":"4bf92f3577b34da6a3ce929d0e0e4736"})).unwrap(), "application/problem+json")
            .insert_header("cache-control", "no-store")
            .insert_header("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"))
        .expect(1).mount(&server).await;
    assert_eq!(
        execute_recovery(&source, &actor, &prepared).await,
        Err(SourceAdapterError::Uncertain)
    );
}

#[tokio::test]
async fn canonical_problem_from_the_initial_post_is_a_definitive_refusal() {
    let server = MockServer::start().await;
    let (source, actor, prepared) = prepare_for_recovery(&server).await;
    mount_recovery_metadata(&server, json_response(metadata())).await;
    Mock::given(method("POST"))
        .and(path(format!("/v1/records/companies/{ID}/actions/apply")))
        .respond_with(ResponseTemplate::new(400)
            .set_body_raw(serde_json::to_vec(&json!({"type":"https://id.registrystack.org/problems/registry-breg/request/invalid","title":"Bad Request","status":400,"detail":"The request is invalid.","code":"request.invalid","traceId":"4bf92f3577b34da6a3ce929d0e0e4736"})).unwrap(), "application/problem+json")
            .insert_header("cache-control", "no-store")
            .insert_header("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"))
        .expect(1).mount(&server).await;
    assert_eq!(
        source
            .execute_prepared(ExecutePreparedRequest {
                prepared: &prepared,
                execution: PreparedExecution::Initial,
                actor: &actor,
                source_profile_id: "reviewer",
                idempotency_key: "casework-attempt-1",
                credential: EphemeralCredential::new("refreshed-human-token"),
            })
            .await,
        Err(SourceAdapterError::DefinitiveRefusal)
    );
}

#[tokio::test]
async fn malformed_four_xx_from_actual_post_remains_uncertain() {
    let server = MockServer::start().await;
    let (source, actor, prepared) = prepare_for_recovery(&server).await;
    mount_recovery_metadata(&server, json_response(metadata())).await;
    Mock::given(method("POST"))
        .and(path(format!("/v1/records/companies/{ID}/actions/apply")))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({"malformed":true})))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        execute_recovery(&source, &actor, &prepared).await,
        Err(SourceAdapterError::Uncertain)
    );
}

#[tokio::test]
async fn metadata_refusal_cannot_masquerade_as_a_definitive_post_refusal() {
    let server = MockServer::start().await;
    let (source, actor, prepared) = prepare_for_recovery(&server).await;
    mount_recovery_metadata(&server, ResponseTemplate::new(403)).await;
    let error = execute_recovery(&source, &actor, &prepared)
        .await
        .unwrap_err();
    assert_ne!(error, SourceAdapterError::DefinitiveRefusal);
    assert_eq!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method.as_str() == "POST")
            .count(),
        0
    );
}

#[tokio::test]
async fn prepared_apply_recovers_under_the_same_actor_with_a_refreshed_human_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/records/companies/{ID}")))
        .and(query_param("accessProfile", "reviewer"))
        .and(header("authorization", "Bearer first-human-token"))
        .respond_with(
            json_response(record())
                .insert_header("etag", "\"breg-record-7\"")
                .insert_header("cache-control", "no-store")
                .insert_header("link", "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/company>; rel=\"describedby\""),
        )
        .expect(1)
        .mount(&server)
        .await;
    for token in ["first-human-token", "refreshed-human-token"] {
        Mock::given(method("GET"))
            .and(path("/v1/registry"))
            .and(query_param("accessProfile", "reviewer"))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(json_response(metadata()))
            .expect(1)
            .mount(&server)
            .await;
    }
    let receipt = json!({
        "id": ID, "revision": 8, "snapshot": format!("breg1_{ID}"),
        "actorReference":"opaque-breg-actor-7d3a",
        "request": {"bregState":"applied","proposalVersion":7,"effectDigest":DIGEST,
            "application":{"applicationId":"00000000-0000-4000-8000-000000000002","proposalVersion":7,"effectDigest":DIGEST,"appliedAt":"2026-09-10T01:00:00Z"}}
    });
    Mock::given(method("POST"))
        .and(path(format!("/v1/records/companies/{ID}/actions/apply")))
        .and(query_param("accessProfile", "reviewer"))
        .and(header("authorization", "Bearer refreshed-human-token"))
        .and(header("if-match", ACTION_ETAG))
        .and(header("idempotency-key", "casework-attempt-1"))
        .and(body_json(
            json!({"proposalVersion":7,"effectDigest":DIGEST}),
        ))
        .respond_with(
            json_response(receipt)
                .insert_header("cache-control", "no-store")
                .insert_header("vary", "authorization, accept"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let source = adapter(&server.uri());
    let displayed = SourceBinding {
        source_revision: "7".into(),
        version: "7".into(),
        integrity: Some(DIGEST.into()),
        generation: "generation-1".into(),
    };
    let original_actor = actor("alice");
    let prepared = source
        .prepare_action(PrepareActionRequest {
            subject: &subject(),
            displayed_binding: &displayed,
            operation: OperationName::parse("apply").expect("apply operation"),
            reason: None,
            actor: &original_actor,
            source_profile_id: "reviewer",
            idempotency_key: "casework-attempt-1",
            credential: EphemeralCredential::new("first-human-token"),
        })
        .await
        .unwrap();
    let evidence = String::from_utf8(prepared.recovery_evidence.as_bytes().to_vec()).unwrap();
    for forbidden in ["PROPOSAL-BODY-CANARY", "first-human-token"] {
        assert!(!evidence.contains(forbidden));
    }
    let result = source
        .execute_prepared(ExecutePreparedRequest {
            prepared: &prepared,
            execution: PreparedExecution::Recovery,
            actor: &original_actor,
            source_profile_id: "reviewer",
            idempotency_key: "casework-attempt-1",
            credential: EphemeralCredential::new("refreshed-human-token"),
        })
        .await
        .unwrap();
    assert_eq!(result.source_revision, "8");
    assert_eq!(result.resulting_state, "applied");
    assert_eq!(
        result.actor_reference.as_deref(),
        Some("opaque-breg-actor-7d3a")
    );
    assert!(result.metadata["nativeReceipt"].contains("applicationId"));
    assert!(!result.metadata["nativeReceipt"].contains("PROPOSAL"));
}

#[tokio::test]
async fn initial_execution_preserves_only_the_opaque_source_actor_reference() {
    let server = MockServer::start().await;
    let (source, actor, prepared) = prepare_for_recovery(&server).await;
    mount_recovery_metadata(&server, json_response(metadata())).await;
    Mock::given(method("POST"))
        .and(path(format!("/v1/records/companies/{ID}/actions/apply")))
        .respond_with(
            json_response(json!({
                "id":ID, "revision":8, "snapshot":format!("breg1_{ID}"),
                "actorReference":"opaque-breg-actor-7d3a",
                "request":{"bregState":"applied","proposalVersion":7,"effectDigest":DIGEST,
                    "application":{"applicationId":"00000000-0000-4000-8000-000000000002",
                        "proposalVersion":7,"effectDigest":DIGEST,"appliedAt":"2026-09-10T01:00:00Z"}}
            }))
            .insert_header("cache-control", "no-store")
            .insert_header("vary", "authorization, accept"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let receipt = source
        .execute_prepared(ExecutePreparedRequest {
            prepared: &prepared,
            execution: PreparedExecution::Initial,
            actor: &actor,
            source_profile_id: "reviewer",
            idempotency_key: "casework-attempt-1",
            credential: EphemeralCredential::new("refreshed-human-token"),
        })
        .await
        .unwrap();
    assert_eq!(
        receipt.actor_reference.as_deref(),
        Some("opaque-breg-actor-7d3a")
    );
    let serialized = serde_json::to_string(&receipt).unwrap();
    assert!(serialized.contains("opaque-breg-actor-7d3a"));
    assert!(!serialized.contains("alice"));
    assert!(!serialized.contains("https://idp.example"));
}

#[tokio::test]
async fn recovery_refuses_a_different_actor_before_source_io() {
    let server = MockServer::start().await;
    let source = adapter(&server.uri());
    let prepared = PreparedSourceAttempt {
        source_binding: SourceBinding {
            source_revision: "7".into(), version: "7".into(), integrity: Some(DIGEST.into()), generation: "generation-1".into(),
        },
        recovery_evidence: RecoveryEvidence::new(serde_json::to_vec(&json!({
            "subject":subject(), "actor":actor("alice").principal, "casework_profile":"staff",
            "source_profile":"reviewer", "binding":{"sourceRevision":"7","version":"7","integrity":DIGEST,"generation":"generation-1"}, "native":[]
        })).unwrap()).unwrap(),
    };
    let error = source
        .execute_prepared(ExecutePreparedRequest {
            prepared: &prepared,
            execution: PreparedExecution::Recovery,
            actor: &actor("mallory"),
            source_profile_id: "reviewer",
            idempotency_key: "casework-attempt-1",
            credential: EphemeralCredential::new("mallory-token"),
        })
        .await
        .unwrap_err();
    assert_eq!(error, SourceAdapterError::Denied);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn source_outage_during_recovery_preserves_an_uncertain_outcome() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/registry"))
        .and(query_param("accessProfile", "reviewer"))
        .and(header("authorization", "Bearer refreshed-human-token"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;
    let source = adapter(&server.uri());
    let original_actor = actor("alice");
    let prepared = PreparedSourceAttempt {
        source_binding: SourceBinding {
            source_revision: "7".into(),
            version: "7".into(),
            integrity: Some(DIGEST.into()),
            generation: "generation-1".into(),
        },
        recovery_evidence: RecoveryEvidence::new(
            serde_json::to_vec(&json!({
                "subject":subject(), "actor":original_actor.principal,
                "casework_profile":"staff", "source_profile":"reviewer",
                "binding":{"sourceRevision":"7","version":"7","integrity":DIGEST,"generation":"generation-1"},
                "native":[]
            }))
            .unwrap(),
        )
        .unwrap(),
    };
    let error = source
        .execute_prepared(ExecutePreparedRequest {
            prepared: &prepared,
            execution: PreparedExecution::Recovery,
            actor: &original_actor,
            source_profile_id: "reviewer",
            idempotency_key: "casework-attempt-1",
            credential: EphemeralCredential::new("refreshed-human-token"),
        })
        .await
        .unwrap_err();
    assert_eq!(error, SourceAdapterError::Uncertain);
}

#[tokio::test]
async fn live_registry_revision_drift_is_refused_during_authoritative_read() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/records/companies/{ID}")))
        .respond_with(
            json_response(record())
                .insert_header("etag", "\"breg-record-7\"")
                .insert_header("cache-control", "no-store")
                .insert_header("link", "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/company>; rel=\"describedby\""),
        )
        .expect(1)
        .mount(&server)
        .await;
    let mut changed = metadata();
    changed["revision"] =
        json!("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    Mock::given(method("GET"))
        .and(path("/v1/registry"))
        .respond_with(json_response(changed))
        .expect(1)
        .mount(&server)
        .await;
    let source = adapter(&server.uri());
    assert_eq!(
        source.read_authoritative(&subject()).await,
        Err(SourceAdapterError::BindingMoved)
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}
