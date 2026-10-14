// SPDX-License-Identifier: Apache-2.0
use registry_breg_client::{BaseRegistryClient, BaseRegistryClientConfig, StaticToken};
use registry_casework_breg::*;
use registry_casework_core::*;
use registry_platform_config::sha256_uri;
use serde_json::{json, Value};
use std::sync::Arc;
use wiremock::{
    matchers::{header, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};
const ID: &str = "00000000-0000-4000-8000-000000000001";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn export() -> BregContextExport {
    let mut schema = json!({"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:context","x-registry-review-context":{"actionId":"correct-address","contextId":"address"},"type":"object","additionalProperties":false,"required":["reference"],"properties":{"reference":{"type":"string","maxLength":128}}});
    let revision =
        sha256_uri(&registry_platform_canonical_json::canonicalize_json(&schema).unwrap());
    schema["x-registry-definition-revision"] = json!(revision);
    let schema_bytes = serde_json::to_string(&schema).unwrap();
    BregContextExport {
        api_version: DESCRIPTION_API_VERSION.into(),
        kind: DESCRIPTION_KIND.into(),
        source_namespace: "source".into(),
        registry_revision: DIGEST.into(),
        action_id: "correct-address".into(),
        context_id: "address".into(),
        contract: ReviewContextContract {
            id: "urn:context".into(),
            revision: ContentDigest::parse(&revision).unwrap(),
            schema_digest: ContentDigest::parse(&sha256_uri(schema_bytes.as_bytes())).unwrap(),
        },
        schema,
        schema_bytes,
    }
}
fn identity(export: &BregContextExport) -> ReviewContextIdentity {
    ReviewContextIdentity {
        subject: SubjectBinding {
            source: "source".into(),
            subject_type: "proposal".into(),
            id: ID.into(),
            version: "1".into(),
            digest: ContentDigest::parse(DIGEST).unwrap(),
        },
        contract: export.contract.clone(),
    }
}
fn response(value: Value) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )
        .insert_header("cache-control", "no-store")
        .insert_header("vary", "authorization, accept")
        .set_body_json(value)
}
async fn mocks(server: &MockServer, profile: &str, bearer: &str, display: bool, revision: &str) {
    let suffix = if display {
        "review-context"
    } else {
        "review-status"
    };
    let operation = if display {
        "get-review-context"
    } else {
        "get-review-status"
    };
    Mock::given(method("GET")).and(path("/v1/registry")).and(query_param("accessProfile",profile)).and(header("authorization",format!("Bearer {bearer}"))).respond_with(response(json!({"metadataVersion":"1","id":"registry","version":"1","revision":revision,"recordTypes":[],"operations":[],"proposals":{"method":"GET","path":"/v1/proposals","accessProfiles":[],"get":{"method":"GET","path":"/v1/proposals/{proposal_id}","accessProfiles":[]},"actions":[{"actionId":"correct-address","accessProfile":profile,"operations":[operation]}]}}))).mount(server).await;
    let mut context = json!({"reference":"native-proposal"});
    if display {
        context["id"] = json!("address");
        context["fields"] = json!({"reference":"REF-42"});
    }
    Mock::given(method("GET")).and(path(format!("/v1/proposals/{ID}/{suffix}"))).and(header("authorization",format!("Bearer {bearer}"))).respond_with(response(json!({"id":ID,"actionId":"correct-address","actionRevision":DIGEST,"submissionVersion":1,"revision":1,"effectDigest":DIGEST,"subject":{"source":"source","subjectType":"proposal","id":ID,"version":"1","digest":DIGEST},"context":context,"reviewable":true}))).mount(server).await;
}
fn provider(server: &MockServer, export: BregContextExport) -> BregContextProvider {
    let client = BaseRegistryClient::new(
        BaseRegistryClientConfig::new(server.uri().parse().unwrap())
            .with_token_provider(Arc::new(StaticToken::new("status-bearer").unwrap())),
    )
    .unwrap();
    BregContextProvider::new("provider".into(), export, client, "status".into()).unwrap()
}
#[tokio::test]
async fn human_display_uses_exact_caller_bearer_and_status_discloses_no_values() {
    let server = MockServer::start().await;
    let export = export();
    let identity = identity(&export);
    let provider = provider(&server, export);
    mocks(&server, "reviewer", "human-bearer", true, DIGEST).await;
    mocks(&server, "status", "status-bearer", false, DIGEST).await;
    let display = provider
        .human_display(HumanDisplayRequest {
            identity: &identity,
            source_profile_id: "reviewer",
            credential: EphemeralCredential::new("human-bearer"),
        })
        .await
        .unwrap();
    assert_eq!(
        display.display_reference.as_deref(),
        Some("native-proposal")
    );
    assert_eq!(display.identity, identity);
    let status = provider.service_status(&identity).await.unwrap();
    assert_eq!(status.identity, identity);
    assert!(status.reviewable);
    let requests = server.received_requests().await.unwrap();
    assert!(requests.iter().all(|r| r.method == "GET"));
    assert!(requests
        .iter()
        .all(|r| r.url.path() != format!("/v1/proposals/{ID}")));
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.url.path().starts_with("/v1/proposals/"))
            .count(),
        2
    );
}
#[tokio::test]
async fn changed_native_registry_contract_refuses_before_reading_business_values() {
    let server = MockServer::start().await;
    let export = export();
    let identity = identity(&export);
    let provider = provider(&server, export);
    mocks(
        &server,
        "reviewer",
        "human-bearer",
        true,
        &format!("sha256:{}", "b".repeat(64)),
    )
    .await;
    assert_eq!(
        provider
            .human_display(HumanDisplayRequest {
                identity: &identity,
                source_profile_id: "reviewer",
                credential: EphemeralCredential::new("human-bearer")
            })
            .await
            .unwrap_err(),
        ReviewContextError::ContractChanged
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
#[tokio::test]
async fn native_provider_does_not_advertise_unminimized_service_fields() {
    let server = MockServer::start().await;
    let export = export();
    let identity = identity(&export);
    let provider = provider(&server, export);
    assert_eq!(
        provider.capabilities(),
        &[
            ReviewContextCapability::HumanDisplay,
            ReviewContextCapability::ServiceStatus
        ]
    );
    let request = ServiceContextRequest {
        identity,
        request_id: uuid::Uuid::new_v4(),
        task_id: uuid::Uuid::new_v4(),
        task_revision: 1,
        policy: PolicyBinding {
            id: "policy".into(),
            version: "1".into(),
            digest: ContentDigest::parse(DIGEST).unwrap(),
        },
        purpose: "routing".into(),
        fields: vec!["region".into()],
    };
    assert_eq!(
        provider.routing_context(&request).await.unwrap_err(),
        ReviewContextError::Unsupported
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}
#[test]
fn changed_export_schema_bytes_cannot_reuse_the_contract_pin() {
    let mut export = export();
    export.schema_bytes.push(' ');
    assert_eq!(export.check(), Err(ReviewContextError::Invalid));
}
#[test]
fn canonical_vendored_schema_matches_the_native_producer_contract() {
    let schema_bytes = include_str!(
        "../../../products/casework/examples/canonical-review/schemas/correct-address.schema.json"
    );
    let index: Value = serde_json::from_str(include_str!(
        "../../../products/breg/generated/refactor/generated/review-context-schemas/index.json"
    ))
    .unwrap();
    let contract = &index["correct-address"];
    let schema: Value = serde_json::from_str(schema_bytes).unwrap();
    let export = BregContextExport {
        api_version: DESCRIPTION_API_VERSION.into(),
        kind: DESCRIPTION_KIND.into(),
        source_namespace: "facility-registry".into(),
        registry_revision: DIGEST.into(),
        action_id: "correct-address".into(),
        context_id: "facility-address-context".into(),
        contract: ReviewContextContract {
            id: contract["id"].as_str().unwrap().into(),
            revision: ContentDigest::parse(contract["revision"].as_str().unwrap()).unwrap(),
            schema_digest: ContentDigest::parse(contract["digest"].as_str().unwrap()).unwrap(),
        },
        schema,
        schema_bytes: schema_bytes.into(),
    };
    export.check().unwrap();
}

#[test]
fn canonical_review_project_compiles_both_context_modes() {
    let project = CaseworkProject::load(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../products/casework/examples/canonical-review/casework.yaml"
    ))
    .unwrap();
    assert!(project.compile_policy("facility-address-review").is_ok());
    assert!(project.compile_policy("decision").is_ok());
}
