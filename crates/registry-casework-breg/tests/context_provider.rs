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
    let mut schema = json!({"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:registry:breg:review-context:source:correct-address:address","x-registry-review-context":{"registryId":"registry","sourceNamespace":"source","actionId":"correct-address","contextId":"address"},"type":"object","additionalProperties":false,"required":["reference"],"properties":{"reference":{"type":"string","maxLength":128}}});
    let revision =
        sha256_uri(&registry_platform_canonical_json::canonicalize_json(&schema).unwrap());
    schema["x-registry-definition-revision"] = json!(revision);
    let schema_bytes = serde_json::to_string(&schema).unwrap();
    BregContextExport {
        api_version: DESCRIPTION_API_VERSION.into(),
        kind: DESCRIPTION_KIND.into(),
        source_namespace: "source".into(),
        action_id: "correct-address".into(),
        context_id: "address".into(),
        contract: ReviewContextContract {
            id: "urn:registry:breg:review-context:source:correct-address:address".into(),
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
    let mut context = json!({"reference":"native-proposal", "contract":export().contract});
    if display {
        context["fields"] = json!({"reference":"REF-42"});
    }
    Mock::given(method("GET")).and(path(format!("/v1/proposals/{ID}/{suffix}"))).and(query_param("accessProfile",profile)).and(header("authorization",format!("Bearer {bearer}"))).respond_with(response(json!({"id":ID,"actionId":"correct-address","actionRevision":DIGEST,"submissionVersion":1,"revision":1,"effectDigest":DIGEST,"subject":{"source":"source","subjectType":"proposal","id":ID,"version":"1","digest":DIGEST},"context":context,"reviewable":true}))).mount(server).await;
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
async fn unrelated_registry_revision_change_preserves_the_exact_context_contract() {
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
    let display = provider
        .human_display(HumanDisplayRequest {
            identity: &identity,
            source_profile_id: "reviewer",
            credential: EphemeralCredential::new("human-bearer"),
        })
        .await
        .unwrap();
    assert_eq!(display.fields["reference"], json!("REF-42"));
    mocks(
        &server,
        "status",
        "status-bearer",
        false,
        &format!("sha256:{}", "c".repeat(64)),
    )
    .await;
    assert!(provider.service_status(&identity).await.unwrap().reviewable);
    assert_eq!(server.received_requests().await.unwrap().len(), 4);
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
        "../../../products/breg/generated/facility/generated/review-context-schemas/index.json"
    ))
    .unwrap();
    let contract = &index["correct-address"];
    let schema: Value = serde_json::from_str(schema_bytes).unwrap();
    let export = BregContextExport {
        api_version: DESCRIPTION_API_VERSION.into(),
        kind: DESCRIPTION_KIND.into(),
        source_namespace: "facility-registry".into(),
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

#[tokio::test]
async fn missing_or_changed_producer_contract_refuses_without_releasing_fields() {
    for member in [None, Some("id"), Some("revision"), Some("schemaDigest")] {
        let server = MockServer::start().await;
        let export = export();
        let identity = identity(&export);
        let mut contract = serde_json::to_value(&export.contract).unwrap();
        let provider = provider(&server, export);
        mocks(&server, "reviewer", "human-bearer", true, DIGEST).await;
        if let Some(member) = member {
            contract[member] = if member == "id" {
                json!("urn:registry:breg:review-context:source:correct-address:other-context")
            } else {
                json!(format!("sha256:{}", "b".repeat(64)))
            };
        }
        let mut context =
            json!({"reference":"native-proposal","fields":{"reference":"private-field-canary"}});
        if member.is_some() {
            context["contract"] = contract;
        }
        Mock::given(method("GET"))
            .and(path(format!("/v1/proposals/{ID}/review-context")))
            .respond_with(response(json!({"id":ID,"actionId":"correct-address","actionRevision":DIGEST,
                "submissionVersion":1,"revision":1,"effectDigest":DIGEST,
                "subject":{"source":"source","subjectType":"proposal","id":ID,"version":"1","digest":DIGEST},
                "context":context,"reviewable":true})))
            .with_priority(1)
            .mount(&server).await;
        assert_eq!(
            provider
                .human_display(HumanDisplayRequest {
                    identity: &identity,
                    source_profile_id: "reviewer",
                    credential: EphemeralCredential::new("human-bearer"),
                })
                .await
                .unwrap_err(),
            ReviewContextError::ContractChanged
        );
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.method == "GET"));
    }
}

#[tokio::test]
async fn status_requires_exact_producer_contract_without_display_fields() {
    for member in [None, Some("id"), Some("revision"), Some("schemaDigest")] {
        let server = MockServer::start().await;
        let export = export();
        let identity = identity(&export);
        let mut contract = serde_json::to_value(&export.contract).unwrap();
        let provider = provider(&server, export);
        mocks(&server, "status", "status-bearer", false, DIGEST).await;
        if let Some(member) = member {
            contract[member] = if member == "id" {
                json!("urn:registry:breg:review-context:source:correct-address:other-context")
            } else {
                json!(format!("sha256:{}", "b".repeat(64)))
            };
        }
        let mut context = json!({"reference":"native-proposal"});
        if member.is_some() {
            context["contract"] = contract;
        }
        Mock::given(method("GET"))
            .and(path(format!("/v1/proposals/{ID}/review-status")))
            .respond_with(response(json!({"id":ID,"actionId":"correct-address","actionRevision":DIGEST,
                "submissionVersion":1,"revision":1,"effectDigest":DIGEST,
                "subject":{"source":"source","subjectType":"proposal","id":ID,"version":"1","digest":DIGEST},
                "context":context,"reviewable":true})))
            .with_priority(1).mount(&server).await;
        assert_eq!(
            provider.service_status(&identity).await.unwrap_err(),
            ReviewContextError::ContractChanged
        );
    }
}

#[test]
fn exported_source_action_and_context_are_covered_by_the_schema() {
    for member in ["sourceNamespace", "actionId", "contextId"] {
        let mut value = serde_json::to_value(export()).unwrap();
        value[member] = json!("changed");
        let export: BregContextExport = serde_json::from_value(value).unwrap();
        assert_eq!(export.check(), Err(ReviewContextError::Invalid), "{member}");
    }
    let mut value = serde_json::to_value(export()).unwrap();
    value["registryRevision"] = json!(DIGEST);
    assert!(serde_json::from_value::<BregContextExport>(value).is_err());
}

#[tokio::test]
async fn changed_request_source_type_or_contract_refuses_before_source_io() {
    for member in ["source", "subjectType", "contract"] {
        let server = MockServer::start().await;
        let export = export();
        let mut identity = identity(&export);
        match member {
            "source" => identity.subject.source = "other-source".into(),
            "subjectType" => identity.subject.subject_type = "record".into(),
            _ => identity.contract.id = "urn:other-context".into(),
        }
        let provider = provider(&server, export);
        assert_eq!(
            provider
                .human_display(HumanDisplayRequest {
                    identity: &identity,
                    source_profile_id: "reviewer",
                    credential: EphemeralCredential::new("human-bearer"),
                })
                .await
                .unwrap_err(),
            ReviewContextError::ContractChanged,
            "{member}",
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn changed_observed_action_or_subject_refuses_the_exact_binding() {
    for member in [
        "source",
        "version",
        "digest",
        "id",
        "subjectType",
        "actionId",
    ] {
        let server = MockServer::start().await;
        let export = export();
        let identity = identity(&export);
        let provider = provider(&server, export);
        mocks(&server, "reviewer", "human-bearer", true, DIGEST).await;
        let mut document = json!({"id":ID,"actionId":"correct-address","actionRevision":DIGEST,
            "submissionVersion":1,"revision":1,"effectDigest":DIGEST,
            "subject":{"source":"source","subjectType":"proposal","id":ID,"version":"1","digest":DIGEST},
            "context":{"reference":"native-proposal","contract":identity.contract,"fields":{"reference":"private-field-canary"}},
            "reviewable":true});
        match member {
            "source" => document["subject"]["source"] = json!("other-source"),
            "id" => document["subject"]["id"] = json!("00000000-0000-4000-8000-000000000002"),
            "subjectType" => document["subject"]["subjectType"] = json!("record"),
            "actionId" => document["actionId"] = json!("other-action"),
            "version" => {
                document["subject"]["version"] = json!("2");
                document["submissionVersion"] = json!(2);
            }
            _ => {
                let digest = format!("sha256:{}", "b".repeat(64));
                document["subject"]["digest"] = json!(digest);
                document["effectDigest"] = json!(digest);
            }
        }
        Mock::given(method("GET"))
            .and(path(format!("/v1/proposals/{ID}/review-context")))
            .respond_with(response(document))
            .with_priority(1)
            .mount(&server)
            .await;
        assert_eq!(
            provider
                .human_display(HumanDisplayRequest {
                    identity: &identity,
                    source_profile_id: "reviewer",
                    credential: EphemeralCredential::new("human-bearer"),
                })
                .await
                .unwrap_err(),
            if matches!(member, "id" | "subjectType" | "actionId") {
                ReviewContextError::ContractChanged
            } else {
                ReviewContextError::BindingMoved
            },
            "{member}"
        );
    }
}

#[tokio::test]
async fn current_metadata_must_advertise_the_exact_profile_action_and_purpose() {
    for member in ["accessProfile", "actionId", "operations"] {
        let server = MockServer::start().await;
        let export = export();
        let identity = identity(&export);
        let provider = provider(&server, export);
        mocks(&server, "reviewer", "human-bearer", true, DIGEST).await;
        let mut action = json!({"actionId":"correct-address","accessProfile":"reviewer","operations":["get-review-context"]});
        action[member] = if member == "operations" {
            json!(["get-review-status"])
        } else {
            json!("other")
        };
        Mock::given(method("GET")).and(path("/v1/registry"))
            .respond_with(response(json!({"metadataVersion":"1","id":"registry","version":"1","revision":DIGEST,
                "recordTypes":[],"operations":[],"proposals":{"method":"GET","path":"/v1/proposals","accessProfiles":[],
                "get":{"method":"GET","path":"/v1/proposals/{proposal_id}","accessProfiles":[]},"actions":[action]}})))
            .with_priority(1).mount(&server).await;
        assert_eq!(
            provider
                .human_display(HumanDisplayRequest {
                    identity: &identity,
                    source_profile_id: "reviewer",
                    credential: EphemeralCredential::new("human-bearer"),
                })
                .await
                .unwrap_err(),
            ReviewContextError::Concealed,
            "{member}"
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn current_row_disclosure_refusal_never_falls_back_to_service_credentials() {
    for status in [403, 404] {
        let server = MockServer::start().await;
        let export = export();
        let identity = identity(&export);
        let provider = provider(&server, export);
        mocks(&server, "reviewer", "human-bearer", true, DIGEST).await;
        // The native concealed response and a bounded future refusal both use
        // BReg's published Problem namespace, as its client requires.
        let (code, title, detail) = if status == 404 {
            (
                "resource.not_found",
                "Not Found",
                "The requested resource was not found.",
            )
        } else {
            (
                "disclosure.refused",
                "Disclosure refused",
                "Current disclosure refused.",
            )
        };
        Mock::given(method("GET"))
            .and(path(format!("/v1/proposals/{ID}/review-context")))
            .respond_with(ResponseTemplate::new(status)
                .insert_header("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
                .insert_header("cache-control", "no-store")
                .set_body_raw(serde_json::to_vec(&json!({"type":format!("https://id.registrystack.org/problems/registry-breg/{}", code.replace('.', "/")),
                    "title":title,"status":status,"detail":detail,
                    "code":code,"traceId":"4bf92f3577b34da6a3ce929d0e0e4736"})).unwrap(), "application/problem+json"))
            .with_priority(1).mount(&server).await;
        assert_eq!(
            provider
                .human_display(HumanDisplayRequest {
                    identity: &identity,
                    source_profile_id: "reviewer",
                    credential: EphemeralCredential::new("human-bearer"),
                })
                .await
                .unwrap_err(),
            ReviewContextError::Concealed
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        for request in requests {
            assert_eq!(
                request.headers.get("authorization").unwrap(),
                "Bearer human-bearer"
            );
            assert!(request
                .url
                .query_pairs()
                .any(|(key, value)| key == "accessProfile" && value == "reviewer"));
        }
    }
}

#[tokio::test]
async fn display_fields_must_match_the_exported_schema() {
    let server = MockServer::start().await;
    let export = export();
    let identity = identity(&export);
    let provider = provider(&server, export);
    mocks(&server, "reviewer", "human-bearer", true, DIGEST).await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/proposals/{ID}/review-context")))
        .respond_with(response(json!({"id":ID,"actionId":"correct-address","actionRevision":DIGEST,
            "submissionVersion":1,"revision":1,"effectDigest":DIGEST,
            "subject":{"source":"source","subjectType":"proposal","id":ID,"version":"1","digest":DIGEST},
            "context":{"reference":"native-proposal","contract":identity.contract,"fields":{"reference":42}},
            "reviewable":true})))
        .with_priority(1).mount(&server).await;
    assert_eq!(
        provider
            .human_display(HumanDisplayRequest {
                identity: &identity,
                source_profile_id: "reviewer",
                credential: EphemeralCredential::new("human-bearer"),
            })
            .await
            .unwrap_err(),
        ReviewContextError::Invalid
    );
}
