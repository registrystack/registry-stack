// SPDX-License-Identifier: Apache-2.0
//! Product-owned acceptance entry point through the real Discovery router.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use registry_discovery::{
    catalog_revision, mapping_revision, router, CompiledEvidenceMapping, Directory, DiscoveryIndex,
    DiscoveryService, EvidenceTypeAlternative, EvidenceTypeResolveResponse, OriginSummary,
    ServiceKind, ServiceRecord, ServiceSearchResponse, INDEX_SCHEMA,
};
use tower::ServiceExt as _;

fn index() -> DiscoveryIndex {
    let origin = OriginSummary {
        origin_id: "acceptance-origin".into(),
        catalog_url: "https://provider.example/catalog.jsonld".into(),
        content_digest: format!("sha256:{}", "1".repeat(64)),
        fetched_at: "2026-08-14T00:00:00Z".into(),
    };
    let services = vec![ServiceRecord {
        record_id: "acceptance-record".into(),
        binding_id: "urn:example:binding:evidence".into(),
        service_id: "urn:example:service:evidence".into(),
        service_kind: ServiceKind::Evidence,
        title: "Example Evidence".into(),
        description: "Minimum-disclosure evidence service".into(),
        endpoint_url: "https://provider.example/evidence".into(),
        publisher_id: Some("urn:example:publisher".into()),
        operator_id: None,
        registry_authority_id: None,
        legal_issuer_id: Some("urn:example:issuer".into()),
        technical_provider_id: Some("urn:example:provider".into()),
        jurisdictions: vec!["urn:example:jurisdiction".into()],
        conforms_to: vec!["urn:example:evidence-profile".into()],
        evidence_type_ids: vec!["urn:example:evidence-type".into()],
        semantic_class_ids: Vec::new(),
        operation_family_ids: Vec::new(),
        origin_id: origin.origin_id.clone(),
        origin_url: origin.catalog_url.clone(),
        origin_content_digest: origin.content_digest.clone(),
        origin_fetched_at: origin.fetched_at.clone(),
    }];
    let mappings = vec![CompiledEvidenceMapping {
        mapping_id: "urn:example:mapping".into(),
        mapping_authority_id: "urn:example:mapping-authority".into(),
        requirement_id: "urn:example:requirement".into(),
        jurisdiction: Some("urn:example:jurisdiction".into()),
        alternatives: vec![EvidenceTypeAlternative {
            evidence_type_list_id: "urn:example:evidence-list".into(),
            evidence_type_ids: vec!["urn:example:evidence-type".into()],
        }],
    }];
    DiscoveryIndex {
        schema_version: INDEX_SCHEMA.into(),
        catalog_revision: catalog_revision(&services).unwrap(),
        mapping_revision: mapping_revision(&mappings).unwrap(),
        built_at: "2026-08-14T00:00:01Z".into(),
        origins: vec![origin],
        services,
        mappings,
    }
}

fn app() -> axum::Router {
    let directory = Directory::new(index(), 100, 100).unwrap();
    let service = Arc::new(DiscoveryService::new(directory, 1024 * 1024).unwrap());
    router(service, 64 * 1024, Duration::from_secs(5)).unwrap()
}

#[tokio::test]
async fn immutable_index_supports_resolution_and_exact_service_search() {
    for route in ["/health", "/ready", "/openapi.json"] {
        let response = app()
            .oneshot(Request::get(route).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let resolution = app()
        .oneshot(
            Request::post("/v1/evidence-types/resolve")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    br#"{"requirementId":"urn:example:requirement","jurisdiction":"urn:example:jurisdiction"}"#
                        .as_slice(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resolution.status(), StatusCode::OK);
    let body = to_bytes(resolution.into_body(), 64 * 1024).await.unwrap();
    let resolution: EvidenceTypeResolveResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resolution.alternatives.len(), 1);

    let search = app()
        .oneshot(
            Request::get(
                "/v1/services?serviceKind=evidence&evidenceType=urn%3Aexample%3Aevidence-type",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(search.status(), StatusCode::OK);
    let body = to_bytes(search.into_body(), 1024 * 1024).await.unwrap();
    let search: ServiceSearchResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(search.items.len(), 1);
    assert_eq!(search.items[0].record_id, "acceptance-record");

    let removed_route = app()
        .oneshot(
            Request::post("/v1/evidence-providers/resolve")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(removed_route.status(), StatusCode::NOT_FOUND);
}
