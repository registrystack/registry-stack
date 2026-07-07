// SPDX-License-Identifier: Apache-2.0
//! Runtime exposure checks generated from the security assurance manifest.

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use axum_test::TestServer;
use registry_relay::audit::{AuditPipeline, InMemorySink};
use registry_relay::auth::api_key::ApiKeyAuth;
use registry_relay::auth::AuthProvider;
use registry_relay::config::Config;
use registry_relay::server::build_app;
use serde::Deserialize;

mod support;

#[derive(Debug, Deserialize)]
struct ExposureManifest {
    endpoints: Vec<Endpoint>,
}

#[derive(Debug, Deserialize)]
struct Endpoint {
    listener: String,
    method: String,
    path: String,
    feature: Option<String>,
    auth: String,
}

fn load_example_config() -> Config {
    support::load_example_config_for_tests("relay-security-assurance-secret-32-bytes")
}

fn sample_path(path: &str) -> String {
    path.replace("{dataset_id}", "social_registry")
        .replace("{aggregate_id}", "benefit_totals")
        .replace("{item_id}", "municipality_code")
        .replace("{entity}", "beneficiaries")
        .replace("{id}", "1")
        .replace("{relationship}", "household")
        .replace("{offering_id}", "offering-1")
        .replace("{profile}", "dcat-ap")
        .replace("{record_id}", "social_registry")
        .replace("{claim_type}", "entity-record")
        .replace("{version}", "v1.json")
        .replace("{registry}", "sr")
        .replace("{collection_id}", "datasets")
        .replace("{feature_id}", "social_registry")
}

fn feature_enabled(feature: Option<&str>) -> bool {
    match feature {
        None => true,
        Some("ogcapi-edr") => cfg!(feature = "ogcapi-edr"),
        Some("ogcapi-features") => cfg!(feature = "ogcapi-features"),
        Some("ogcapi-records") => cfg!(feature = "ogcapi-records"),
        Some("spdci-api-standards") => cfg!(feature = "spdci-api-standards"),
        Some(_) => false,
    }
}

#[tokio::test]
async fn manifest_public_protected_routes_are_mounted_behind_auth() {
    let manifest: ExposureManifest =
        serde_json::from_str(include_str!("../security/exposure-manifest.json"))
            .expect("security exposure manifest parses");
    let config = Arc::new(load_example_config());
    let auth: Arc<dyn AuthProvider> = Arc::new(ApiKeyAuth::new(Vec::new()));
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let server = TestServer::new(build_app(config, auth, sink).expect("app builds"));

    for endpoint in manifest.endpoints.iter().filter(|endpoint| {
        endpoint.listener == "public"
            && endpoint.auth != "none"
            && feature_enabled(endpoint.feature.as_deref())
            && endpoint.method != "HEAD"
    }) {
        let method = Method::from_bytes(endpoint.method.as_bytes()).expect("method parses");
        let path = sample_path(&endpoint.path);
        let response = server.method(method, &path).await;
        assert_eq!(
            response.status_code(),
            StatusCode::UNAUTHORIZED,
            "{} {} must be mounted behind auth on the public listener",
            endpoint.method,
            endpoint.path
        );
    }
}
