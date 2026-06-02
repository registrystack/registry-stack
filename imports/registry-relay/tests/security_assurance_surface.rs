// SPDX-License-Identifier: Apache-2.0
//! Runtime exposure checks generated from the security assurance manifest.

use std::path::PathBuf;
use std::sync::Arc;

use axum::http::{Method, StatusCode};
use axum_test::TestServer;
use registry_relay::audit::{AuditPipeline, InMemorySink};
use registry_relay::auth::api_key::ApiKeyAuth;
use registry_relay::auth::AuthProvider;
use registry_relay::config::Config;
use registry_relay::server::build_app;
use serde::Deserialize;

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
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/example.yaml");
    let fingerprint = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("STATS_OFFICE_API_KEY_HASH", fingerprint);
        std::env::set_var("PROGRAM_SYSTEM_API_KEY_HASH", fingerprint);
        std::env::set_var("VERIFICATION_SERVICE_API_KEY_HASH", fingerprint);
        std::env::set_var(
            "REGISTRY_RELAY_AUDIT_HASH_SECRET",
            "relay-security-assurance-secret-32-bytes",
        );
    }
    registry_relay::config::load(&path).expect("example config loads")
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
            && endpoint.feature.is_none()
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
