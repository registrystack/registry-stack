// SPDX-License-Identifier: Apache-2.0
//! Product-owned acceptance entry point through the real Discovery router.

use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use registry_discovery::{
    canonical_index_bytes, catalog_revision, mapping_revision, package_limits, prepare, router,
    CompiledEvidenceMapping, Directory, DiscoveryIndex, DiscoveryService, EvidenceTypeAlternative,
    EvidenceTypeResolveResponse, OriginSummary, ServiceKind, ServiceRecord, ServiceSearchResponse,
    INDEX_API_VERSION, INDEX_FILE, INDEX_KIND, PACKAGE_COMMAND,
};
use registry_platform_config::{write_package, DeclaredPosture, Posture, PostureSource};

const PRODUCTION: DeclaredPosture = DeclaredPosture {
    posture: Posture::Production,
    source: PostureSource::Default,
};
const DEVELOPMENT: DeclaredPosture = DeclaredPosture {
    posture: Posture::Development,
    source: PostureSource::Flag,
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
        api_version: INDEX_API_VERSION.into(),
        kind: INDEX_KIND.into(),
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
async fn verified_package_startup_serves_the_packaged_index_through_the_real_router() {
    let (temporary, runtime) = packaged_runtime(&index());
    let response = prepare(&runtime, PRODUCTION)
        .unwrap()
        .app()
        .oneshot(
            Request::get(
                "/v1/services?serviceKind=evidence&evidenceType=urn%3Aexample%3Aevidence-type",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let search: ServiceSearchResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(search.items.len(), 1);
    assert_eq!(search.items[0].record_id, "acceptance-record");
    drop(temporary);
}

fn packaged_runtime(index: &DiscoveryIndex) -> (tempfile::TempDir, std::path::PathBuf) {
    let temporary = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let package_root = temporary.path().join("package");
    let files = BTreeMap::from([(INDEX_FILE.to_owned(), canonical_index_bytes(index).unwrap())]);
    let package = write_package(
        &package_root,
        &files,
        Some("http-journey"),
        &package_limits(),
        PACKAGE_COMMAND,
    )
    .unwrap();
    let runtime = temporary.path().join("runtime.yaml");
    fs::write(
        &runtime,
        format!(
            r#"apiVersion: id.registrystack.org/formats/discovery/runtime/v1alpha1
kind: DiscoveryRuntimeConfig
listener: {{ bind: 127.0.0.1:0, requestTimeoutMilliseconds: 10000 }}
package:
  root: {}
  expectedDigest: {}
limits:
  maximumRequestBytes: 65536
  maximumResponseBytes: 1048576
  maximumResultRecords: 100
  maximumResultAlternatives: 100
  shutdownGraceMilliseconds: 10000
logLevel: info
"#,
            package_root.display(),
            package.digest()
        ),
    )
    .unwrap();

    (temporary, runtime)
}

fn reserve_runtime_address(runtime: &std::path::Path) -> std::net::TcpListener {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let config = fs::read_to_string(runtime).unwrap();
    fs::write(
        runtime,
        config.replace("127.0.0.1:0", &listener.local_addr().unwrap().to_string()),
    )
    .unwrap();
    listener
}

#[test]
fn executable_logs_the_source_of_each_posture_declaration() {
    let (_temporary, runtime) = packaged_runtime(&index());
    let _listener = reserve_runtime_address(&runtime);
    for (flag, environment, source, posture) in [
        (None, None, "default", "production"),
        (None, Some("development"), "environment", "development"),
        (Some("development"), None, "flag", "development"),
    ] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_discovery"));
        command
            .env_remove("REGISTRY_STACK_POSTURE")
            .arg("--runtime-config")
            .arg(&runtime);
        if let Some(flag) = flag {
            command.args(["--posture", flag]);
        }
        if let Some(environment) = environment {
            command.env("REGISTRY_STACK_POSTURE", environment);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("listener could not be started"), "{stderr}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let events = stdout
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok());
        assert!(
            events
                .into_iter()
                .any(|event| event["fields"]["message"] == "posture declared"
                    && event["fields"]["posture_source"] == source
                    && event["fields"]["posture"] == posture),
            "{stdout}"
        );
    }
}

#[cfg(unix)]
#[test]
fn startup_reports_package_root_lookup_failure() {
    let (temporary, runtime) = packaged_runtime(&index());
    let root = temporary.path().join("package-loop");
    std::os::unix::fs::symlink(&root, &root).unwrap();
    let text = fs::read_to_string(&runtime).unwrap();
    let text = text
        .lines()
        .map(|line| {
            if line.starts_with("  root:") {
                format!("  root: {}", root.display())
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&runtime, text).unwrap();
    let Err(registry_discovery::StartupError::PackageRootLookup(diagnostic)) =
        prepare(&runtime, PRODUCTION)
    else {
        panic!("startup must return a typed diagnostic for the package root lookup");
    };
    assert_eq!(diagnostic.code, "discovery.runtime.package-refused");
    assert_eq!(diagnostic.path, "/package/root");
}

#[tokio::test]
async fn production_refuses_loopback_package_urls() {
    let mut index = index();
    index.origins[0].catalog_url = "http://127.0.0.1/catalog.jsonld".into();
    index.services[0].origin_url = index.origins[0].catalog_url.clone();
    index.services[0].endpoint_url = "http://localhost/evidence".into();
    index.catalog_revision = catalog_revision(&index.services).unwrap();
    let (temporary, runtime) = packaged_runtime(&index);
    let Err(error) = prepare(&runtime, PRODUCTION) else {
        panic!("the undeclared production default admitted a loopback catalog");
    };
    let message = error.to_string();
    assert!(
        message.contains("discovery.posture.loopback-catalog-url"),
        "{message}"
    );
    for pointer in [
        "/origins/0/catalogUrl",
        "/services/0/originUrl",
        "/services/0/endpointUrl",
    ] {
        assert!(message.contains(pointer), "{message}");
    }
    assert!(message.contains("rstack dev"), "{message}");
    assert!(
        message.contains("REGISTRY_STACK_POSTURE=development"),
        "{message}"
    );
    let _listener = reserve_runtime_address(&runtime);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_discovery"))
        .env_remove("REGISTRY_STACK_POSTURE")
        .arg("--runtime-config")
        .arg(&runtime)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("discovery.posture.loopback-catalog-url"),
        "{stderr}"
    );
    for pointer in [
        "/origins/0/catalogUrl",
        "/services/0/originUrl",
        "/services/0/endpointUrl",
    ] {
        assert!(stderr.contains(pointer), "{stderr}");
    }

    let log_path = temporary.path().join("startup.log");
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(fs::File::create(&log_path).unwrap())
        .finish();
    let prepared = tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        prepare(&runtime, DEVELOPMENT)
    })
    .unwrap();
    let logs = fs::read_to_string(log_path).unwrap();
    assert!(logs.contains("posture declared"), "{logs}");
    assert!(logs.contains(r#""development_settings":3"#), "{logs}");
    assert_eq!(
        logs.matches("discovery.posture.loopback-catalog-url")
            .count(),
        3
    );

    let response = prepared
        .app()
        .oneshot(Request::get("/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["registry-posture"], "development");
    let body = to_bytes(response.into_body(), 65536).await.unwrap();
    let ready: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(ready["posture"], "development");
    assert_eq!(ready["status"], "ready");
    assert_eq!(ready["developmentSettings"].as_array().unwrap().len(), 3);
    assert_eq!(
        ready["developmentSettings"][0]["pointer"],
        "/origins/0/catalogUrl"
    );
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
