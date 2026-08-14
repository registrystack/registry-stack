// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Response, StatusCode};
use axum::routing::get;
use axum::Router;
use registry_discovery::parse_index;
use registry_discovery_profile::{
    render_description, DiscoveryDescription, ServiceDescription, ServiceKind, ServiceRoles,
    MEDIA_TYPE,
};
use registry_discoveryctl::{build_project_at, BuildError};
use tempfile::TempDir;
use time::{macros::datetime, OffsetDateTime};

fn description() -> Vec<u8> {
    let service = ServiceDescription::new(
        "urn:example:service:evidence".into(),
        ServiceKind::Evidence,
        "Example Evidence".into(),
        "Public minimum-disclosure assertions".into(),
        "https://evidence.example.org".into(),
        ServiceRoles {
            publisher_id: Some("urn:example:publisher".into()),
            legal_issuer_id: Some("urn:example:issuer".into()),
            technical_provider_id: Some("urn:example:provider".into()),
            ..ServiceRoles::default()
        },
        vec!["urn:example:jurisdiction".into()],
        vec!["https://registrystack.org/evidence/profile/v1".into()],
        vec!["urn:example:evidence-type:adult-status".into()],
        Vec::new(),
        Vec::new(),
    )
    .expect("service");
    render_description(&DiscoveryDescription::new(vec![service]).expect("description"))
        .expect("render")
}

fn description_with_service_count(count: usize) -> Vec<u8> {
    let services = (0..count)
        .map(|index| {
            ServiceDescription::new(
                format!("urn:s:{index}"),
                ServiceKind::Evidence,
                "S".into(),
                "D".into(),
                "https://e.example".into(),
                ServiceRoles::default(),
                vec!["urn:j".into()],
                vec!["urn:p".into()],
                vec!["urn:e".into()],
                Vec::new(),
                Vec::new(),
            )
            .expect("service")
        })
        .collect();
    render_description(&DiscoveryDescription::new(services).expect("description")).expect("render")
}

async fn provider(
    body: Vec<u8>,
    status: StatusCode,
    counter: Arc<AtomicUsize>,
) -> (String, tokio::task::JoinHandle<()>) {
    provider_with_content_encoding(body, status, counter, None).await
}

async fn provider_with_content_encoding(
    body: Vec<u8>,
    status: StatusCode,
    counter: Arc<AtomicUsize>,
    content_encoding: Option<&'static str>,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/catalog.jsonld",
        get(move || {
            let body = body.clone();
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut response = Response::builder()
                    .status(status)
                    .header(CONTENT_TYPE, MEDIA_TYPE);
                if let Some(content_encoding) = content_encoding {
                    response = response.header("content-encoding", content_encoding);
                }
                response.body(Body::from(body)).expect("response")
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("listener");
    let address = listener.local_addr().expect("address");
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("provider server");
    });
    (format!("http://{address}/catalog.jsonld"), task)
}

async fn any_path_provider(
    body: Vec<u8>,
    counter: Arc<AtomicUsize>,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/{*path}",
        get(move || {
            let body = body.clone();
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, MEDIA_TYPE)
                    .body(Body::from(body))
                    .expect("response")
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("listener");
    let address = listener.local_addr().expect("address");
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("provider server");
    });
    (format!("http://{address}"), task)
}

async fn provider_with_media_type(
    body: Vec<u8>,
    media_type: &'static str,
    counter: Arc<AtomicUsize>,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/catalog.jsonld",
        get(move || {
            let body = body.clone();
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, media_type)
                    .body(Body::from(body))
                    .expect("response")
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("listener");
    let address = listener.local_addr().expect("address");
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("provider server");
    });
    (format!("http://{address}/catalog.jsonld"), task)
}

async fn provider_with_duplicate_media_type(
    body: Vec<u8>,
    counter: Arc<AtomicUsize>,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/catalog.jsonld",
        get(move || {
            let body = body.clone();
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, MEDIA_TYPE)
                    .header(CONTENT_TYPE, MEDIA_TYPE)
                    .body(Body::from(body))
                    .expect("response")
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("listener");
    let address = listener.local_addr().expect("address");
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("provider server");
    });
    (format!("http://{address}/catalog.jsonld"), task)
}

fn authoring_project(catalog_url: &str) -> TempDir {
    let project = TempDir::new().expect("project");
    fs::write(
        project.path().join("origins.yaml"),
        format!(
            "schemaVersion: registry-discovery/origins/v1alpha1\norigins:\n  - originId: evidence-one\n    catalogUrl: {catalog_url}\n    profile: registry-discovery-v1alpha1\n    enabled: true\n"
        ),
    )
    .expect("origins");
    fs::create_dir(project.path().join("mappings")).expect("mappings");
    fs::write(
        project.path().join("mappings/adult-status.yaml"),
        "schemaVersion: registry-discovery/evidence-mapping/v1alpha1\nmappingId: urn:example:mapping:adult-status\nmappingAuthorityId: urn:example:authority\nrequirementId: urn:example:requirement:adult-status\njurisdiction: urn:example:jurisdiction\nalternatives:\n  - evidenceTypeListId: urn:example:list:adult-status\n    evidenceTypeIds:\n      - urn:example:evidence-type:adult-status\n",
    )
    .expect("mapping");
    project
}

#[tokio::test]
async fn build_fetches_each_origin_once_and_preserves_semantic_revisions() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (catalog_url, task) = provider(description(), StatusCode::OK, Arc::clone(&counter)).await;
    let project = authoring_project(&catalog_url);
    let first_output = project.path().join("first.json");
    let first = build_project_at(
        project.path(),
        &first_output,
        true,
        datetime!(2026-08-14 00:00:00 UTC),
    )
    .await
    .expect("first build");
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_ne!(
        first.origins[0].fetched_at, first.built_at,
        "origin provenance must record its own completed fetch time"
    );
    assert_eq!(
        first.origins[0].fetched_at,
        first.services[0].origin_fetched_at
    );
    assert_eq!(
        parse_index(&fs::read(&first_output).expect("index")).expect("valid index"),
        first
    );

    let second_output = project.path().join("second.json");
    let second = build_project_at(
        project.path(),
        &second_output,
        true,
        datetime!(2026-08-15 00:00:00 UTC),
    )
    .await
    .expect("second build");
    assert_eq!(counter.load(Ordering::SeqCst), 2);
    assert_eq!(first.catalog_revision, second.catalog_revision);
    assert_eq!(first.mapping_revision, second.mapping_revision);
    assert_ne!(first.built_at, second.built_at);
    task.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn successful_builds_publish_a_stable_runtime_readable_file_mode() {
    use std::os::unix::fs::PermissionsExt as _;

    let counter = Arc::new(AtomicUsize::new(0));
    let (catalog_url, task) = provider(description(), StatusCode::OK, Arc::clone(&counter)).await;
    let project = authoring_project(&catalog_url);
    let output = project.path().join("index.json");

    build_project_at(
        project.path(),
        &output,
        true,
        datetime!(2026-08-14 00:00:00 UTC),
    )
    .await
    .expect("initial build");
    assert_eq!(
        fs::metadata(&output)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );

    fs::set_permissions(&output, fs::Permissions::from_mode(0o600))
        .expect("restrict previous output");
    build_project_at(
        project.path(),
        &output,
        true,
        datetime!(2026-08-15 00:00:00 UTC),
    )
    .await
    .expect("replacement build");
    assert_eq!(
        fs::metadata(&output)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert_eq!(counter.load(Ordering::SeqCst), 2);
    task.abort();
}

#[tokio::test]
async fn failed_origin_fetch_leaves_the_previous_output_untouched() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (catalog_url, task) =
        provider(description(), StatusCode::FOUND, Arc::clone(&counter)).await;
    let project = authoring_project(&catalog_url);
    let output = project.path().join("index.json");
    fs::write(&output, b"previous-index-canary").expect("previous index");
    let result = build_project_at(project.path(), &output, true, OffsetDateTime::UNIX_EPOCH).await;
    assert!(matches!(result, Err(BuildError::Fetch)));
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(
        fs::read(&output).expect("previous output"),
        b"previous-index-canary"
    );
    task.abort();
}

#[tokio::test]
async fn production_policy_refuses_loopback_before_connecting() {
    let project = authoring_project("https://127.0.0.1:9/catalog.jsonld");
    let output = project.path().join("index.json");
    let result = build_project_at(project.path(), &output, false, OffsetDateTime::UNIX_EPOCH).await;
    assert!(matches!(result, Err(BuildError::Fetch)));
    assert!(!output.exists());
}

#[tokio::test]
async fn identical_claimed_service_ids_from_distinct_origins_remain_separate() {
    let first_counter = Arc::new(AtomicUsize::new(0));
    let second_counter = Arc::new(AtomicUsize::new(0));
    let (first_url, first_task) =
        provider(description(), StatusCode::OK, Arc::clone(&first_counter)).await;
    let (second_url, second_task) =
        provider(description(), StatusCode::OK, Arc::clone(&second_counter)).await;
    let project = authoring_project(&first_url);
    fs::write(
        project.path().join("origins.yaml"),
        format!(
            "schemaVersion: registry-discovery/origins/v1alpha1\norigins:\n  - originId: evidence-one\n    catalogUrl: {first_url}\n    profile: registry-discovery-v1alpha1\n    enabled: true\n  - originId: evidence-two\n    catalogUrl: {second_url}\n    profile: registry-discovery-v1alpha1\n    enabled: true\n"
        ),
    )
    .expect("origins");

    let index = build_project_at(
        project.path(),
        &project.path().join("index.json"),
        true,
        OffsetDateTime::UNIX_EPOCH,
    )
    .await
    .expect("build");

    assert_eq!(first_counter.load(Ordering::SeqCst), 1);
    assert_eq!(second_counter.load(Ordering::SeqCst), 1);
    assert_eq!(index.services.len(), 2);
    assert_eq!(index.services[0].service_id, index.services[1].service_id);
    assert_ne!(index.services[0].record_id, index.services[1].record_id);
    assert_ne!(index.services[0].origin_id, index.services[1].origin_id);
    first_task.abort();
    second_task.abort();
}

#[tokio::test]
async fn unsupported_remote_context_leaves_the_previous_output_untouched() {
    let mut value: serde_json::Value =
        serde_json::from_slice(&description()).expect("description JSON");
    value["@context"] = serde_json::json!("https://attacker.invalid/context");
    let counter = Arc::new(AtomicUsize::new(0));
    let (catalog_url, task) = provider(
        serde_json::to_vec(&value).expect("description bytes"),
        StatusCode::OK,
        Arc::clone(&counter),
    )
    .await;
    let project = authoring_project(&catalog_url);
    let output = project.path().join("index.json");
    fs::write(&output, b"previous-index-canary").expect("previous index");

    let result = build_project_at(project.path(), &output, true, OffsetDateTime::UNIX_EPOCH).await;

    assert!(matches!(result, Err(BuildError::Description)));
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(
        fs::read(&output).expect("previous output"),
        b"previous-index-canary"
    );
    task.abort();
}

#[tokio::test]
async fn oversized_origin_body_leaves_the_previous_output_untouched() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (catalog_url, task) = provider(
        vec![b' '; registry_discovery_profile::MAX_DESCRIPTION_BYTES + 1],
        StatusCode::OK,
        Arc::clone(&counter),
    )
    .await;
    let project = authoring_project(&catalog_url);
    let output = project.path().join("index.json");
    fs::write(&output, b"previous-index-canary").expect("previous index");

    let result = build_project_at(project.path(), &output, true, OffsetDateTime::UNIX_EPOCH).await;

    assert!(matches!(result, Err(BuildError::Fetch)));
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(
        fs::read(&output).expect("previous output"),
        b"previous-index-canary"
    );
    task.abort();
}

#[tokio::test]
async fn encoded_origin_body_is_refused_without_replacing_the_output() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (catalog_url, task) = provider_with_content_encoding(
        description(),
        StatusCode::OK,
        Arc::clone(&counter),
        Some("gzip"),
    )
    .await;
    let project = authoring_project(&catalog_url);
    let output = project.path().join("index.json");
    fs::write(&output, b"previous-index-canary").expect("previous index");

    let result = build_project_at(project.path(), &output, true, OffsetDateTime::UNIX_EPOCH).await;

    assert!(matches!(result, Err(BuildError::Fetch)));
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(
        fs::read(&output).expect("previous output"),
        b"previous-index-canary"
    );
    task.abort();
}

#[tokio::test]
async fn wrong_profile_media_type_is_refused_without_replacing_the_output() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (catalog_url, task) =
        provider_with_media_type(description(), "application/ld+json", Arc::clone(&counter)).await;
    let project = authoring_project(&catalog_url);
    let output = project.path().join("index.json");
    fs::write(&output, b"previous-index-canary").expect("previous index");

    let result = build_project_at(project.path(), &output, true, OffsetDateTime::UNIX_EPOCH).await;

    assert!(matches!(result, Err(BuildError::Fetch)));
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(
        fs::read(&output).expect("previous output"),
        b"previous-index-canary"
    );
    task.abort();
}

#[tokio::test]
async fn duplicate_profile_media_type_is_refused_without_replacing_the_output() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (catalog_url, task) =
        provider_with_duplicate_media_type(description(), Arc::clone(&counter)).await;
    let project = authoring_project(&catalog_url);
    let output = project.path().join("index.json");
    fs::write(&output, b"previous-index-canary").expect("previous index");

    let result = build_project_at(project.path(), &output, true, OffsetDateTime::UNIX_EPOCH).await;

    assert!(matches!(result, Err(BuildError::Fetch)));
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(
        fs::read(&output).expect("previous output"),
        b"previous-index-canary"
    );
    task.abort();
}

#[tokio::test]
async fn duplicate_binding_within_one_origin_is_refused_without_replacing_the_output() {
    let mut value: serde_json::Value =
        serde_json::from_slice(&description()).expect("description JSON");
    let services = value["services"].as_array_mut().expect("service array");
    let duplicate = services[0].clone();
    services.push(duplicate);
    let counter = Arc::new(AtomicUsize::new(0));
    let (catalog_url, task) = provider(
        serde_json::to_vec(&value).expect("description bytes"),
        StatusCode::OK,
        Arc::clone(&counter),
    )
    .await;
    let project = authoring_project(&catalog_url);
    let output = project.path().join("index.json");
    fs::write(&output, b"previous-index-canary").expect("previous index");

    let result = build_project_at(project.path(), &output, true, OffsetDateTime::UNIX_EPOCH).await;

    assert!(matches!(result, Err(BuildError::Description)));
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(
        fs::read(&output).expect("previous output"),
        b"previous-index-canary"
    );
    task.abort();
}

#[tokio::test]
async fn invalid_mapping_is_refused_before_origin_io_and_preserves_previous_output() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (catalog_url, task) = provider(description(), StatusCode::OK, Arc::clone(&counter)).await;
    let project = authoring_project(&catalog_url);
    fs::write(
        project.path().join("mappings/adult-status.yaml"),
        "schemaVersion: registry-discovery/evidence-mapping/v1alpha1\nunexpected: true\n",
    )
    .expect("invalid mapping");
    let output = project.path().join("index.json");
    fs::write(&output, b"previous-index-canary").expect("previous index");

    let result = build_project_at(project.path(), &output, true, OffsetDateTime::UNIX_EPOCH).await;

    assert!(matches!(result, Err(BuildError::Project(_))));
    assert_eq!(counter.load(Ordering::SeqCst), 0);
    assert_eq!(
        fs::read(&output).expect("previous output"),
        b"previous-index-canary"
    );
    task.abort();
}

#[tokio::test]
async fn compiled_service_bound_leaves_the_previous_output_untouched() {
    let per_origin = registry_discovery_profile::MAX_SERVICES;
    let origins_needed = registry_discovery::MAXIMUM_SERVICES / per_origin + 1;
    let body = description_with_service_count(per_origin);
    assert!(body.len() <= registry_discovery_profile::MAX_DESCRIPTION_BYTES);
    let counter = Arc::new(AtomicUsize::new(0));
    let (base_url, task) = any_path_provider(body, Arc::clone(&counter)).await;
    let project = TempDir::new().expect("project");
    let mut origins =
        String::from("schemaVersion: registry-discovery/origins/v1alpha1\norigins:\n");
    for index in 0..origins_needed {
        origins.push_str(&format!(
            "  - originId: evidence-{index:03}\n    catalogUrl: {base_url}/catalog-{index:03}.jsonld\n    profile: registry-discovery-v1alpha1\n    enabled: true\n"
        ));
    }
    fs::write(project.path().join("origins.yaml"), origins).expect("origins");
    fs::create_dir(project.path().join("mappings")).expect("mappings");
    let output = project.path().join("index.json");
    fs::write(&output, b"previous-index-canary").expect("previous index");

    let result = build_project_at(project.path(), &output, true, OffsetDateTime::UNIX_EPOCH).await;

    assert!(matches!(result, Err(BuildError::Compile)));
    assert_eq!(counter.load(Ordering::SeqCst), origins_needed);
    assert_eq!(
        fs::read(&output).expect("previous output"),
        b"previous-index-canary"
    );
    task.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn write_failure_preserves_previous_output_and_leaves_no_visible_temporary_file() {
    use std::os::unix::fs::PermissionsExt as _;

    let counter = Arc::new(AtomicUsize::new(0));
    let (catalog_url, task) = provider(description(), StatusCode::OK, Arc::clone(&counter)).await;
    let project = authoring_project(&catalog_url);
    let deployment = project.path().join("deployment");
    fs::create_dir(&deployment).expect("deployment directory");
    let output = deployment.join("index.json");
    fs::write(&output, b"previous-index-canary").expect("previous index");
    fs::set_permissions(&deployment, fs::Permissions::from_mode(0o555))
        .expect("read-only deployment directory");

    let result = build_project_at(project.path(), &output, true, OffsetDateTime::UNIX_EPOCH).await;

    fs::set_permissions(&deployment, fs::Permissions::from_mode(0o755))
        .expect("restore deployment directory");
    assert!(matches!(result, Err(BuildError::Write)));
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(
        fs::read(&output).expect("previous output"),
        b"previous-index-canary"
    );
    let entries = fs::read_dir(&deployment)
        .expect("deployment entries")
        .map(|entry| entry.expect("entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(entries, [std::ffi::OsString::from("index.json")]);
    task.abort();
}
