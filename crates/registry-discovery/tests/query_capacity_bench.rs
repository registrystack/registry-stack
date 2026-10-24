// SPDX-License-Identifier: Apache-2.0
//! Manual capacity benchmark over the real Discovery HTTP router.
//!
//! Run this ignored test with an optimized build and one test thread:
//!
//! ```sh
//! cargo test --locked --release -p registry-discovery \
//!   --test query_capacity_bench -- --ignored --nocapture --test-threads=1
//! ```
//!
//! The benchmark uses deterministic public metadata at the compiled service,
//! filter, and result bounds. It prints measurements for operator sizing; it
//! deliberately asserts no wall-clock threshold because host load is not a
//! product invariant.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use registry_discovery::{
    canonical_index_bytes, catalog_revision, mapping_revision, router, Directory, DiscoveryIndex,
    DiscoveryService, OriginSummary, ServiceKind, ServiceRecord, ServiceSearchResponse,
    INDEX_API_VERSION, INDEX_KIND, MAXIMUM_FILTER_VALUES, MAXIMUM_HTTP_BODY_BYTES,
    MAXIMUM_INDEX_BYTES, MAXIMUM_QUERY_BYTES, MAXIMUM_RESULT_RECORDS, MAXIMUM_SERVICES,
    MAXIMUM_VALUES_PER_FIELD,
};
use sha2::{Digest as _, Sha256};
use tokio::sync::Barrier;
use tower::ServiceExt as _;

const SAMPLE_COUNT: usize = 5;
const CONCURRENT_SAMPLE_COUNT: usize = 3;
const CONCURRENCY_LEVELS: [usize; 3] = [1, 4, 8];
const TYPICAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MINIMUM_REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
const PAGE_EVIDENCE_TYPE: &str = "urn:e:page";
const OTHER_EVIDENCE_TYPE: &str = "urn:e:other";
const COMMON_SERVICE_ID: &str = "urn:s:match";
const COMMON_JURISDICTION: &str = "urn:j:match";
const COMMON_PROFILE: &str = "urn:c:match";
const WIDE_VALUES_PER_FILTERED_SERVICE_FIELD: usize = 6;
const DENSE_SERVICE_COUNT: usize = 6_000;

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn filtered_values(prefix: &str, matching: &str, count: usize) -> Vec<String> {
    let mut values = (0..(count - 1))
        .map(|index| {
            if count < 10 {
                format!("urn:{prefix}:{index}")
            } else {
                format!("urn:{prefix}:{index:03}")
            }
        })
        .collect::<Vec<_>>();
    values.push(matching.into());
    values
}

#[derive(Debug)]
struct RequestSample {
    elapsed: Duration,
    status: StatusCode,
    body: Vec<u8>,
}

fn service(
    index: usize,
    origin: &OriginSummary,
    values_per_filtered_field: usize,
) -> ServiceRecord {
    ServiceRecord {
        record_id: format!("r{index:06}"),
        binding_id: format!("urn:b:{index:06}"),
        service_id: COMMON_SERVICE_ID.into(),
        service_kind: ServiceKind::Evidence,
        title: "t".into(),
        description: "d".into(),
        endpoint_url: "https://p.example/e".into(),
        publisher_id: None,
        operator_id: None,
        registry_authority_id: None,
        legal_issuer_id: None,
        technical_provider_id: None,
        jurisdictions: filtered_values("j", COMMON_JURISDICTION, values_per_filtered_field),
        conforms_to: filtered_values("c", COMMON_PROFILE, values_per_filtered_field),
        evidence_type_ids: filtered_values(
            "e",
            if index < MAXIMUM_RESULT_RECORDS {
                PAGE_EVIDENCE_TYPE
            } else {
                OTHER_EVIDENCE_TYPE
            },
            values_per_filtered_field,
        ),
        semantic_class_ids: Vec::new(),
        operation_family_ids: Vec::new(),
        origin_id: origin.origin_id.clone(),
        origin_url: origin.catalog_url.clone(),
        origin_content_digest: origin.content_digest.clone(),
        origin_fetched_at: origin.fetched_at.clone(),
    }
}

fn synthetic_index(service_count: usize, values_per_filtered_field: usize) -> DiscoveryIndex {
    let origin = OriginSummary {
        origin_id: "o".into(),
        catalog_url: "https://o.example/c".into(),
        content_digest: format!("sha256:{}", "1".repeat(64)),
        fetched_at: "2026-10-24T00:00:00Z".into(),
    };
    let services = (0..service_count)
        .map(|index| service(index, &origin, values_per_filtered_field))
        .collect::<Vec<_>>();
    DiscoveryIndex {
        api_version: INDEX_API_VERSION.into(),
        kind: INDEX_KIND.into(),
        catalog_revision: catalog_revision(&services).expect("benchmark services are valid"),
        mapping_revision: mapping_revision(&[]).expect("empty mappings have a revision"),
        built_at: "2026-10-24T00:00:01Z".into(),
        origins: vec![origin],
        services,
        mappings: Vec::new(),
    }
}

fn app(index: DiscoveryIndex, request_timeout: Duration) -> axum::Router {
    let directory = Directory::new(index, MAXIMUM_RESULT_RECORDS, 1)
        .expect("the benchmark index satisfies the runtime contract");
    let service = Arc::new(
        DiscoveryService::new(directory, MAXIMUM_HTTP_BODY_BYTES)
            .expect("the compiled response bound is accepted"),
    );
    router(service, MAXIMUM_QUERY_BYTES, request_timeout)
        .expect("the supported HTTP limits are accepted")
}

fn encode_query(parameters: impl IntoIterator<Item = (&'static str, String)>) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in parameters {
        serializer.append_pair(name, &value);
    }
    serializer.finish()
}

fn maximum_filter_query() -> String {
    let mut parameters = Vec::with_capacity(MAXIMUM_FILTER_VALUES * 4);
    for index in 0..(MAXIMUM_FILTER_VALUES - 1) {
        parameters.push(("serviceId", format!("urn:s:{index:02}")));
    }
    parameters.push(("serviceId", COMMON_SERVICE_ID.into()));
    for index in 0..(MAXIMUM_FILTER_VALUES - 1) {
        parameters.push(("jurisdiction", format!("urn:j:{index:02}")));
    }
    parameters.push(("jurisdiction", COMMON_JURISDICTION.into()));
    for index in 0..(MAXIMUM_FILTER_VALUES - 1) {
        parameters.push(("conformsTo", format!("urn:c:{index:02}")));
    }
    parameters.push(("conformsTo", COMMON_PROFILE.into()));
    for index in 0..MAXIMUM_FILTER_VALUES {
        parameters.push(("evidenceType", format!("urn:n:{index:02}")));
    }
    encode_query(parameters)
}

async fn request(app: axum::Router, query: &str) -> RequestSample {
    let started = Instant::now();
    let response = app
        .oneshot(
            Request::get(format!("/v1/services?{query}"))
                .body(Body::empty())
                .expect("benchmark request"),
        )
        .await
        .expect("Discovery router response");
    let status = response.status();
    let body = to_bytes(response.into_body(), MAXIMUM_HTTP_BODY_BYTES)
        .await
        .expect("bounded Discovery response")
        .to_vec();
    RequestSample {
        elapsed: started.elapsed(),
        status,
        body,
    }
}

fn report(name: &str, samples: &[RequestSample]) {
    let mut microseconds = samples
        .iter()
        .map(|sample| sample.elapsed.as_micros())
        .collect::<Vec<_>>();
    microseconds.sort_unstable();
    let statuses = samples
        .iter()
        .map(|sample| sample.status.as_u16().to_string())
        .collect::<Vec<_>>()
        .join(",");
    eprintln!(
        "discovery/query_capacity name={name} samples={} min_us={} median_us={} max_us={} statuses={statuses} body_bytes={}",
        samples.len(),
        microseconds[0],
        microseconds[microseconds.len() / 2],
        microseconds[microseconds.len() - 1],
        samples[0].body.len(),
    );
}

async fn sample_sequential(app: &axum::Router, query: &str) -> Vec<RequestSample> {
    let mut samples = Vec::with_capacity(SAMPLE_COUNT);
    for _ in 0..SAMPLE_COUNT {
        samples.push(request(app.clone(), query).await);
    }
    samples
}

async fn sample_concurrent(
    app: &axum::Router,
    query: &str,
    concurrency: usize,
) -> Vec<RequestSample> {
    let barrier = Arc::new(Barrier::new(concurrency + 1));
    let mut tasks = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let app = app.clone();
        let query = query.to_owned();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            request(app, &query).await
        }));
    }
    barrier.wait().await;
    let mut samples = Vec::with_capacity(concurrency);
    for task in tasks {
        samples.push(task.await.expect("benchmark request task"));
    }
    samples
}

fn assert_successful_search(sample: &RequestSample, expected_items: usize) {
    assert_eq!(
        sample.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&sample.body)
    );
    let response: ServiceSearchResponse =
        serde_json::from_slice(&sample.body).expect("successful search response");
    assert_eq!(response.items.len(), expected_items);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "manual optimized capacity benchmark; no wall-clock CI threshold"]
async fn query_capacity_at_compiled_bounds() {
    let index = synthetic_index(MAXIMUM_SERVICES, WIDE_VALUES_PER_FILTERED_SERVICE_FIELD);
    let canonical = canonical_index_bytes(&index).expect("maximum-service index fits byte bound");
    assert!(canonical.len() as u64 > (MAXIMUM_INDEX_BYTES * 95) / 100);
    let digest = sha256_hex(&canonical);
    eprintln!(
        "discovery/query_capacity fixture=max_services fixture_sha256={digest} fixture_bytes={} maximum_index_bytes={} services={} result_records={} values_per_filtered_service_field={}",
        canonical.len(),
        MAXIMUM_INDEX_BYTES,
        index.services.len(),
        MAXIMUM_RESULT_RECORDS,
        WIDE_VALUES_PER_FILTERED_SERVICE_FIELD,
    );

    let exact_record_query = encode_query([("recordId", "r099999".into())]);
    let maximum_filter_query = maximum_filter_query();
    let maximum_page_query = encode_query([("evidenceType", PAGE_EVIDENCE_TYPE.into())]);
    assert!(maximum_filter_query.len() <= MAXIMUM_QUERY_BYTES);
    eprintln!(
        "discovery/query_capacity exact_query_sha256={} exact_query_bytes={} maximum_filter_query_sha256={} maximum_filter_query_bytes={} maximum_page_query_sha256={} maximum_page_query_bytes={} filter_values_per_field={}",
        sha256_hex(exact_record_query.as_bytes()),
        exact_record_query.len(),
        sha256_hex(maximum_filter_query.as_bytes()),
        maximum_filter_query.len(),
        sha256_hex(maximum_page_query.as_bytes()),
        maximum_page_query.len(),
        MAXIMUM_FILTER_VALUES,
    );

    let typical = app(index.clone(), TYPICAL_REQUEST_TIMEOUT);
    let exact = sample_sequential(&typical, &exact_record_query).await;
    for sample in &exact {
        assert_successful_search(sample, 1);
    }
    report("exact_record_last_of_100000/timeout_10s", &exact);

    let filters = sample_sequential(&typical, &maximum_filter_query).await;
    for sample in &filters {
        assert_successful_search(sample, 0);
    }
    report("max_filters_no_match/timeout_10s", &filters);

    let page = sample_sequential(&typical, &maximum_page_query).await;
    for sample in &page {
        assert_successful_search(sample, MAXIMUM_RESULT_RECORDS);
    }
    report("max_page_10000/timeout_10s", &page);

    for concurrency in CONCURRENCY_LEVELS {
        let mut batches = Vec::with_capacity(CONCURRENT_SAMPLE_COUNT * concurrency);
        for _ in 0..CONCURRENT_SAMPLE_COUNT {
            batches.extend(sample_concurrent(&typical, &maximum_filter_query, concurrency).await);
        }
        for sample in &batches {
            assert_successful_search(sample, 0);
        }
        report(
            &format!("max_filters_no_match/concurrency_{concurrency}/timeout_10s"),
            &batches,
        );
    }

    let minimum = app(index, MINIMUM_REQUEST_TIMEOUT);
    let minimum_timeout = sample_concurrent(&minimum, &maximum_filter_query, 8).await;
    assert!(minimum_timeout.iter().all(|sample| {
        sample.status == StatusCode::OK || sample.status == StatusCode::SERVICE_UNAVAILABLE
    }));
    report(
        "max_filters_no_match/concurrency_8/timeout_1s",
        &minimum_timeout,
    );

    drop(minimum);
    drop(typical);
    drop(canonical);

    let dense_index = synthetic_index(DENSE_SERVICE_COUNT, MAXIMUM_VALUES_PER_FIELD);
    let dense_canonical =
        canonical_index_bytes(&dense_index).expect("maximum-cardinality index fits byte bound");
    eprintln!(
        "discovery/query_capacity fixture=dense_fields fixture_sha256={} fixture_bytes={} maximum_index_bytes={} services={} values_per_filtered_service_field={}",
        sha256_hex(&dense_canonical),
        dense_canonical.len(),
        MAXIMUM_INDEX_BYTES,
        dense_index.services.len(),
        MAXIMUM_VALUES_PER_FIELD,
    );
    let dense = app(dense_index, MINIMUM_REQUEST_TIMEOUT);
    let dense_sequential = sample_sequential(&dense, &maximum_filter_query).await;
    for sample in &dense_sequential {
        assert_successful_search(sample, 0);
    }
    report(
        "max_cardinality_fields_no_match/timeout_1s",
        &dense_sequential,
    );
    let dense_concurrent = sample_concurrent(&dense, &maximum_filter_query, 8).await;
    assert!(dense_concurrent.iter().all(|sample| {
        sample.status == StatusCode::OK || sample.status == StatusCode::SERVICE_UNAVAILABLE
    }));
    report(
        "max_cardinality_fields_no_match/concurrency_8/timeout_1s",
        &dense_concurrent,
    );
}
