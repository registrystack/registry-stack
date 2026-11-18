use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use registry_breg_client::{
    BRegIdempotencyKey, BRegProblemCode, BRegProblemFieldPath, BRegProtocolFailure,
    BRegReleaseSelection, BRegReleaseStatus, BRegStatisticsFormat, BRegWithdrawalReason,
    BaseRegistryClient, BaseRegistryClientConfig, BaseRegistryClientError, StaticToken,
};
use registry_platform_httputil::client::{BearerToken, TokenError, TokenProvider};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use url::Url;

const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
// The client returns statistical documents as the server's exact bytes. These
// fixtures carry the served shape: a `measures` list on the dataset and a
// `measure` member on every cell, and a `measure` column in CSV.
const STATISTICS_JSON: &[u8] = br#"{"dataset":{"id":"enrolments","unit":"person","measures":[{"id":"count","type":"count"},{"id":"headcount","type":"count"}],"periodKind":"stock","granularity":"month","population":"People enrolled.","definitionDigest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"cells":[{"period":"2025-01","dimensions":{},"measure":"count","value":5,"status":"rounded"},{"period":"2025-01","dimensions":{},"measure":"headcount","value":null,"status":"suppressed"}]}"#;
const STATISTICS_CSV: &[u8] = b"period,periodStart,periodEnd,measure,value,status\r\n2025-01,2025-01-01,2025-02-01,count,5,rounded\r\n2025-01,2025-01-01,2025-02-01,headcount,,suppressed\r\n";
const MAX_SERVER_ISSUED_CURSOR_BYTES: usize = ((1_usize + 24 + 8 * 1024 + 16) * 4).div_ceil(3);

#[derive(Clone, Debug)]
struct Captured {
    method: String,
    uri: String,
    accept: String,
    idempotency_key: Option<String>,
    body: Vec<u8>,
}

async fn handler(
    State(captured): State<Arc<Mutex<Vec<Captured>>>>,
    request: Request<Body>,
) -> Response<Body> {
    let method = request.method().to_string();
    let uri = request.uri().to_string();
    let accept = request.headers()["accept"].to_str().unwrap().to_owned();
    let idempotency_key = request
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let body = to_bytes(request.into_body(), 8 * 1024)
        .await
        .unwrap()
        .to_vec();
    captured.lock().unwrap().push(Captured {
        method: method.clone(),
        uri: uri.clone(),
        accept: accept.clone(),
        idempotency_key,
        body,
    });
    if uri.contains("/statistics/unavailable/") {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
        return response;
    }
    let problem =
        if uri.contains("/statistics/missing:live") || uri.contains("/statistics/missing:exact") {
            Some((BRegProblemCode::ResourceNotFound, None))
        } else if uri.contains("/statistics/release-refused/") {
            Some((
                BRegProblemCode::StatisticalDatasetReleaseRefused,
                Some(("refusalCode", "period-not-ended")),
            ))
        } else if uri.contains("/statistics/invalid-refusal/") {
            Some((
                BRegProblemCode::StatisticalDatasetReleaseRefused,
                Some(("refusalCode", "response-invented")),
            ))
        } else if uri.contains("/statistics/version-conflict/") {
            Some((BRegProblemCode::StatisticalDatasetVersionConflict, None))
        } else if uri.contains("/statistics/version-withdrawn/") {
            Some((
                BRegProblemCode::StatisticalDatasetVersionWithdrawn,
                Some(("reasonCode", "source-data-error")),
            ))
        } else if uri.contains("/statistics/invalid-reason/") {
            Some((
                BRegProblemCode::StatisticalDatasetVersionWithdrawn,
                Some(("reasonCode", "response-invented")),
            ))
        } else if uri.contains("/statistics/domain-violation:live")
            || uri.contains("/statistics/domain-violation:exact")
        {
            Some((
                BRegProblemCode::StatisticalDatasetDomainViolation,
                Some((
                    "fieldPath",
                    "statisticalDatasets[id=domain-violation].dimensions[id=category]",
                )),
            ))
        } else {
            None
        };
    if let Some((code, extension)) = problem {
        let mut document = json!({
            "type": format!(
                "https://id.registrystack.org/problems/registry-breg/{}",
                code.code().replace('.', "/")
            ),
            "title": match code.status() {
                404 => "Not Found",
                409 => "Conflict",
                410 => "Gone",
                422 => "Unprocessable Entity",
                500 => "Internal Server Error",
                _ => unreachable!(),
            },
            "status": code.status(),
            "detail": code.detail(),
            "code": code.code(),
            "traceId": TRACE_ID,
        });
        if let Some((name, value)) = extension {
            document[name] = json!(value);
        }
        let mut response = Response::new(Body::from(serde_json::to_vec(&document).unwrap()));
        *response.status_mut() = StatusCode::from_u16(code.status()).unwrap();
        response
            .headers_mut()
            .insert("content-type", "application/problem+json".parse().unwrap());
        response
            .headers_mut()
            .insert("cache-control", "no-store".parse().unwrap());
        response
            .headers_mut()
            .insert("traceparent", TRACEPARENT.parse().unwrap());
        return response;
    }

    let publish = method == "POST" && uri.ends_with("/versions?accessProfile=publisher");
    let release_list =
        method == "GET" && (uri.ends_with("/releases") || uri.contains("/releases?"));
    let response_body = if release_list {
        serde_json::to_vec(&json!({
            "items": [],
            "pageInfo": {
                "hasMore": !uri.contains("$skiptoken"),
                "nextCursor": (!uri.contains("$skiptoken"))
                    .then(|| "A".repeat(MAX_SERVER_ISSUED_CURSOR_BYTES)),
            }
        }))
        .unwrap()
    } else if accept == "text/csv" {
        STATISTICS_CSV.to_vec()
    } else {
        STATISTICS_JSON.to_vec()
    };
    let mut response = Response::new(Body::from(response_body.clone()));
    *response.status_mut() = if publish {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    response.headers_mut().insert(
        "content-type",
        if accept == "text/csv" {
            "text/csv; charset=utf-8".parse().unwrap()
        } else {
            accept.parse().unwrap()
        },
    );
    response
        .headers_mut()
        .insert("traceparent", TRACEPARENT.parse().unwrap());
    if !uri.contains("cache-control-missing") {
        response.headers_mut().insert(
            "cache-control",
            if uri.contains("cache-control-wrong") {
                "private".parse().unwrap()
            } else {
                "no-store".parse().unwrap()
            },
        );
    }
    if !uri.contains("vary-missing") {
        response.headers_mut().insert(
            "vary",
            if uri.contains("vary-wrong") {
                "accept".parse().unwrap()
            } else {
                "authorization, accept".parse().unwrap()
            },
        );
    }
    if !release_list && !uri.contains("missing-digest") {
        let digest_body = if uri.contains("bad-digest") {
            b"different bytes".as_slice()
        } else {
            response_body.as_slice()
        };
        let digest = if uri.contains("malformed-digest") {
            "sha-256=:not-base64:".parse().unwrap()
        } else {
            format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(digest_body)))
                .parse()
                .unwrap()
        };
        response.headers_mut().insert("repr-digest", digest);
        if uri.contains("repeated-digest") {
            response.headers_mut().append(
                "repr-digest",
                "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:"
                    .parse()
                    .unwrap(),
            );
        }
    }
    response
}

#[tokio::test]
async fn statistics_releases_accepts_the_complete_server_cursor_envelope() {
    let (client, captured) = client().await;
    let dataset = "d".repeat(64);
    let profile = "p".repeat(64);
    let page = client
        .statistics_releases(&dataset, Some(1), None, Some(&profile))
        .await
        .unwrap();
    let document: serde_json::Value = serde_json::from_slice(page.value.as_bytes()).unwrap();
    let cursor = document["pageInfo"]["nextCursor"].as_str().unwrap();
    assert_eq!(cursor.len(), MAX_SERVER_ISSUED_CURSOR_BYTES);

    client
        .statistics_releases(&dataset, Some(1), Some(cursor), Some(&profile))
        .await
        .unwrap();
    let requests_before_refusal = captured.lock().unwrap().len();
    assert!(client
        .statistics_releases(
            &dataset,
            Some(1),
            Some(&"A".repeat(MAX_SERVER_ISSUED_CURSOR_BYTES + 1)),
            Some(&profile),
        )
        .await
        .is_err());
    assert_eq!(captured.lock().unwrap().len(), requests_before_refusal);
}

async fn client() -> (BaseRegistryClient, Arc<Mutex<Vec<Captured>>>) {
    client_with_provider(Arc::new(StaticToken::new("client-token").unwrap())).await
}

async fn client_with_provider(
    token: Arc<dyn TokenProvider>,
) -> (BaseRegistryClient, Arc<Mutex<Vec<Captured>>>) {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = captured.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(any(handler)).with_state(state),
        )
        .await
        .unwrap();
    });
    let config =
        BaseRegistryClientConfig::new(Url::parse(&format!("http://{address}/tenant")).unwrap())
            .with_token_provider(token);
    (BaseRegistryClient::new(config).unwrap(), captured)
}

#[derive(Debug)]
struct CountingToken(AtomicUsize);

#[async_trait]
impl TokenProvider for CountingToken {
    async fn bearer_token(&self) -> Result<BearerToken, TokenError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        BearerToken::new("client-token")
    }
}

#[tokio::test]
async fn statistics_reads_map_every_route_query_and_media_type() {
    let (client, captured) = client().await;
    let live = client
        .statistics_live(
            "enrolments",
            Some("2025-01"),
            Some("2025-03"),
            Some("analyst"),
            BRegStatisticsFormat::Csv,
        )
        .await
        .unwrap();
    client
        .statistics_releases(
            "enrolments",
            Some(25),
            Some("opaque cursor"),
            Some("reader"),
        )
        .await
        .unwrap();
    client
        .statistics_latest_release(
            "enrolments",
            "2025-01",
            BRegReleaseSelection::Final,
            Some("reader"),
            BRegStatisticsFormat::Json,
        )
        .await
        .unwrap();
    let version = client
        .statistics_release_version(
            "enrolments",
            "2025-01",
            i64::MAX as u64,
            Some("reader"),
            BRegStatisticsFormat::Csv,
        )
        .await
        .unwrap();
    client
        .statistics_release_series(
            "enrolments",
            "2025-01",
            "2025-03",
            BRegReleaseSelection::Any,
            Some("reader"),
            BRegStatisticsFormat::Json,
        )
        .await
        .unwrap();

    let requests = captured.lock().unwrap();
    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].uri,
        "/tenant/v1/statistics/enrolments:live?from=2025-01&to=2025-03&accessProfile=analyst"
    );
    assert_eq!(requests[0].accept, "text/csv");
    assert_eq!(live.value.media_type(), "text/csv; charset=utf-8");
    assert!(live.value.representation_digest().is_some());
    assert_eq!(requests[1].uri, "/tenant/v1/statistics/enrolments/releases?$top=25&$skiptoken=opaque%20cursor&accessProfile=reader");
    assert_eq!(
        requests[2].uri,
        "/tenant/v1/statistics/enrolments/releases/2025-01?status=final&accessProfile=reader"
    );
    assert_eq!(
        requests[3].uri,
        format!(
            "/tenant/v1/statistics/enrolments/releases/2025-01/versions/{}?accessProfile=reader",
            i64::MAX
        )
    );
    assert_eq!(requests[3].accept, "text/csv");
    assert_eq!(version.value.media_type(), "text/csv; charset=utf-8");
    assert!(version.value.representation_digest().is_some());
    assert_eq!(requests[4].uri, "/tenant/v1/statistics/enrolments/releases:series?from=2025-01&to=2025-03&accessProfile=reader");
}

#[tokio::test]
async fn statistics_documents_are_returned_as_the_exact_served_bytes() {
    let (client, _captured) = client().await;
    let json = client
        .statistics_live("enrolments", None, None, None, BRegStatisticsFormat::Json)
        .await
        .unwrap();
    assert_eq!(json.value.as_bytes(), STATISTICS_JSON);
    let document: serde_json::Value = serde_json::from_slice(json.value.as_bytes()).unwrap();
    assert!(document["dataset"].get("measure").is_none());
    assert_eq!(document["dataset"]["measures"].as_array().unwrap().len(), 2);
    let cells = document["cells"].as_array().unwrap();
    assert_eq!(cells[0]["measure"], "count");
    assert_eq!(cells[1]["measure"], "headcount");
    let csv = client
        .statistics_live("enrolments", None, None, None, BRegStatisticsFormat::Csv)
        .await
        .unwrap();
    assert_eq!(csv.value.as_bytes(), STATISTICS_CSV);
}

#[tokio::test]
async fn statistics_exact_maps_route_both_periods_profile_and_media_type() {
    let (client, captured) = client().await;
    let json = client
        .statistics_exact(
            "enrolments",
            "2025-01",
            "2025-03",
            None,
            BRegStatisticsFormat::Json,
        )
        .await
        .unwrap();
    assert_eq!(json.value.as_bytes(), STATISTICS_JSON);
    let csv = client
        .statistics_exact(
            "enrolments",
            "2025-01",
            "2025-03",
            Some("analyst"),
            BRegStatisticsFormat::Csv,
        )
        .await
        .unwrap();
    assert_eq!(csv.value.as_bytes(), STATISTICS_CSV);

    let requests = captured.lock().unwrap();
    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].uri,
        "/tenant/v1/statistics/enrolments:exact?from=2025-01&to=2025-03"
    );
    assert_eq!(requests[0].accept, "application/json");
    assert_eq!(
        requests[1].uri,
        "/tenant/v1/statistics/enrolments:exact?from=2025-01&to=2025-03&accessProfile=analyst"
    );
    assert_eq!(requests[1].accept, "text/csv");
}

#[tokio::test]
async fn statistics_exact_keeps_concealment_and_domain_problem_details() {
    let (client, _) = client().await;
    let missing = client
        .statistics_exact(
            "missing",
            "2025-01",
            "2025-03",
            None,
            BRegStatisticsFormat::Json,
        )
        .await
        .unwrap_err();
    assert_eq!(missing.kind(), "not-found");
    assert_eq!(
        missing.problem_code(),
        Some(BRegProblemCode::ResourceNotFound)
    );
    let violation = client
        .statistics_exact(
            "domain-violation",
            "2025-01",
            "2025-03",
            Some("reader"),
            BRegStatisticsFormat::Json,
        )
        .await
        .unwrap_err();
    assert_eq!(
        violation.problem_code(),
        Some(BRegProblemCode::StatisticalDatasetDomainViolation)
    );
}

#[tokio::test]
async fn invalid_statistics_exact_arguments_fail_before_token_or_io() {
    let token = Arc::new(CountingToken(AtomicUsize::new(0)));
    let (client, captured) = client_with_provider(token.clone()).await;
    for (dataset, from, to, profile) in [
        ("Bad Dataset", "2025-01", "2025-02", None),
        ("enrolments", "2025-99", "2025-02", None),
        ("enrolments", "2025-01", "2025€", None),
        ("enrolments", "9999", "9999", None),
        ("enrolments", "", "2025-02", None),
        ("enrolments", "2025-01", "2025-02", Some("bad profile")),
    ] {
        assert!(client
            .statistics_exact(dataset, from, to, profile, BRegStatisticsFormat::Json)
            .await
            .is_err());
    }
    assert_eq!(token.0.load(Ordering::SeqCst), 0);
    assert!(captured.lock().unwrap().is_empty());
}

#[tokio::test]
async fn statistics_live_emits_each_optional_period_bound_independently() {
    let (client, captured) = client().await;
    client
        .statistics_live(
            "enrolments",
            Some("2025-01"),
            None,
            None,
            BRegStatisticsFormat::Json,
        )
        .await
        .unwrap();
    client
        .statistics_live(
            "enrolments",
            None,
            Some("2025-03"),
            None,
            BRegStatisticsFormat::Json,
        )
        .await
        .unwrap();

    let requests = captured.lock().unwrap();
    assert_eq!(
        requests[0].uri,
        "/tenant/v1/statistics/enrolments:live?from=2025-01"
    );
    assert_eq!(
        requests[1].uri,
        "/tenant/v1/statistics/enrolments:live?to=2025-03"
    );
}

#[tokio::test]
async fn statistics_period_codes_admit_each_canonical_calendar_form_and_upper_bound() {
    let (client, captured) = client().await;
    client
        .statistics_live(
            "enrolments",
            Some("0001"),
            Some("9998"),
            None,
            BRegStatisticsFormat::Json,
        )
        .await
        .unwrap();
    client
        .statistics_latest_release(
            "enrolments",
            "9999-Q3",
            BRegReleaseSelection::Any,
            None,
            BRegStatisticsFormat::Json,
        )
        .await
        .unwrap();
    client
        .statistics_release_version("enrolments", "9999-11", 1, None, BRegStatisticsFormat::Json)
        .await
        .unwrap();
    client
        .statistics_release_series(
            "enrolments",
            "2024-02-29",
            "9999-12-30",
            BRegReleaseSelection::Any,
            None,
            BRegStatisticsFormat::Json,
        )
        .await
        .unwrap();

    let requests = captured.lock().unwrap();
    assert_eq!(
        requests[0].uri,
        "/tenant/v1/statistics/enrolments:live?from=0001&to=9998"
    );
    assert_eq!(
        requests[1].uri,
        "/tenant/v1/statistics/enrolments/releases/9999-Q3"
    );
    assert_eq!(
        requests[2].uri,
        "/tenant/v1/statistics/enrolments/releases/9999-11/versions/1"
    );
    assert_eq!(
        requests[3].uri,
        "/tenant/v1/statistics/enrolments/releases:series?from=2024-02-29&to=9999-12-30"
    );
}

#[tokio::test]
async fn statistics_problems_keep_concealment_and_closed_domain_details() {
    let (client, _) = client().await;
    let missing = client
        .statistics_live("missing", None, None, None, BRegStatisticsFormat::Json)
        .await
        .unwrap_err();
    assert_eq!(missing.kind(), "not-found");
    assert_eq!(
        missing.problem_code(),
        Some(BRegProblemCode::ResourceNotFound)
    );

    let key = BRegIdempotencyKey::parse("problem-key").unwrap();
    let release_refused = client
        .statistics_publish(
            "release-refused",
            "2025-01",
            BRegReleaseStatus::Final,
            "publisher",
            &key,
        )
        .await
        .unwrap_err();
    assert_eq!(
        release_refused.problem_code(),
        Some(BRegProblemCode::StatisticalDatasetReleaseRefused)
    );
    assert_eq!(
        release_refused.refusal_code().map(|value| value.as_str()),
        Some("period-not-ended")
    );

    let version_conflict = client
        .statistics_publish(
            "version-conflict",
            "2025-01",
            BRegReleaseStatus::Final,
            "publisher",
            &key,
        )
        .await
        .unwrap_err();
    assert_eq!(
        version_conflict.problem_code(),
        Some(BRegProblemCode::StatisticalDatasetVersionConflict)
    );

    let withdrawn = client
        .statistics_release_version(
            "version-withdrawn",
            "2025-01",
            7,
            Some("reader"),
            BRegStatisticsFormat::Json,
        )
        .await
        .unwrap_err();
    assert_eq!(
        withdrawn.problem_code(),
        Some(BRegProblemCode::StatisticalDatasetVersionWithdrawn)
    );
    assert_eq!(withdrawn.reason_code(), Some("source-data-error"));
    assert!(withdrawn.refusal_code().is_none());

    let domain = client
        .statistics_live(
            "domain-violation",
            None,
            None,
            Some("reader"),
            BRegStatisticsFormat::Json,
        )
        .await
        .unwrap_err();
    assert_eq!(
        domain.problem_code(),
        Some(BRegProblemCode::StatisticalDatasetDomainViolation)
    );
    assert_eq!(
        domain.field_path().map(BRegProblemFieldPath::as_str),
        Some("statisticalDatasets[id=domain-violation].dimensions[id=category]")
    );
    let rendered = format!("{domain:?}: {domain}");
    assert!(!rendered.contains("domain-violation"));
    assert!(!rendered.contains("category"));

    for error in [
        client
            .statistics_publish(
                "invalid-refusal",
                "2025-01",
                BRegReleaseStatus::Final,
                "publisher",
                &key,
            )
            .await
            .unwrap_err(),
        client
            .statistics_release_version(
                "invalid-reason",
                "2025-01",
                7,
                Some("reader"),
                BRegStatisticsFormat::Json,
            )
            .await
            .unwrap_err(),
    ] {
        assert!(matches!(
            error,
            BaseRegistryClientError::Protocol {
                failure: BRegProtocolFailure::Problem,
                ..
            }
        ));
    }
}

#[tokio::test]
async fn statistics_refuses_missing_repeated_or_mismatched_representation_digests() {
    // The ordinary fixture proves the accepted digest and exact CSV media type.
    let (client, _) = client().await;
    let accepted = client
        .statistics_live("enrolments", None, None, None, BRegStatisticsFormat::Csv)
        .await
        .unwrap();
    assert_eq!(accepted.value.media_type(), "text/csv; charset=utf-8");
    let digest = accepted.value.representation_digest().unwrap();
    assert!(digest.as_str().starts_with("sha-256=:"));

    for dataset in [
        "missing-digest",
        "bad-digest",
        "repeated-digest",
        "malformed-digest",
    ] {
        let error = client
            .statistics_live(dataset, None, None, None, BRegStatisticsFormat::Json)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            BaseRegistryClientError::Protocol {
                failure: BRegProtocolFailure::RepresentationDigest,
                ..
            }
        ));
    }
}

#[tokio::test]
async fn statistics_reads_require_the_exact_private_cache_policy() {
    let (client, _) = client().await;
    for error in [
        client
            .statistics_live(
                "cache-control-missing",
                None,
                None,
                None,
                BRegStatisticsFormat::Json,
            )
            .await
            .unwrap_err(),
        client
            .statistics_live("vary-wrong", None, None, None, BRegStatisticsFormat::Csv)
            .await
            .unwrap_err(),
        client
            .statistics_releases("vary-missing", Some(10), None, None)
            .await
            .unwrap_err(),
        client
            .statistics_releases("cache-control-wrong", Some(10), None, None)
            .await
            .unwrap_err(),
    ] {
        assert!(matches!(
            error,
            BaseRegistryClientError::Protocol {
                failure: BRegProtocolFailure::CachePolicy,
                ..
            }
        ));
    }
}

#[tokio::test]
async fn statistics_mutations_preserve_key_body_and_success_status() {
    let (client, captured) = client().await;
    let key = BRegIdempotencyKey::parse("caller-owned-key-123").unwrap();
    let published = client
        .statistics_publish(
            "enrolments",
            "2025-01",
            BRegReleaseStatus::Final,
            "publisher",
            &key,
        )
        .await
        .unwrap();
    let withdrawn = client
        .statistics_withdraw(
            "enrolments",
            "2025-01",
            i64::MAX as u64,
            BRegWithdrawalReason::DisclosureRisk,
            "publisher",
            &key,
        )
        .await
        .unwrap();
    assert!(published.value.representation_digest().is_some());
    assert!(withdrawn.value.representation_digest().is_some());
    let requests = captured.lock().unwrap();
    assert_eq!(requests[0].method, "POST");
    assert_eq!(
        requests[0].uri,
        "/tenant/v1/statistics/enrolments/releases/2025-01/versions?accessProfile=publisher"
    );
    assert_eq!(
        requests[0].idempotency_key.as_deref(),
        Some("caller-owned-key-123")
    );
    assert_eq!(requests[0].body, br#"{"status":"final"}"#);
    assert_eq!(
        requests[1].uri,
        format!(
            "/tenant/v1/statistics/enrolments/releases/2025-01/versions/{}/withdrawal?accessProfile=publisher",
            i64::MAX
        )
    );
    assert_eq!(requests[1].body, br#"{"reason":"disclosure-risk"}"#);
}

#[tokio::test]
async fn statistics_release_dry_run_posts_the_publish_body_without_a_key() {
    let (client, captured) = client().await;
    let dry_run = client
        .statistics_release_dry_run(
            "enrolments",
            "2025-01",
            BRegReleaseStatus::Provisional,
            "publisher",
        )
        .await
        .unwrap();
    assert_eq!(dry_run.value.media_type(), "application/json");
    assert!(!dry_run.value.as_bytes().is_empty());
    let requests = captured.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(
        requests[0].uri,
        "/tenant/v1/statistics/enrolments/releases/2025-01/versions:dry-run?accessProfile=publisher"
    );
    assert_eq!(requests[0].accept, "application/json");
    assert_eq!(requests[0].idempotency_key, None);
    assert_eq!(requests[0].body, br#"{"status":"provisional"}"#);
}

#[tokio::test]
async fn statistics_release_dry_run_maps_a_release_refusal_like_publish() {
    let (client, captured) = client().await;
    let refused = client
        .statistics_release_dry_run(
            "release-refused",
            "2025-01",
            BRegReleaseStatus::Final,
            "publisher",
        )
        .await
        .unwrap_err();
    assert_eq!(
        refused.problem_code(),
        Some(BRegProblemCode::StatisticalDatasetReleaseRefused)
    );
    assert_eq!(
        refused.refusal_code().map(|value| value.as_str()),
        Some("period-not-ended")
    );
    // The exchange is sent once: a dry run is never resent.
    assert_eq!(captured.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn statistics_release_dry_run_refuses_invalid_arguments_before_token_or_io() {
    let token = Arc::new(CountingToken(AtomicUsize::new(0)));
    let (client, captured) = client_with_provider(token.clone()).await;
    for (dataset, period, profile) in [
        ("Bad Dataset", "2025-01", "publisher"),
        ("enrolments", "2023-02-29", "publisher"),
        ("enrolments", "2025-01", "bad profile"),
    ] {
        assert!(client
            .statistics_release_dry_run(dataset, period, BRegReleaseStatus::Final, profile)
            .await
            .is_err());
    }
    assert_eq!(token.0.load(Ordering::SeqCst), 0);
    assert!(captured.lock().unwrap().is_empty());
}

#[tokio::test]
async fn statistics_release_dry_run_requires_a_matching_representation_digest() {
    let (client, _) = client().await;
    for dataset in [
        "missing-digest",
        "bad-digest",
        "malformed-digest",
        "repeated-digest",
    ] {
        let error = client
            .statistics_release_dry_run(dataset, "2025-01", BRegReleaseStatus::Final, "publisher")
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                BaseRegistryClientError::Protocol {
                    failure: BRegProtocolFailure::RepresentationDigest,
                    ..
                }
            ),
            "{dataset}: {error:?}"
        );
    }
    let accepted = client
        .statistics_release_dry_run(
            "enrolments",
            "2025-01",
            BRegReleaseStatus::Final,
            "publisher",
        )
        .await
        .unwrap();
    assert!(accepted.value.representation_digest().is_some());
}

#[tokio::test]
async fn statistics_release_dry_run_is_sent_once_after_a_503() {
    let (client, captured) = client().await;
    let error = client
        .statistics_release_dry_run(
            "unavailable",
            "2025-01",
            BRegReleaseStatus::Final,
            "publisher",
        )
        .await
        .unwrap_err();
    drop(error);
    assert_eq!(captured.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn statistics_release_dry_run_is_sent_once_after_a_connection_reset() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    let config =
        BaseRegistryClientConfig::new(Url::parse(&format!("http://{address}/tenant")).unwrap());
    let client = BaseRegistryClient::new(config).unwrap();
    assert!(client
        .statistics_release_dry_run(
            "enrolments",
            "2025-01",
            BRegReleaseStatus::Final,
            "publisher"
        )
        .await
        .is_err());
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn statistics_mutations_require_matching_representation_digests() {
    let (client, _) = client().await;
    let key = BRegIdempotencyKey::parse("caller-owned-key-123").unwrap();
    for error in [
        client
            .statistics_publish(
                "missing-digest",
                "2025-01",
                BRegReleaseStatus::Final,
                "publisher",
                &key,
            )
            .await
            .unwrap_err(),
        client
            .statistics_withdraw(
                "bad-digest",
                "2025-01",
                7,
                BRegWithdrawalReason::SourceDataError,
                "publisher",
                &key,
            )
            .await
            .unwrap_err(),
    ] {
        assert!(matches!(
            error,
            BaseRegistryClientError::Protocol {
                failure: BRegProtocolFailure::RepresentationDigest,
                ..
            }
        ));
    }
}

#[tokio::test]
async fn invalid_statistics_arguments_fail_before_token_or_io() {
    let token = Arc::new(CountingToken(AtomicUsize::new(0)));
    let (client, captured) = client_with_provider(token.clone()).await;
    let key = BRegIdempotencyKey::parse("caller-owned-key-123").unwrap();
    assert!(client
        .statistics_live("Bad Dataset", None, None, None, BRegStatisticsFormat::Json,)
        .await
        .is_err());
    assert!(client
        .statistics_live(
            "enrolments",
            Some("2025-99"),
            None,
            None,
            BRegStatisticsFormat::Json,
        )
        .await
        .is_err());
    assert!(client
        .statistics_live(
            "enrolments",
            Some("9999"),
            None,
            None,
            BRegStatisticsFormat::Json,
        )
        .await
        .is_err());
    assert!(client
        .statistics_live(
            "enrolments",
            Some("2025€"),
            None,
            None,
            BRegStatisticsFormat::Json,
        )
        .await
        .is_err());
    assert!(client
        .statistics_latest_release(
            "enrolments",
            "----",
            BRegReleaseSelection::Any,
            None,
            BRegStatisticsFormat::Json,
        )
        .await
        .is_err());
    assert!(client
        .statistics_latest_release(
            "enrolments",
            "9999-Q4",
            BRegReleaseSelection::Any,
            None,
            BRegStatisticsFormat::Json,
        )
        .await
        .is_err());
    assert!(client
        .statistics_release_version("enrolments", "0000", 1, None, BRegStatisticsFormat::Json,)
        .await
        .is_err());
    assert!(client
        .statistics_release_version("enrolments", "9999-12", 1, None, BRegStatisticsFormat::Json,)
        .await
        .is_err());
    assert!(client
        .statistics_release_series(
            "enrolments",
            "2024-Q0",
            "2024-Q1",
            BRegReleaseSelection::Any,
            None,
            BRegStatisticsFormat::Json,
        )
        .await
        .is_err());
    assert!(client
        .statistics_release_series(
            "enrolments",
            "9999-12-30",
            "9999-12-31",
            BRegReleaseSelection::Any,
            None,
            BRegStatisticsFormat::Json,
        )
        .await
        .is_err());
    assert!(client
        .statistics_publish(
            "enrolments",
            "2023-02-29",
            BRegReleaseStatus::Final,
            "publisher",
            &key,
        )
        .await
        .is_err());
    assert!(client
        .statistics_withdraw(
            "enrolments",
            "2025-Q5",
            1,
            BRegWithdrawalReason::DisclosureRisk,
            "publisher",
            &key,
        )
        .await
        .is_err());
    assert!(client
        .statistics_release_version("enrolments", "2025-01", 0, None, BRegStatisticsFormat::Json,)
        .await
        .is_err());
    assert!(client
        .statistics_release_version(
            "enrolments",
            "2025-01",
            i64::MAX as u64 + 1,
            None,
            BRegStatisticsFormat::Json,
        )
        .await
        .is_err());
    assert!(client
        .statistics_withdraw(
            "enrolments",
            "2025-01",
            i64::MAX as u64 + 1,
            BRegWithdrawalReason::DisclosureRisk,
            "publisher",
            &key,
        )
        .await
        .is_err());
    assert!(client
        .statistics_releases("enrolments", Some(101), None, None)
        .await
        .is_err());
    assert_eq!(token.0.load(Ordering::SeqCst), 0);
    assert!(captured.lock().unwrap().is_empty());
}
