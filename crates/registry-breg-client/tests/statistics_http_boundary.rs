use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use registry_breg_client::{
    BRegIdempotencyKey, BRegReleaseSelection, BRegReleaseStatus, BRegStatisticsFormat,
    BRegWithdrawalReason, BaseRegistryClient, BaseRegistryClientConfig, StaticToken,
};
use tokio::net::TcpListener;
use url::Url;

const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

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
    let publish = method == "POST" && uri.ends_with("/versions?accessProfile=publisher");
    let mut response = Response::new(Body::from(if accept == "text/csv" {
        b"period,periodStart,periodEnd,value,status\r\n2025-01,2025-01-01,2025-02-01,5,rounded\r\n"
            .to_vec()
    } else {
        br#"{"dataset":"enrolments","ok":true}"#.to_vec()
    }));
    *response.status_mut() = if publish {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    response
        .headers_mut()
        .insert("content-type", accept.parse().unwrap());
    response
        .headers_mut()
        .insert("traceparent", TRACEPARENT.parse().unwrap());
    if method == "POST" {
        response
            .headers_mut()
            .insert("cache-control", "no-store".parse().unwrap());
        response
            .headers_mut()
            .insert("vary", "authorization, accept".parse().unwrap());
    }
    response
}

async fn client() -> (BaseRegistryClient, Arc<Mutex<Vec<Captured>>>) {
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
    let token = Arc::new(StaticToken::new("client-token").unwrap());
    let config =
        BaseRegistryClientConfig::new(Url::parse(&format!("http://{address}/tenant")).unwrap())
            .with_token_provider(token);
    (BaseRegistryClient::new(config).unwrap(), captured)
}

#[tokio::test]
async fn statistics_reads_map_every_route_query_and_media_type() {
    let (client, captured) = client().await;
    client
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
    client
        .statistics_release_version(
            "enrolments",
            "2025-01",
            7,
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
    assert_eq!(requests[1].uri, "/tenant/v1/statistics/enrolments/releases?$top=25&$skiptoken=opaque%20cursor&accessProfile=reader");
    assert_eq!(
        requests[2].uri,
        "/tenant/v1/statistics/enrolments/releases/2025-01?status=final&accessProfile=reader"
    );
    assert_eq!(
        requests[3].uri,
        "/tenant/v1/statistics/enrolments/releases/2025-01/versions/7?accessProfile=reader"
    );
    assert_eq!(requests[3].accept, "text/csv");
    assert_eq!(requests[4].uri, "/tenant/v1/statistics/enrolments/releases:series?from=2025-01&to=2025-03&status=any&accessProfile=reader");
}

#[tokio::test]
async fn statistics_mutations_preserve_key_body_and_success_status() {
    let (client, captured) = client().await;
    let key = BRegIdempotencyKey::parse("caller-owned-key-123").unwrap();
    client
        .statistics_publish(
            "enrolments",
            "2025-01",
            BRegReleaseStatus::Final,
            "publisher",
            &key,
        )
        .await
        .unwrap();
    client
        .statistics_withdraw(
            "enrolments",
            "2025-01",
            7,
            BRegWithdrawalReason::DisclosureRisk,
            "publisher",
            &key,
        )
        .await
        .unwrap();
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
    assert_eq!(requests[1].uri, "/tenant/v1/statistics/enrolments/releases/2025-01/versions/7/withdrawal?accessProfile=publisher");
    assert_eq!(requests[1].body, br#"{"reason":"disclosure-risk"}"#);
}

#[tokio::test]
async fn invalid_statistics_arguments_fail_before_token_or_io() {
    let (client, captured) = client().await;
    assert!(client
        .statistics_live("Bad Dataset", None, None, None, BRegStatisticsFormat::Json,)
        .await
        .is_err());
    assert!(client
        .statistics_release_version("enrolments", "2025-01", 0, None, BRegStatisticsFormat::Json,)
        .await
        .is_err());
    assert!(client
        .statistics_live(
            "enrolments",
            Some("2025-01"),
            None,
            None,
            BRegStatisticsFormat::Json,
        )
        .await
        .is_err());
    assert!(captured.lock().unwrap().is_empty());
}
