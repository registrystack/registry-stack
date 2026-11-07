//! Every response carries exactly one canonical W3C `traceparent`, the field
//! Evidence's `wallet-presentation-v1` host protocol requires before it
//! accepts an upstream answer.

mod common;

use axum::http::StatusCode;
use axum_test::{TestResponse, TestServer};
use common::{bearer, Harness, Options};
use registry_platform_httpsec::response_trace_id;
use serde_json::{json, Value};

const INBOUND_TRACE_ID: &str = "0123456789abcdef0123456789abcdef";
const INBOUND: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
const CANARY: &str = "vendor=trace-state-canary";

/// The trace id Evidence would read from `response`, failing on a missing,
/// duplicated or non-canonical field.
fn trace_id_of(context: &str, response: &TestResponse) -> String {
    let headers = response.headers();
    response_trace_id(headers)
        .unwrap_or_else(|error| panic!("{context}: {error}"))
        .as_str()
        .to_owned()
}

fn assert_traced(context: &str, response: &TestResponse) {
    trace_id_of(context, response);
    assert!(
        response.maybe_header("tracestate").is_none(),
        "{context}: tracestate is never answered"
    );
}

#[tokio::test]
async fn every_kind_of_response_carries_a_canonical_traceparent() {
    let harness = Harness::new(&Options {
        session_creation_burst: 1,
        ..Options::default()
    })
    .await;
    let (server, _) = harness.server().await;
    let token = harness.applicant_token("portal", "user-1");

    for path in ["/health", "/ready", "/.well-known/did.json", "/v1/jwks"] {
        let response = server.get(path).await;
        response.assert_status_ok();
        assert_traced(path, &response);
    }

    let created = server
        .post("/v1/sessions")
        .add_header("authorization", bearer(&token))
        .json(&json!({"policy": "national-id"}))
        .await;
    created.assert_status(StatusCode::CREATED);
    assert_traced("201 created", &created);
    let created: Value = created.json();
    let reference = created["reference"].as_str().unwrap();
    let request_id = created["requestUri"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();

    let status = server
        .get(&format!("/v1/sessions/{reference}"))
        .add_header("authorization", bearer(&token))
        .await;
    status.assert_status_ok();
    assert_traced("session status", &status);

    let request_object = server.get(&format!("/v1/requests/{request_id}")).await;
    request_object.assert_status_ok();
    assert_traced("request object", &request_object);

    // 404, in the router's fallback and in a handler.
    let unknown_route = server.get("/nope").await;
    unknown_route.assert_status_not_found();
    assert_traced("404 route", &unknown_route);
    let unknown_request = server.get("/v1/requests/unknown").await;
    unknown_request.assert_status_not_found();
    assert_traced("404 request", &unknown_request);

    // 405 from the method fallback.
    let wrong_method = server.delete("/health").await;
    assert_eq!(wrong_method.status_code(), StatusCode::METHOD_NOT_ALLOWED);
    assert_traced("405", &wrong_method);

    // 401 from a handler.
    let unauthorized = server
        .post("/v1/sessions")
        .json(&json!({"policy": "national-id"}))
        .await;
    unauthorized.assert_status_unauthorized();
    assert_traced("401", &unauthorized);

    // 409 from the Evidence read of a session still waiting for the wallet.
    let issuer = harness.idp.issuer();
    let conflict = server
        .post("/v1/presentations/read")
        .add_header("authorization", bearer(&harness.evidence_token()))
        .json(&json!({
            "reference": reference,
            "principal": {"issuer": issuer, "subject": "user-1"},
        }))
        .await;
    conflict.assert_status(StatusCode::CONFLICT);
    assert_traced("409", &conflict);

    // 413 from the body bound, on the portal route and on the wallet route.
    let oversized = server
        .post("/v1/sessions")
        .add_header("authorization", bearer(&token))
        .text("x".repeat(64 * 1024))
        .await;
    oversized.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
    assert_traced("413 portal", &oversized);
    let oversized_wallet = server
        .post(&format!("/v1/responses/{request_id}"))
        .content_type("application/x-www-form-urlencoded")
        .bytes(format!("response={}", "A".repeat(2 * 1024 * 1024)).into())
        .await;
    oversized_wallet.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
    assert_traced("413 wallet", &oversized_wallet);

    // 400 from a body that is not JSON. No route extracts a body that
    // axum itself would refuse with 415, so that status is not reachable.
    let not_json = server
        .post("/v1/presentations/read")
        .add_header("authorization", bearer(&harness.evidence_token()))
        .content_type("text/plain")
        .text("reference")
        .await;
    not_json.assert_status(StatusCode::BAD_REQUEST);
    assert_traced("400 not json", &not_json);

    // The wallet route answers in the OAuth error shape; it is traced too.
    let wallet_refusal = server
        .post(&format!("/v1/responses/{request_id}"))
        .content_type("application/x-www-form-urlencoded")
        .bytes("response=not-a-jwe".into())
        .await;
    wallet_refusal.assert_status(StatusCode::BAD_REQUEST);
    assert_traced("wallet 400", &wallet_refusal);

    // 429: the session creation budget is one.
    let limited = server
        .post("/v1/sessions")
        .add_header("authorization", bearer(&token))
        .json(&json!({"policy": "national-id"}))
        .await;
    limited.assert_status(StatusCode::TOO_MANY_REQUESTS);
    assert_traced("429", &limited);
}

#[tokio::test]
async fn a_valid_inbound_traceparent_keeps_its_trace_id() {
    let harness = Harness::new(&Options::default()).await;
    let (server, _) = harness.server().await;

    for path in ["/health", "/nope", "/v1/jwks"] {
        let response = server.get(path).add_header("traceparent", INBOUND).await;
        assert_eq!(trace_id_of(path, &response), INBOUND_TRACE_ID, "{path}");
    }
    let unauthorized = server
        .post("/v1/sessions")
        .add_header("traceparent", INBOUND)
        .json(&json!({"policy": "national-id"}))
        .await;
    unauthorized.assert_status_unauthorized();
    assert_eq!(trace_id_of("401", &unauthorized), INBOUND_TRACE_ID);
}

async fn assert_replaced(server: &TestServer, inbound: &[&str], label: &str) {
    let mut request = server.get("/health");
    for value in inbound {
        request = request.add_header("traceparent", *value);
    }
    let response = request.await;
    response.assert_status_ok();
    let trace_id = trace_id_of(label, &response);
    assert_ne!(trace_id, INBOUND_TRACE_ID, "{label}");
    assert_eq!(response.headers().get_all("traceparent").iter().count(), 1);
}

#[tokio::test]
async fn an_invalid_or_duplicated_inbound_traceparent_is_replaced() {
    let harness = Harness::new(&Options::default()).await;
    let (server, _) = harness.server().await;

    let other = "00-fedcba9876543210fedcba9876543210-0123456789abcdef-01";
    for (label, inbound) in [
        ("garbage", vec!["not-a-traceparent"]),
        (
            "uppercase",
            vec!["00-0123456789ABCDEF0123456789ABCDEF-0123456789abcdef-01"],
        ),
        (
            "all-zero trace id",
            vec!["00-00000000000000000000000000000000-0123456789abcdef-01"],
        ),
        (
            "version ff",
            vec!["ff-0123456789abcdef0123456789abcdef-0123456789abcdef-01"],
        ),
        ("duplicated", vec![INBOUND, other]),
    ] {
        assert_replaced(&server, &inbound, label).await;
    }
}

#[tokio::test]
async fn inbound_tracestate_is_never_reflected() {
    let harness = Harness::new(&Options::default()).await;
    let (server, _) = harness.server().await;

    for path in ["/health", "/nope"] {
        let response = server
            .get(path)
            .add_header("traceparent", INBOUND)
            .add_header("tracestate", CANARY)
            .await;
        assert_traced(path, &response);
        assert!(response
            .headers()
            .values()
            .all(|value| !value.to_str().unwrap_or_default().contains(CANARY)));
    }
}
