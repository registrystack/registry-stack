// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use registry_payment_client::{
    BearerToken, CollectionState, PaymentClient, PaymentClientConfig, PaymentClientError,
    PaymentProblemCode, PaymentProtocolFailure, ReadCollection, RecordReceipt, RequestCollection,
};
use serde_json::json;
use url::Url;
use uuid::Uuid;

const TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
const TRACE_ID: &str = "0123456789abcdef0123456789abcdef";
const KEY: &str = "service-attempt-1";

#[derive(Clone, Debug)]
struct Captured {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
}

#[derive(Clone)]
struct Fixture {
    observations: Arc<Mutex<Vec<Captured>>>,
    status: StatusCode,
    content_type: &'static str,
    body: String,
}

async fn answer(
    State(fixture): State<Fixture>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    fixture
        .observations
        .lock()
        .expect("observations")
        .push(Captured {
            method,
            uri,
            headers,
            body,
        });
    (
        fixture.status,
        [
            ("content-type", fixture.content_type),
            ("traceparent", TRACEPARENT),
        ],
        fixture.body,
    )
}

async fn serve(status: StatusCode, body: serde_json::Value) -> (PaymentClient, Fixture) {
    serve_text(status, body.to_string()).await
}

async fn serve_text(status: StatusCode, body: String) -> (PaymentClient, Fixture) {
    serve_fixture(status, "application/json", body).await
}

async fn serve_problem(status: StatusCode, code: PaymentProblemCode) -> (PaymentClient, Fixture) {
    serve_fixture(
        status,
        "application/problem+json",
        code_problem(code).to_string(),
    )
    .await
}

async fn serve_fixture(
    status: StatusCode,
    content_type: &'static str,
    body: String,
) -> (PaymentClient, Fixture) {
    let fixture = Fixture {
        observations: Arc::new(Mutex::new(Vec::new())),
        status,
        content_type,
        body,
    };
    let app = Router::new()
        .route(
            "/adapter/v1/payments/bill-payments/collections",
            post(answer),
        )
        .route(
            "/adapter/v1/payments/bill-payments/collections/receipt",
            post(answer),
        )
        .route(
            "/adapter/v1/payments/bill-payments/collections/{collection_id}",
            get(answer),
        )
        .route(
            "/adapter/v1/payments/bill-payments/collections/{collection_id}/record-receipt",
            post(answer),
        )
        .with_state(fixture.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fixture listener");
    let address = listener.local_addr().expect("fixture address");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });
    let config = PaymentClientConfig::new(
        Url::parse(&format!("http://{address}/adapter")).expect("fixture URL"),
        "bill-payments",
    );
    (PaymentClient::new(config).expect("payment client"), fixture)
}

fn code_problem(code: PaymentProblemCode) -> serde_json::Value {
    json!({
        "type": code.type_uri(),
        "title": code.as_str(),
        "status": code.status(),
        "code": code
    })
}

fn token() -> BearerToken {
    BearerToken::new("synthetic-payment-token").expect("fixture token")
}

fn acceptance(collection_id: Uuid, bill_id: Uuid) -> serde_json::Value {
    json!({
        "collectionId": collection_id,
        "billId": bill_id,
        "billVersion": 3,
        "bindingRevision": "sha256:synthetic-binding",
        "simulation": true
    })
}

fn status(collection_id: Uuid, bill_id: Uuid, state: &str) -> serde_json::Value {
    let mut value = json!({
        "collectionId": collection_id,
        "billId": bill_id,
        "billVersion": 3,
        "bindingRevision": "sha256:synthetic-binding",
        "simulation": true,
        "state": state,
        "money": {"value": "25.00", "currency": "USD", "scale": 2}
    });
    if state == "confirmed" {
        value["providerReference"] = json!("SIM-confirmed-1");
    }
    if state == "failed" {
        value["failureReason"] = json!("payer-rejected");
    }
    value
}

#[tokio::test]
async fn collection_request_sends_only_authoritative_bill_identity() {
    let collection_id = Uuid::new_v4();
    let bill_id = Uuid::new_v4();
    let (client, fixture) = serve(StatusCode::ACCEPTED, acceptance(collection_id, bill_id)).await;
    let request = RequestCollection {
        bill_id,
        bill_version: 3,
    };

    let completed = client
        .request_collection(&token(), KEY, &request)
        .await
        .expect("accepted collection");

    assert_eq!(completed.trace_id, TRACE_ID);
    assert_eq!(completed.value.collection_id, collection_id);
    let observations = fixture.observations.lock().expect("observations");
    assert_eq!(observations.len(), 1);
    let sent = &observations[0];
    assert_eq!(sent.method, Method::POST);
    assert_eq!(
        sent.uri.path(),
        "/adapter/v1/payments/bill-payments/collections"
    );
    assert_eq!(sent.headers["idempotency-key"], KEY);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&sent.body).unwrap(),
        json!({"billId": bill_id, "billVersion": 3})
    );
}

#[tokio::test]
async fn original_request_receipt_is_a_read_with_the_exact_key_and_body() {
    let collection_id = Uuid::new_v4();
    let bill_id = Uuid::new_v4();
    let (client, fixture) = serve(StatusCode::OK, acceptance(collection_id, bill_id)).await;
    let request = RequestCollection {
        bill_id,
        bill_version: 3,
    };

    client
        .collection_receipt(&token(), KEY, &request)
        .await
        .expect("retained original acceptance");

    let observations = fixture.observations.lock().expect("observations");
    assert_eq!(observations.len(), 1);
    assert_eq!(
        observations[0].uri.path(),
        "/adapter/v1/payments/bill-payments/collections/receipt"
    );
    assert_eq!(observations[0].headers["idempotency-key"], KEY);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&observations[0].body).unwrap(),
        json!({"billId": bill_id, "billVersion": 3})
    );
}

#[tokio::test]
async fn collection_reads_preserve_pending_unknown_and_confirmed_as_distinct_states() {
    for (wire, expected) in [
        ("pending", CollectionState::Pending),
        ("unknown", CollectionState::Unknown),
        ("confirmed", CollectionState::Confirmed),
    ] {
        let collection_id = Uuid::new_v4();
        let bill_id = Uuid::new_v4();
        let (client, _) = serve(StatusCode::OK, status(collection_id, bill_id, wire)).await;
        let completed = client
            .read_collection(&token(), &ReadCollection { collection_id })
            .await
            .expect("authoritative collection observation");
        assert_eq!(completed.value.state, expected);
    }
}

#[tokio::test]
async fn a_response_for_another_command_or_collection_is_a_protocol_failure() {
    let collection_id = Uuid::new_v4();
    let requested_bill = Uuid::new_v4();
    let other_bill = Uuid::new_v4();
    let (client, _) = serve(StatusCode::ACCEPTED, acceptance(collection_id, other_bill)).await;
    let error = client
        .request_collection(
            &token(),
            KEY,
            &RequestCollection {
                bill_id: requested_bill,
                bill_version: 3,
            },
        )
        .await
        .expect_err("another bill cannot settle this command");
    assert!(matches!(
        &error,
        PaymentClientError::Protocol {
            failure: PaymentProtocolFailure::Correlation,
            ..
        }
    ));

    let requested_collection = Uuid::new_v4();
    let (client, _) = serve(
        StatusCode::OK,
        status(collection_id, requested_bill, "pending"),
    )
    .await;
    let error = client
        .read_collection(
            &token(),
            &ReadCollection {
                collection_id: requested_collection,
            },
        )
        .await
        .expect_err("another collection cannot settle this observation");
    assert!(matches!(
        &error,
        PaymentClientError::Protocol {
            failure: PaymentProtocolFailure::Correlation,
            ..
        }
    ));
}

#[tokio::test]
async fn malformed_or_duplicate_payment_evidence_fails_visibly() {
    let collection_id = Uuid::new_v4();
    let bill_id = Uuid::new_v4();
    let malformed = status(collection_id, bill_id, "pending")
        .to_string()
        .replace("\"state\":\"pending\"", "\"state\":\"confirmed\"");
    let (client, _) = serve_text(StatusCode::OK, malformed).await;
    assert!(matches!(
        client
            .read_collection(&token(), &ReadCollection { collection_id })
            .await,
        Err(PaymentClientError::Protocol {
            failure: PaymentProtocolFailure::Body,
            ..
        })
    ));

    let duplicated = acceptance(collection_id, bill_id).to_string().replacen(
        "{",
        &format!("{{\"billId\":\"{bill_id}\","),
        1,
    );
    let (client, _) = serve_text(StatusCode::ACCEPTED, duplicated).await;
    assert!(matches!(
        client
            .request_collection(
                &token(),
                KEY,
                &RequestCollection {
                    bill_id,
                    bill_version: 3
                }
            )
            .await,
        Err(PaymentClientError::Protocol {
            failure: PaymentProtocolFailure::Body,
            ..
        })
    ));
}

#[tokio::test]
async fn record_receipt_requires_confirmed_exactly_correlated_evidence() {
    let collection_id = Uuid::new_v4();
    let bill_id = Uuid::new_v4();
    let receipt = json!({
        "collectionId": collection_id,
        "billId": bill_id,
        "billVersion": 3,
        "bindingRevision": "sha256:synthetic-binding",
        "simulation": true,
        "money": {"value": "25.00", "currency": "USD", "scale": 2},
        "providerReference": "SIM-confirmed-1",
        "receiptId": "bill-receipt-1"
    });
    let (client, fixture) = serve(StatusCode::OK, receipt).await;
    let completed = client
        .record_receipt(&token(), KEY, &RecordReceipt { collection_id })
        .await
        .expect("recorded receipt");
    assert_eq!(completed.value.collection_id, collection_id);
    let observations = fixture.observations.lock().expect("observations");
    assert_eq!(observations[0].headers["idempotency-key"], KEY);
    assert_eq!(
        observations[0].uri.path(),
        format!("/adapter/v1/payments/bill-payments/collections/{collection_id}/record-receipt")
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&observations[0].body).unwrap(),
        json!({"collectionId": collection_id})
    );
}

#[tokio::test]
async fn typed_problem_codes_preserve_authentication_and_uncertainty_semantics() {
    let bill_id = Uuid::new_v4();
    let request = RequestCollection {
        bill_id,
        bill_version: 3,
    };
    let (client, _) = serve_problem(
        StatusCode::UNAUTHORIZED,
        PaymentProblemCode::Unauthenticated,
    )
    .await;
    let error = client
        .request_collection(&token(), KEY, &request)
        .await
        .expect_err("authentication failure");
    assert!(matches!(
        &error,
        PaymentClientError::Problem {
            status: 401,
            code: PaymentProblemCode::Unauthenticated,
            ..
        }
    ));
    assert!(!error.is_outcome_unknown());

    let (client, _) = serve_problem(
        StatusCode::SERVICE_UNAVAILABLE,
        PaymentProblemCode::OutcomeUnknown,
    )
    .await;
    let error = client
        .request_collection(&token(), KEY, &request)
        .await
        .expect_err("provider outcome stays unknown");
    assert!(matches!(
        &error,
        PaymentClientError::Problem {
            code: PaymentProblemCode::OutcomeUnknown,
            ..
        }
    ));
    assert!(error.is_outcome_unknown());

    let (client, _) = serve_problem(
        StatusCode::BAD_GATEWAY,
        PaymentProblemCode::ProviderProtocol,
    )
    .await;
    let error = client
        .request_collection(&token(), KEY, &request)
        .await
        .expect_err("malformed provider acknowledgement stays unknown");
    assert!(matches!(
        &error,
        PaymentClientError::Problem {
            code: PaymentProblemCode::ProviderProtocol,
            ..
        }
    ));
    assert!(error.is_outcome_unknown());

    let (client, _) = serve_problem(
        StatusCode::SERVICE_UNAVAILABLE,
        PaymentProblemCode::Unavailable,
    )
    .await;
    let error = client
        .request_collection(&token(), KEY, &request)
        .await
        .expect_err("explicit availability refusal");
    assert!(!error.is_outcome_unknown());

    for code in [
        PaymentProblemCode::ReceiptUnresolved,
        PaymentProblemCode::ReceiptExpired,
        PaymentProblemCode::RecoveryHeld,
    ] {
        let error = PaymentClientError::Problem {
            status: code.status(),
            code,
            trace_id: None,
            retry_after_seconds: None,
        };
        assert!(error.is_outcome_unknown(), "{}", code.as_str());
    }

    let malformed_authentication_refusal = PaymentClientError::Protocol {
        status: 401,
        failure: PaymentProtocolFailure::Problem,
        trace_id: None,
    };
    assert!(!malformed_authentication_refusal.is_outcome_unknown());
}

#[tokio::test]
async fn inconsistent_problem_document_is_a_protocol_failure() {
    let bill_id = Uuid::new_v4();
    let body = json!({
        "type": PaymentProblemCode::Unavailable.type_uri(),
        "title": PaymentProblemCode::Unavailable.as_str(),
        "status": PaymentProblemCode::Unavailable.status(),
        "code": PaymentProblemCode::Unavailable
    });
    let (client, _) = serve_fixture(
        StatusCode::BAD_GATEWAY,
        "application/problem+json",
        body.to_string(),
    )
    .await;
    let error = client
        .request_collection(
            &token(),
            KEY,
            &RequestCollection {
                bill_id,
                bill_version: 3,
            },
        )
        .await
        .expect_err("problem status mismatch");
    assert!(matches!(
        &error,
        PaymentClientError::Protocol {
            status: 502,
            failure: PaymentProtocolFailure::Problem,
            ..
        }
    ));
    assert!(error.is_outcome_unknown());
}

#[test]
fn connection_and_request_values_are_rejected_before_io() {
    let base = Url::parse("https://adapter.example.invalid/root").unwrap();
    for connection in ["", "UPPER", "two/segments", ".", &"a".repeat(65)] {
        assert!(matches!(
            PaymentClient::new(PaymentClientConfig::new(base.clone(), connection)),
            Err(PaymentClientError::Configuration { .. })
        ));
    }
}
