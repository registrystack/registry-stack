// SPDX-License-Identifier: Apache-2.0
//! Native payment calls, original-command recovery, and authoritative named
//! completion observations through the configured Adapter connection.
mod support;

use registry_coordinator::{
    adapters::{ConnectionConfig, HttpAdapters},
    definition::{CompletionDefinition, CompletionKind},
    protocol::{
        AdapterSet, CallOutcome, CallRequest, CompletionObservation, Operation,
        ReconciliationOutcome,
    },
    runtime::PaymentConnectionConfig,
};
use registry_payment_client::PaymentProblemCode;
use serde_json::{json, Value};
use uuid::Uuid;
use wiremock::{
    matchers::{body_json, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

const KEY: &str = "service-payment-attempt-1";

fn accepted(collection_id: Uuid, bill_id: Uuid) -> Value {
    json!({
        "collectionId": collection_id,
        "billId": bill_id,
        "billVersion": 3,
        "bindingRevision": "sha256:synthetic-binding",
        "simulation": true
    })
}

fn status(collection_id: Uuid, bill_id: Uuid, state: &str) -> Value {
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

fn json_answer(status: u16, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("traceparent", support::TRACE)
        .set_body_raw(body.to_string(), "application/json")
}

fn problem(code: PaymentProblemCode) -> ResponseTemplate {
    ResponseTemplate::new(code.status())
        .insert_header("traceparent", support::TRACE)
        .set_body_raw(
            json!({
                "type": code.type_uri(),
                "title": code.as_str(),
                "status": code.status(),
                "code": code
            })
            .to_string(),
            "application/problem+json",
        )
}

fn request(bill_id: Uuid) -> CallRequest {
    CallRequest {
        connection: "payments".into(),
        operation: Operation::RequestCollection,
        input: json!({"billId": bill_id, "billVersion": 3}),
        idempotency_key: Some(KEY.into()),
        operation_contract: None,
    }
}

fn completion() -> CompletionDefinition {
    CompletionDefinition {
        kind: CompletionKind::PaymentCollection {},
        output: registry_coordinator::contracts::payment_completion_schema().clone(),
        revision: String::new(),
    }
}

struct Fixture {
    adapters: HttpAdapters,
    payment: MockServer,
    _token: MockServer,
    _root: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let token = MockServer::start().await;
    let payment = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let issuer = support::issuer().await;
    let mut config = support::config(root.path(), &issuer, &payment.uri(), &payment.uri());
    let mut authorization = config.connections["applications"]
        .authorization()
        .unwrap()
        .clone();
    authorization.token_endpoint = format!("{}/token", token.uri()).parse().unwrap();
    authorization.resource = "urn:example:payments".into();
    authorization.scopes = vec!["payments:collect".into()];
    config.connections.insert(
        "payments".into(),
        ConnectionConfig::Payments(PaymentConnectionConfig {
            base_url: payment.uri().parse().unwrap(),
            payment_connection: "service-fees".into(),
            authorization,
            result_check_seconds: None,
        }),
    );
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "fixture-token",
            "token_type": "Bearer",
            "expires_in": 40,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
        })))
        .mount(&token)
        .await;
    let adapters = HttpAdapters::new(&config).unwrap();
    issuer.stop().await;
    Fixture {
        adapters,
        payment,
        _token: token,
        _root: root,
    }
}

#[tokio::test]
async fn collection_request_and_recovery_use_the_exact_original_command() {
    let fixture = fixture().await;
    let collection_id = Uuid::new_v4();
    let bill_id = Uuid::new_v4();
    let command = request(bill_id);
    let acceptance = accepted(collection_id, bill_id);
    Mock::given(method("POST"))
        .and(path("/v1/payments/service-fees/collections"))
        .and(header("authorization", "Bearer fixture-token"))
        .and(header("idempotency-key", KEY))
        .and(body_json(json!({"billId": bill_id, "billVersion": 3})))
        .respond_with(json_answer(202, acceptance.clone()))
        .expect(1)
        .mount(&fixture.payment)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/payments/service-fees/collections/receipt"))
        .and(header("authorization", "Bearer fixture-token"))
        .and(header("idempotency-key", KEY))
        .and(body_json(json!({"billId": bill_id, "billVersion": 3})))
        .respond_with(json_answer(200, acceptance.clone()))
        .expect(1)
        .mount(&fixture.payment)
        .await;

    assert!(matches!(
        fixture.adapters.call(&command).await,
        CallOutcome::Success(value) if value == acceptance
    ));
    assert!(matches!(
        fixture.adapters.reconcile(&command, None).await,
        ReconciliationOutcome::Confirmed(value) if value == acceptance
    ));
}

#[tokio::test]
async fn ambiguous_mutation_response_holds_until_read_only_recovery_resolves() {
    let fixture = fixture().await;
    let bill_id = Uuid::new_v4();
    let command = request(bill_id);
    Mock::given(method("POST"))
        .and(path("/v1/payments/service-fees/collections"))
        .respond_with(problem(PaymentProblemCode::ProviderProtocol))
        .expect(1)
        .mount(&fixture.payment)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/payments/service-fees/collections/receipt"))
        .respond_with(problem(PaymentProblemCode::ReceiptUnresolved))
        .expect(1)
        .mount(&fixture.payment)
        .await;

    assert!(matches!(
        fixture.adapters.call(&command).await,
        CallOutcome::Uncertain { code } if code == "payment-invalid-response"
    ));
    assert!(matches!(
        fixture.adapters.reconcile(&command, None).await,
        ReconciliationOutcome::Unresolved { code } if code == "receipt-unresolved"
    ));
}

#[tokio::test]
async fn payment_authentication_failure_is_a_value_free_refusal() {
    let fixture = fixture().await;
    Mock::given(method("POST"))
        .and(path("/v1/payments/service-fees/collections"))
        .respond_with(problem(PaymentProblemCode::Unauthenticated))
        .expect(1)
        .mount(&fixture.payment)
        .await;

    assert!(matches!(
        fixture.adapters.call(&request(Uuid::new_v4())).await,
        CallOutcome::Refused { code } if code == "product-forbidden"
    ));
}

#[tokio::test]
async fn payment_completion_settles_only_terminal_exactly_bound_state() {
    for (state, settles) in [
        ("accepted", false),
        ("pending", false),
        ("unknown", false),
        ("confirmed", true),
        ("failed", true),
    ] {
        let fixture = fixture().await;
        let collection_id = Uuid::new_v4();
        let bill_id = Uuid::new_v4();
        let command = request(bill_id);
        let acceptance = accepted(collection_id, bill_id);
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1/payments/service-fees/collections/{collection_id}"
            )))
            .respond_with(json_answer(200, status(collection_id, bill_id, state)))
            .expect(1)
            .mount(&fixture.payment)
            .await;

        let observed = fixture
            .adapters
            .observe_completion(&command, &acceptance, &completion())
            .await;
        assert_eq!(
            matches!(&observed, CompletionObservation::Settled(_)),
            settles
        );
        if !settles {
            assert!(matches!(&observed, CompletionObservation::Pending { .. }));
        }
    }

    let fixture = fixture().await;
    let collection_id = Uuid::new_v4();
    let bill_id = Uuid::new_v4();
    let other_bill_id = Uuid::new_v4();
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/payments/service-fees/collections/{collection_id}"
        )))
        .respond_with(json_answer(
            200,
            status(collection_id, other_bill_id, "confirmed"),
        ))
        .expect(1)
        .mount(&fixture.payment)
        .await;
    let observed = fixture
        .adapters
        .observe_completion(
            &request(bill_id),
            &accepted(collection_id, bill_id),
            &completion(),
        )
        .await;
    assert!(matches!(
        observed,
        CompletionObservation::Hold { code } if code == "payment-correlation-mismatch"
    ));
}
