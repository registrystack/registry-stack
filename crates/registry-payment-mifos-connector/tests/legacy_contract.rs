// SPDX-License-Identifier: Apache-2.0

use registry_payment_mifos_connector::{
    build_batch_request, build_collection_request, parse_batch_acceptance,
    parse_collection_acceptance, BatchAccepted, BatchCommand, CollectionAccepted,
    CollectionCommand, ConnectorError, ExactMoney, MifosClient, MifosConnection, PartyIdentifier,
    PaymentState, RequestAuth, SecretHeader, SubmissionState, TransactionType,
};
use registry_platform_httputil::client::BearerToken;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn connection(base: &str) -> MifosConnection {
    MifosConnection {
        channel_base_url: base.into(),
        bulk_base_url: base.into(),
        operations_base_url: base.into(),
        tenant: "pilot".into(),
        payment_scheme: "mpesa".into(),
    }
}

fn collection() -> CollectionCommand {
    CollectionCommand {
        correlation_id: "collection-1".into(),
        payer: [
            PartyIdentifier {
                key: "MSISDN".into(),
                value: "254700000001".into(),
            },
            PartyIdentifier {
                key: "ACCOUNTID".into(),
                value: "bill-account-1".into(),
            },
        ],
        money: ExactMoney {
            amount: "25.50".into(),
            currency: "USD".into(),
        },
        transaction_type: TransactionType {
            scenario: "MPESA".into(),
            sub_scenario: "BUYGOODS".into(),
            initiator: "PAYEE".into(),
            initiator_type: "BUSINESS".into(),
        },
    }
}

fn batch() -> BatchCommand {
    BatchCommand {
        correlation_id: "batch-request-1".into(),
        purpose: "social-transfer".into(),
        credit_party: vec![PartyIdentifier {
            key: "MSISDN".into(),
            value: "254700000002".into(),
        }],
        debit_party: vec![PartyIdentifier {
            key: "ACCOUNTID".into(),
            value: "programme-account".into(),
        }],
        sub_type: "TRANSFER".into(),
        money: ExactMoney {
            amount: "1000.00".into(),
            currency: "KES".into(),
        },
        description_text: "cycle-2026-11".into(),
        registering_institution_id: Some("ministry".into()),
        program_id: Some("cash-programme".into()),
        callback_url: Some("https://registry.example.test/payment-callback".into()),
    }
}

#[test]
fn collection_request_matches_channel_v1_12_2_and_keeps_decimal_text() {
    let encoded = build_collection_request(&collection()).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&encoded).unwrap(),
        json!({
            "payer": [
                {"key": "MSISDN", "value": "254700000001"},
                {"key": "ACCOUNTID", "value": "bill-account-1"}
            ],
            "amount": {"amount": "25.50", "currency": "USD"},
            "transactionType": {
                "scenario": "MPESA",
                "subScenario": "BUYGOODS",
                "initiator": "PAYEE",
                "initiatorType": "BUSINESS"
            },
            "customData": []
        })
    );
    assert!(String::from_utf8(encoded)
        .unwrap()
        .contains("\"amount\":\"25.50\""));
}

#[test]
fn pure_fixture_parsers_preserve_async_acceptance() {
    let collection_accepted =
        parse_collection_acceptance(br#"{"transactionId":"tx-fixture"}"#).unwrap();
    assert_eq!(collection_accepted.state, SubmissionState::Accepted);
    assert_eq!(collection_accepted.transaction_id, "tx-fixture");

    let batch_accepted = parse_batch_acceptance(
        &batch(),
        200,
        br#"{"batch_id":"batch-fixture","request_id":"batch-request-1","status":"queued"}"#,
    )
    .unwrap();
    assert_eq!(batch_accepted.state, SubmissionState::Accepted);
    assert_eq!(batch_accepted.batch_id, "batch-fixture");
}

#[test]
fn batch_acceptance_omits_and_defaults_absent_poll_delay() {
    let accepted = BatchAccepted {
        batch_id: "batch-1".into(),
        request_id: "batch-request-1".into(),
        state: SubmissionState::Accepted,
        suggested_poll_after_seconds: None,
    };
    assert_eq!(
        serde_json::to_value(&accepted).unwrap(),
        json!({
            "batchId": "batch-1",
            "requestId": "batch-request-1",
            "state": "accepted"
        })
    );
    let decoded: BatchAccepted = serde_json::from_value(json!({
        "batchId": "batch-1",
        "requestId": "batch-request-1",
        "state": "accepted"
    }))
    .unwrap();
    assert_eq!(decoded, accepted);
}

#[test]
fn transport_and_header_inputs_are_bounded_before_dispatch() {
    assert!(connection("https://payment.example/").validate().is_ok());
    assert!(connection("http://payment.example/").validate().is_err());
    assert!(connection("http://127.0.0.1:8099/").validate().is_ok());

    let mut invalid_tenant = connection("https://payment.example/");
    invalid_tenant.tenant = "pilot\r\nX-Injected: yes".into();
    assert_eq!(
        invalid_tenant.validate().unwrap_err(),
        ConnectorError::Configuration
    );
    assert!(SecretHeader::new("signature\nX-Injected: yes").is_err());

    let oversized = vec![b'x'; 65_537];
    assert_eq!(
        parse_collection_acceptance(&oversized).unwrap_err(),
        ConnectorError::Protocol
    );
}

#[test]
fn collection_status_uses_operations_states_without_channel_flattening() {
    let accepted = CollectionAccepted {
        transaction_id: "tx-1".into(),
        state: SubmissionState::Accepted,
    };
    for (provider, expected) in [
        ("INITIATED", PaymentState::Pending),
        ("IN_PROGRESS", PaymentState::Pending),
        ("RECEIVED", PaymentState::Pending),
        ("REQUEST_ACCEPTED", PaymentState::Pending),
        ("ACCEPTED", PaymentState::Pending),
        ("SUCCESS", PaymentState::ProviderConfirmed),
        ("FAILED", PaymentState::Failed),
        ("REJECTED", PaymentState::Failed),
        ("SETTLED_BY_FUTURE_VERSION", PaymentState::Unknown),
    ] {
        let body = json!({
            "content": [{
                "transactionId": "tx-1",
                "state": provider,
                "amount": "25.50",
                "currency": "USD",
                "clientCorrelationId": "collection-1"
            }]
        });
        assert_eq!(
            collection()
                .decode_status(&accepted, body.to_string().as_bytes())
                .unwrap()
                .state,
            expected
        );
    }

    assert_eq!(
        collection()
            .decode_status(&accepted, br#"{"content":[]}"#)
            .unwrap()
            .state,
        PaymentState::Unknown
    );
}

#[test]
fn collection_status_refuses_changed_identity_or_money() {
    let accepted = CollectionAccepted {
        transaction_id: "tx-1".into(),
        state: SubmissionState::Accepted,
    };
    let original = r#"{"content":[{"transactionId":"tx-1","state":"SUCCESS","amount":25.50,"currency":"USD","clientCorrelationId":"collection-1"}]}"#;
    for changed in [
        original.replace("tx-1", "tx-2"),
        original.replace("collection-1", "collection-2"),
        original.replace("25.50", "25.51"),
        original.replace("USD", "EUR"),
    ] {
        assert_eq!(
            collection()
                .decode_status(&accepted, changed.as_bytes())
                .unwrap_err(),
            ConnectorError::Protocol
        );
    }
}

#[test]
fn one_instruction_batch_matches_bulk_v1_12_1_not_the_dev_contract() {
    let encoded = build_batch_request(&batch()).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&encoded).unwrap(),
        json!([{
            "creditParty": [{"key": "MSISDN", "value": "254700000002"}],
            "debitParty": [{"key": "ACCOUNTID", "value": "programme-account"}],
            "subType": "TRANSFER",
            "amount": "1000.00",
            "currency": "KES",
            "descriptionText": "cycle-2026-11"
        }])
    );
    let text = String::from_utf8(encoded).unwrap();
    assert!(!text.contains("paymentMode"));
    assert!(!text.contains("requestId"));
}

#[test]
fn batch_status_requires_exact_one_instruction_detail() {
    let accepted = BatchAccepted {
        batch_id: "batch-1".into(),
        request_id: "batch-request-1".into(),
        state: SubmissionState::Accepted,
        suggested_poll_after_seconds: None,
    };
    let succeeded = br#"{"content":[{"transactionId":"transfer-1","status":"COMPLETED","payeePartyId":"254700000002","payeePartyIdType":"MSISDN","payerPartyId":"programme-account","payerPartyIdType":"ACCOUNTID","amount":"1000.00","currency":"KES","batchId":"batch-1","clientCorrelationId":"batch-request-1"}]}"#;
    let observation = batch().decode_status(&accepted, succeeded).unwrap();
    assert_eq!(observation.state, PaymentState::ProviderConfirmed);
    assert_eq!(
        observation.provider_reference.as_deref(),
        Some("transfer-1")
    );
    assert_eq!(observation.instruction_correlation_id, "batch-request-1");
    assert_eq!(observation.funding, batch().debit_party[0]);
    assert_eq!(observation.recipient, batch().credit_party[0]);
    assert_eq!(observation.money, batch().money);
    let failed = br#"{"content":[{"transactionId":"transfer-1","status":"FAILED","payeePartyId":"254700000002","payeePartyIdType":"MSISDN","payerPartyId":"programme-account","payerPartyIdType":"ACCOUNTID","amount":1000.00,"currency":"KES","batchId":"batch-1","clientCorrelationId":"batch-request-1"}]}"#;
    assert_eq!(
        batch().decode_status(&accepted, failed).unwrap().state,
        PaymentState::Failed
    );
    let drift = br#"{"content":[{"transactionId":"transfer-1","status":"RECONCILING","payeePartyId":"254700000002","payeePartyIdType":"MSISDN","payerPartyId":"programme-account","payerPartyIdType":"ACCOUNTID","amount":"1000.00","currency":"KES","batchId":"batch-1","clientCorrelationId":"batch-request-1"}]}"#;
    assert_eq!(
        batch().decode_status(&accepted, drift).unwrap().state,
        PaymentState::Unknown
    );
    let inconsistent = br#"{"content":[{"transactionId":"transfer-1","status":"COMPLETED","payeePartyId":"changed-recipient","payeePartyIdType":"MSISDN","payerPartyId":"programme-account","payerPartyIdType":"ACCOUNTID","amount":"1000.00","currency":"KES","batchId":"batch-1","clientCorrelationId":"batch-request-1"}]}"#;
    assert_eq!(
        batch().decode_status(&accepted, inconsistent).unwrap_err(),
        ConnectorError::Protocol
    );
    let changed_funding = String::from_utf8(succeeded.to_vec())
        .unwrap()
        .replace("programme-account", "other-account");
    assert_eq!(
        batch()
            .decode_status(&accepted, changed_funding.as_bytes())
            .unwrap_err(),
        ConnectorError::Protocol
    );
    let missing_destination = br#"{"content":[{"transactionId":"transfer-1","status":"COMPLETED","payerPartyId":"programme-account","payerPartyIdType":"ACCOUNTID","amount":"1000.00","currency":"KES","batchId":"batch-1","clientCorrelationId":"batch-request-1"}]}"#;
    assert_eq!(
        batch()
            .decode_status(&accepted, missing_destination)
            .unwrap_err(),
        ConnectorError::Protocol
    );
}

#[tokio::test]
async fn clients_send_only_bounded_profile_headers_and_return_async_acceptance() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let collection_request = receive(&listener).await;
        assert!(collection_request.starts_with("POST /channel/collection HTTP/1.1\r\n"));
        assert_header(&collection_request, "platform-tenantid", "pilot");
        assert_header(&collection_request, "x-correlationid", "collection-1");
        assert_header(&collection_request, "x-payment-scheme", "mpesa");
        assert_header(&collection_request, "authorization", "Bearer canary-token");
        respond(
            collection_request.socket,
            200,
            r#"{"transactionId":"tx-1"}"#,
        )
        .await;

        let batch_request = receive(&listener).await;
        assert!(batch_request.starts_with("POST /batchtransactions HTTP/1.1\r\n"));
        assert_header(&batch_request, "platform-tenantid", "pilot");
        assert_header(&batch_request, "x-correlationid", "batch-request-1");
        assert_header(&batch_request, "purpose", "social-transfer");
        assert_header(&batch_request, "type", "raw");
        assert_header(&batch_request, "x-signature", "canary-jws");
        assert_header(&batch_request, "x-registering-institution-id", "ministry");
        assert_header(&batch_request, "x-program-id", "cash-programme");
        assert_header(
            &batch_request,
            "x-callbackurl",
            "https://registry.example.test/payment-callback",
        );
        respond(
            batch_request.socket,
            200,
            r#"{"batch_id":"batch-1","request_id":"batch-request-1","status":"queued"}"#,
        )
        .await;
    });

    let client = MifosClient::new(connection(&format!("http://{address}/"))).unwrap();
    let bearer = BearerToken::new("canary-token").unwrap();
    let signature = SecretHeader::new("canary-jws").unwrap();
    let collection_accepted = client
        .submit_collection(&collection(), &RequestAuth::bearer(&bearer))
        .await
        .unwrap();
    assert_eq!(collection_accepted.state, SubmissionState::Accepted);
    let batch_accepted = client
        .submit_batch(&batch(), &RequestAuth::signature(&signature))
        .await
        .unwrap();
    assert_eq!(batch_accepted.state, SubmissionState::Accepted);
    server.await.unwrap();
}

#[tokio::test]
async fn status_reads_operations_detail_and_preserves_provider_only_semantics() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let collection_request = receive(&listener).await;
        assert!(collection_request.starts_with(
            "GET /api/v1/transactionRequests?page=0&size=2&clientCorrelationId=collection-1 HTTP/1.1\r\n"
        ));
        assert_header(&collection_request, "platform-tenantid", "pilot");
        respond(
            collection_request.socket,
            200,
            r#"{"content":[{"transactionId":"tx-1","state":"SUCCESS","amount":"25.50","currency":"USD","clientCorrelationId":"collection-1"}]}"#,
        )
        .await;

        let batch_request = receive(&listener).await;
        assert!(batch_request.starts_with(
            "GET /api/v1/batch/detail?batchId=batch-1&status=ALL&pageNo=0&pageSize=2&command=json HTTP/1.1\r\n"
        ));
        assert_header(&batch_request, "platform-tenantid", "pilot");
        respond(
            batch_request.socket,
            200,
            r#"{"content":[{"transactionId":"transfer-1","status":"COMPLETED","payeePartyId":"254700000002","payeePartyIdType":"MSISDN","payerPartyId":"programme-account","payerPartyIdType":"ACCOUNTID","amount":"1000.00","currency":"KES","batchId":"batch-1","clientCorrelationId":"batch-request-1"}]}"#,
        )
        .await;
    });

    let client = MifosClient::new(connection(&format!("http://{address}/"))).unwrap();
    let collection_observation = client
        .collection_status(
            &collection(),
            &CollectionAccepted {
                transaction_id: "tx-1".into(),
                state: SubmissionState::Accepted,
            },
            &RequestAuth::none(),
        )
        .await
        .unwrap();
    assert_eq!(
        collection_observation.state,
        PaymentState::ProviderConfirmed
    );
    let batch_observation = client
        .batch_status(
            &batch(),
            &BatchAccepted {
                batch_id: "batch-1".into(),
                request_id: "batch-request-1".into(),
                state: SubmissionState::Accepted,
                suggested_poll_after_seconds: None,
            },
            &RequestAuth::none(),
        )
        .await
        .unwrap();
    assert_eq!(batch_observation.state, PaymentState::ProviderConfirmed);
    assert_eq!(
        batch_observation.recipient,
        PartyIdentifier {
            key: "MSISDN".into(),
            value: "254700000002".into()
        }
    );
    server.await.unwrap();
}

#[tokio::test]
async fn polling_acknowledgement_is_still_only_async_acceptance() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let request = receive(&listener).await;
        respond(
            request.socket,
            202,
            r#"{"PollingPath":"/batch/Summary/batch-2","SuggestedCallbackSeconds":"10"}"#,
        )
        .await;
    });
    let client = MifosClient::new(connection(&format!("http://{address}/"))).unwrap();
    let accepted = client
        .submit_batch(&batch(), &RequestAuth::none())
        .await
        .unwrap();
    assert_eq!(accepted.batch_id, "batch-2");
    assert_eq!(accepted.request_id, "batch-request-1");
    assert_eq!(accepted.state, SubmissionState::Accepted);
    assert_eq!(accepted.suggested_poll_after_seconds, Some(10));
    server.await.unwrap();
}

#[tokio::test]
async fn uncertain_submit_is_not_retried_and_errors_do_not_disclose_secrets() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let request = receive(&listener).await;
        respond(request.socket, 200, r#"{"transactionId":"wrong value"}"#).await;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(150), listener.accept())
                .await
                .is_err()
        );
    });
    let client = MifosClient::new(connection(&format!("http://{address}/"))).unwrap();
    let token = BearerToken::new("secret-canary-never-disclose").unwrap();
    let error = client
        .submit_collection(&collection(), &RequestAuth::bearer(&token))
        .await
        .unwrap_err();
    assert_eq!(error, ConnectorError::OutcomeUnknown);
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("secret-canary"));
    assert!(!rendered.contains("wrong value"));
    server.await.unwrap();
}

struct Received {
    text: String,
    socket: tokio::net::TcpStream,
}

impl std::ops::Deref for Received {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.text
    }
}

async fn receive(listener: &tokio::net::TcpListener) -> Received {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let count = socket.read(&mut chunk).await.unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&bytes[..header_end + 4]);
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::trim)
                        .and_then(|value| value.parse::<usize>().ok())
                })
                .unwrap_or(0);
            if bytes.len() >= header_end + 4 + length {
                break;
            }
        }
    }
    Received {
        text: String::from_utf8(bytes).unwrap(),
        socket,
    }
}

fn assert_header(request: &str, name: &str, value: &str) {
    let expected = format!("{}: {}", name.to_ascii_lowercase(), value);
    assert!(
        request
            .lines()
            .map(str::to_ascii_lowercase)
            .any(|line| line == expected.to_ascii_lowercase()),
        "missing header {name}"
    );
}

async fn respond(mut socket: tokio::net::TcpStream, status: u16, body: &str) {
    let response = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    socket.write_all(response.as_bytes()).await.unwrap();
}
