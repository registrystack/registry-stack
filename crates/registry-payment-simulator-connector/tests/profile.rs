// SPDX-License-Identifier: Apache-2.0
use registry_payment_protocol::{CollectionState, Money};
use registry_payment_simulator_connector::{ProviderCommand, SimulatorConnection};

fn connection() -> SimulatorConnection {
    SimulatorConnection {
        base_url: "http://127.0.0.1:8099/".into(),
        tenant: "pilot".into(),
        biller: "ministry".into(),
        biller_name: "Ministry".into(),
        callback_url: "https://programme.example.test/callback".into(),
        payer_fi_bic: "SIMBANK".into(),
    }
}
fn command() -> ProviderCommand {
    ProviderCommand {
        request_id: "request1".into(),
        rtp_id: 1,
        bill_id: "bill1".into(),
        payer_address: "synthetic-payer".into(),
        money: Money {
            value: "25.50".into(),
            currency: "USD".into(),
            scale: 2,
        },
    }
}
#[test]
fn synthetic_transport_cannot_point_to_live_or_named_remote_hosts() {
    assert!(connection().validate().is_ok());
    for base in [
        "https://bank.example/",
        "http://192.168.1.1/",
        "http://user@127.0.0.1/",
        "http://127.0.0.1/?token=secret",
        " http://127.0.0.1/",
        "http://127.0.0.1/\n",
        "http://127.0.0.1/\\",
    ] {
        let mut config = connection();
        config.base_url = base.into();
        assert!(config.validate().is_err());
    }
}
#[test]
fn request_amount_is_an_exact_json_number_even_near_the_portable_bound() {
    let mut cmd = command();
    cmd.money.value = "90071992547409.91".into();
    let body = String::from_utf8(cmd.encode(&connection()).unwrap()).unwrap();
    assert!(body.contains("\"amount\":90071992547409.91"));
    assert!(!body.contains("\"amount\":\""));
}
#[test]
fn com_pending_does_not_confirm_and_mismatched_facts_are_refused() {
    let body = br#"{"transferRequestId":"tr1","RequestId":"request1","rtpId":1,"billId":"bill1","amount":25.50,"currency":"USD","requestStatus":"COM","paymentStatus":"PENDING","lastUpdateDate":1}"#;
    let cmd = command();
    let observation = cmd.decode_status("tr1", body).unwrap();
    assert_eq!(observation.state, CollectionState::Pending);
    for (from, to) in [
        ("25.50", "25.51"),
        ("USD", "EUR"),
        ("bill1", "bill2"),
        ("request1", "request2"),
        ("\"rtpId\":1", "\"rtpId\":2"),
    ] {
        let changed = String::from_utf8(body.to_vec()).unwrap().replace(from, to);
        assert!(cmd.decode_status("tr1", changed.as_bytes()).is_err());
    }
    assert!(cmd.decode_status("wrong-transfer", body).is_err());
}
#[test]
fn confirmation_requires_synthetic_reference_and_exact_valid_pair() {
    let body = br#"{"transferRequestId":"tr1","RequestId":"request1","rtpId":1,"billId":"bill1","amount":25.5,"currency":"USD","requestStatus":"COM","paymentStatus":"PAID","lastUpdateDate":1,"PaymentReferenceID":"SIM-1"}"#;
    assert_eq!(
        command().decode_status("tr1", body).unwrap().state,
        CollectionState::Confirmed
    );
    for (from, to) in [("SIM-1", "BANK-1"), ("COM", "PND"), ("25.5", "25.50001")] {
        let changed = String::from_utf8(body.to_vec()).unwrap().replace(from, to);
        assert!(command().decode_status("tr1", changed.as_bytes()).is_err());
    }
}

#[tokio::test]
async fn an_invalid_acknowledgement_after_dispatch_is_an_unknown_outcome() {
    use registry_payment_simulator_connector::{ConnectorError, SimulatorClient};
    use registry_platform_httputil::client::BearerToken;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for body in [
        "not-json",
        r#"{"responseCode":"00","responseDescription":"Accepted","requestID":"wrong","rtpId":1,"transferRequestId":"tr1"}"#,
        r#"{"responseCode":"00","responseDescription":"Accepted","requestID":"request1","rtpId":2,"transferRequestId":"tr1"}"#,
        r#"{"responseCode":"00","responseDescription":"Accepted","requestID":"request1","rtpId":1,"transferRequestId":"../wrong"}"#,
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let count = socket.read(&mut request).await.unwrap();
            assert!(std::str::from_utf8(&request[..count])
                .unwrap()
                .starts_with("POST /rtpRequest "));
            let response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Payment-Simulator: synthetic\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        let mut config = connection();
        config.base_url = format!("http://{address}/");
        let client = SimulatorClient::new(config).unwrap();
        assert_eq!(
            client
                .submit(
                    &command(),
                    &BearerToken::new("synthetic-test-token").unwrap()
                )
                .await
                .unwrap_err(),
            ConnectorError::Unknown
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn loopback_root_origins_with_or_without_a_slash_reach_the_same_provider_routes() {
    use registry_payment_simulator_connector::SimulatorClient;
    use registry_platform_httputil::client::BearerToken;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for suffix in ["/", ""] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for (route, body) in [
                (
                    "POST /rtpRequest ",
                    r#"{"responseCode":"00","responseDescription":"Accepted","requestID":"request1","rtpId":1,"transferRequestId":"tr1"}"#,
                ),
                (
                    "GET /transferRequests/tr1 ",
                    r#"{"transferRequestId":"tr1","RequestId":"request1","rtpId":1,"billId":"bill1","amount":25.50,"currency":"USD","requestStatus":"COM","paymentStatus":"PENDING","lastUpdateDate":1}"#,
                ),
            ] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 4096];
                let count = socket.read(&mut request).await.unwrap();
                assert!(std::str::from_utf8(&request[..count])
                    .unwrap()
                    .starts_with(route));
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Payment-Simulator: synthetic\r\nX-CorrelationID: request1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let mut config = connection();
        config.base_url = format!("http://{address}{suffix}");
        let client = SimulatorClient::new(config).unwrap();
        let token = BearerToken::new("canary-synthetic-provider-token").unwrap();
        let transfer = client.submit(&command(), &token).await.unwrap();
        assert_eq!(transfer, "tr1");
        assert_eq!(
            client
                .observe(&command(), &transfer, &token)
                .await
                .unwrap()
                .state,
            CollectionState::Pending
        );
        server.await.unwrap();
    }
}
