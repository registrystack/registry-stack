// SPDX-License-Identifier: Apache-2.0
mod support;

use registry_breg_client::{
    BRegRecordOptions, BaseRegistryClient, BaseRegistryClientConfig, BaseRegistryClientError,
};
use registry_coordinator::{
    adapters::HttpAdapters,
    protocol::{AdapterSet, CallOutcome, CallRequest, Operation},
};
use serde_json::json;
use support::{config, issuer, receipt, record, submission, RECORD, TRACE};
use wiremock::{
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

#[tokio::test]
async fn breg_transient_http_failures_are_retryable_without_retrying_inside_an_attempt() {
    let issuer = issuer().await;
    for (status, response) in [408, 429, 500, 503, 599].into_iter().flat_map(|status| {
        [
            ResponseTemplate::new(status).set_body_string("private-upstream-canary"),
            ResponseTemplate::new(status)
                .insert_header("traceparent", TRACE)
                .insert_header("cache-control", "no-store")
                .set_body_raw(
                    json!({"code":"edge.rate-limited", "detail":"private-upstream-canary"})
                        .to_string(),
                    "application/problem+json",
                ),
        ]
        .map(|response| (status, response))
    }) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/records/applications/{RECORD}")))
            .and(query_param("accessProfile", "follow-up-reader"))
            .respond_with(response)
            .expect(2)
            .mount(&server)
            .await;
        let client = BaseRegistryClient::new(BaseRegistryClientConfig::new(
            url::Url::parse(&server.uri()).unwrap(),
        ))
        .unwrap();
        let options = BRegRecordOptions::default()
            .access_profile("follow-up-reader")
            .unwrap();
        let error = client
            .get_record("applications", RECORD, &options)
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error,
                BaseRegistryClientError::Protocol { status: observed, .. } if *observed == status
            ),
            "an intermediary failure is not a closed BReg problem: {error:?}"
        );
        assert!(!format!("{error:?}").contains("private-upstream-canary"));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);

        let root = tempfile::tempdir().unwrap();
        let adapters =
            HttpAdapters::new(&config(root.path(), &issuer, &server.uri(), &server.uri())).unwrap();
        let outcome = adapters
            .call(&CallRequest {
                connection: "applications".into(),
                operation: Operation::ReadRecord,
                input: json!({"collection":"applications", "recordId":RECORD}),
                idempotency_key: None,
            })
            .await;
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            2,
            "one durable attempt sends one product request"
        );
        match outcome {
            CallOutcome::Retryable { code } => assert_eq!(code, if status == 429 { "rate-limited" } else { "transport-unavailable" }),
            CallOutcome::Refused { code } => panic!(
                "temporary BReg HTTP {status} must use the existing bounded workflow retry; got permanent {code}"
            ),
            _ => panic!("temporary BReg read failure must be retryable"),
        }
    }
    issuer.stop().await;
}

#[tokio::test]
async fn breg_malformed_success_and_product_refusals_remain_permanent() {
    let issuer = issuer().await;
    for (response, expected) in [
        (
            ResponseTemplate::new(200)
                .insert_header("traceparent", TRACE)
                .insert_header("etag", "\"breg-record-000000000001\"")
                .insert_header("link", "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/application>; rel=\"describedby\"")
                .set_body_json(json!({"private-upstream-canary":true})),
            "invalid-response",
        ),
        (
            ResponseTemplate::new(400).set_body_string("private-upstream-canary"),
            "invalid-response",
        ),
        (
            ResponseTemplate::new(401)
                .insert_header("traceparent", TRACE)
                .insert_header("cache-control", "no-store")
                .set_body_raw(json!({"type":"https://id.registrystack.org/problems/registry-breg/authentication/refused", "title":"Unauthorized", "status":401, "detail":"The bearer credential is missing or refused.", "code":"authentication.refused", "traceId":"4bf92f3577b34da6a3ce929d0e0e4736"}).to_string(), "application/problem+json"),

            "product-forbidden",
        ),
        (
            ResponseTemplate::new(404)
                .insert_header("traceparent", TRACE)
                .insert_header("cache-control", "no-store")
                .set_body_raw(json!({"type":"https://id.registrystack.org/problems/registry-breg/resource/not_found", "title":"Not Found", "status":404, "detail":"The requested resource was not found.", "code":"resource.not_found", "traceId":"4bf92f3577b34da6a3ce929d0e0e4736"}).to_string(), "application/problem+json"),

            "product-not-found",
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/records/applications/{RECORD}")))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let root = tempfile::tempdir().unwrap();
        let adapters =
            HttpAdapters::new(&config(root.path(), &issuer, &server.uri(), &server.uri())).unwrap();
        let outcome = adapters
            .call(&CallRequest {
                connection: "applications".into(),
                operation: Operation::ReadRecord,
                input: json!({"collection":"applications", "recordId":RECORD}),
                idempotency_key: None,
            })
            .await;
        match outcome {
            CallOutcome::Refused { code } => assert_eq!(code, expected),
            _ => panic!("BReg malformed-success and product-refusal controls must stay permanent"),
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
    issuer.stop().await;
}

#[tokio::test]
async fn maintained_clients_acquire_credentials_and_decode_product_responses() {
    let issuer = issuer().await;
    let breg = MockServer::start().await;
    let messaging = MockServer::start().await;
    Mock::given(method("GET")).and(path(format!("/v1/records/applications/{RECORD}")))
        .and(query_param("accessProfile", "follow-up-reader"))
        .respond_with(ResponseTemplate::new(200).insert_header("traceparent", TRACE)
            .insert_header("etag", "\"breg-record-000000000001\"")
            .insert_header("link", "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/application>; rel=\"describedby\"")
            .set_body_json(record(true, "person@example.invalid")))
        .expect(1).mount(&breg).await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(202)
                .insert_header("traceparent", TRACE)
                .set_body_json(receipt()),
        )
        .expect(1)
        .mount(&messaging)
        .await;
    let root = tempfile::tempdir().unwrap();
    let adapters =
        HttpAdapters::new(&config(root.path(), &issuer, &breg.uri(), &messaging.uri())).unwrap();
    let read = adapters
        .call(&CallRequest {
            connection: "applications".into(),
            operation: Operation::ReadRecord,
            input: json!({"collection":"applications", "recordId":RECORD}),
            idempotency_key: None,
        })
        .await;
    assert!(
        matches!(read, CallOutcome::Success(value) if value["data"]["domainData"]["noticeAllowed"] == true)
    );
    let send = adapters
        .call(&CallRequest {
            connection: "notices".into(),
            operation: Operation::SubmitMessage,
            input: submission(),
            idempotency_key: Some("stable-command".into()),
        })
        .await;
    assert!(matches!(send, CallOutcome::Success(value) if value == receipt()));
    for server in [&breg, &messaging] {
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let authorization = requests[0]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(authorization.starts_with("Bearer "));
        assert_eq!(
            authorization[7..].split('.').count(),
            3,
            "fixture issued signed token after validating private-key assertion"
        );
    }
    let requests = messaging.received_requests().await.unwrap();
    assert_eq!(requests[0].headers["idempotency-key"], "stable-command");
    issuer.stop().await;
}

#[tokio::test]
async fn one_dispatch_attempt_does_not_retry_or_expose_remote_error_values() {
    let issuer = issuer().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("traceparent", TRACE)
                .set_body_string("recipient-and-token-canary"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let root = tempfile::tempdir().unwrap();
    let adapters =
        HttpAdapters::new(&config(root.path(), &issuer, &server.uri(), &server.uri())).unwrap();
    let outcome = adapters
        .call(&CallRequest {
            connection: "notices".into(),
            operation: Operation::SubmitMessage,
            input: submission(),
            idempotency_key: Some("stable-command".into()),
        })
        .await;
    assert!(matches!(outcome, CallOutcome::Uncertain { code } if code == "transport-uncertain"));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    issuer.stop().await;
}

#[tokio::test]
async fn binding_identity_excludes_secret_path_but_pins_destination_and_authority() {
    let issuer = issuer().await;
    let root = tempfile::tempdir().unwrap();
    let mut config = config(
        root.path(),
        &issuer,
        "http://127.0.0.1:1",
        "http://127.0.0.1:2",
    );
    let first = HttpAdapters::new(&config)
        .unwrap()
        .binding_digest()
        .to_owned();
    support::private_file(
        &root.path().join("rotated-key"),
        registry_platform_testing::fixtures::ED25519_ROTATED_PRIVATE_JWK.as_bytes(),
    );
    config
        .connections
        .get_mut("notices")
        .unwrap()
        .authorization
        .signing_key_ref =
        registry_platform_config::SecretReference::parse("secret:file/rotated-key").unwrap();
    assert_eq!(HttpAdapters::new(&config).unwrap().binding_digest(), first);
    config
        .connections
        .get_mut("notices")
        .unwrap()
        .authorization
        .client_id = "another-sender".into();
    assert_ne!(HttpAdapters::new(&config).unwrap().binding_digest(), first);
    config.connections.get_mut("notices").unwrap().base_url =
        url::Url::parse("http://sensitive-host-canary.invalid").unwrap();
    let error = HttpAdapters::new(&config).err().unwrap();
    assert!(!error.to_string().contains("sensitive-host-canary"));
    issuer.stop().await;
}

#[tokio::test]
async fn declined_credentials_and_invalid_commands_never_reach_the_product() {
    let issuer = issuer().await;
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let mut config = config(root.path(), &issuer, &server.uri(), &server.uri());
    config
        .connections
        .get_mut("notices")
        .unwrap()
        .authorization
        .client_id = "unregistered-client-canary".into();
    let adapters = HttpAdapters::new(&config).unwrap();
    let mut request = CallRequest {
        connection: "notices".into(),
        operation: Operation::SubmitMessage,
        input: submission(),
        idempotency_key: Some("stable-command".into()),
    };
    let outcome = adapters.call(&request).await;
    assert!(matches!(outcome, CallOutcome::Refused { code } if code == "credential-refused"));
    request.idempotency_key = Some("invalid key canary".into());
    let outcome = adapters.call(&request).await;
    assert!(matches!(outcome, CallOutcome::Refused { code } if code == "invalid-command"));
    assert!(server.received_requests().await.unwrap().is_empty());
    issuer.stop().await;
}

#[tokio::test]
async fn workflow_connections_are_checked_without_product_calls() {
    let issuer = issuer().await;
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let mut config = config(root.path(), &issuer, &server.uri(), &server.uri());
    let definition =
        registry_coordinator::definition::Definition::load(&support::project()).unwrap();
    config.validate_workflow(&definition.workflow).unwrap();
    config.connections.get_mut("notices").unwrap().product =
        registry_coordinator::adapters::Product::Breg;
    assert_eq!(
        config
            .validate_workflow(&definition.workflow)
            .unwrap_err()
            .code,
        "workflow-binding"
    );
    config.connections.remove("notices");
    assert_eq!(
        config
            .validate_workflow(&definition.workflow)
            .unwrap_err()
            .code,
        "workflow-binding"
    );
    assert!(server.received_requests().await.unwrap().is_empty());
    issuer.stop().await;
}

#[tokio::test]
async fn task_binding_requires_an_unexpired_approval_and_never_uses_standing_authority() {
    use registry_coordinator::runtime::TaskAuthorityConfig;
    let issuer = issuer().await;
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let mut config = config(root.path(), &issuer, &server.uri(), &server.uri());
    let standing = HttpAdapters::new(&config).unwrap();
    let mut request = CallRequest {
        connection: "applications".into(),
        operation: Operation::ReadRecord,
        input: json!({"collection":"applications","recordId":RECORD,
            "grant":{"id":uuid::Uuid::new_v4(),"expiresAt":chrono::Utc::now().timestamp()+120}}),
        idempotency_key: None,
    };
    assert!(
        matches!(standing.call(&request).await, CallOutcome::Refused{code} if code == "invalid-command")
    );
    config
        .connections
        .get_mut("applications")
        .unwrap()
        .authorization
        .task_authority = Some(TaskAuthorityConfig {
        base_url: server.uri().parse().unwrap(),
        issuer: "https://casework.example".into(),
        subject: "poc-reader".into(),
        exchange_audience: issuer.issuer(),
        bootstrap_resource: "urn:example:applications".into(),
    });
    let task = HttpAdapters::new(&config).unwrap();
    request.input["grant"]["expiresAt"] = json!(chrono::Utc::now().timestamp() - 1);
    assert!(
        matches!(task.call(&request).await, CallOutcome::Refused{code} if code == "credential-refused")
    );
    request.input.as_object_mut().unwrap().remove("grant");
    assert!(
        matches!(task.call(&request).await, CallOutcome::Refused{code} if code == "invalid-command")
    );
    request.input["grant"] = json!({"id":"bearer-canary","expiresAt":123});
    assert!(
        matches!(task.call(&request).await, CallOutcome::Refused{code} if code == "invalid-command")
    );
    assert!(server.received_requests().await.unwrap().is_empty());
    issuer.stop().await;
}

#[tokio::test]
async fn authority_deadline_mismatch_and_revocation_never_reach_breg() {
    use registry_coordinator::runtime::TaskAuthorityConfig;
    let issuer = issuer().await;
    let authority = MockServer::start().await;
    let breg = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let mut config = config(root.path(), &issuer, &breg.uri(), &breg.uri());
    config
        .connections
        .get_mut("applications")
        .unwrap()
        .authorization
        .task_authority = Some(TaskAuthorityConfig {
        base_url: authority.uri().parse().unwrap(),
        issuer: "https://casework.example".into(),
        subject: "poc-reader".into(),
        exchange_audience: issuer.issuer(),
        bootstrap_resource: "urn:example:applications".into(),
    });
    let grant = uuid::Uuid::new_v4();
    let expiry = chrono::Utc::now().timestamp() + 120;
    let request = CallRequest {
        connection: "applications".into(),
        operation: Operation::ReadRecord,
        input: json!({"collection":"applications","recordId":RECORD,"grant":{"id":grant,"expiresAt":expiry}}),
        idempotency_key: None,
    };
    Mock::given(method("POST"))
        .and(path(format!("/v1/task-grants/{grant}/assertion")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("traceparent", TRACE)
                .set_body_json(
                    json!({"assertion":"sensitive-assertion-canary","expiresAt":expiry,
                "grantExpiresAt":expiry+1}),
                ),
        )
        .expect(1)
        .mount(&authority)
        .await;
    let adapters = HttpAdapters::new(&config).unwrap();
    assert!(
        matches!(adapters.call(&request).await, CallOutcome::Refused{code} if code == "credential-refused")
    );
    authority.verify().await;
    let received = authority.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    assert!(received[0].body.is_empty());
    assert!(received[0]
        .headers
        .get("registry-casework-profile")
        .is_none());
    authority.reset().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("traceparent", TRACE)
                .set_body_json(json!({"code":"grant-revoked"})),
        )
        .expect(2)
        .mount(&authority)
        .await;
    // Repeated attempts go back to Casework. A revoked grant is a refusal,
    // never a reason to fall back to the standing service identity.
    for _ in 0..2 {
        assert!(
            matches!(adapters.call(&request).await, CallOutcome::Refused{code} if code == "credential-refused")
        );
    }
    assert!(breg.received_requests().await.unwrap().is_empty());
    issuer.stop().await;
}

#[tokio::test]
async fn message_reconciliation_requires_original_command_receipt_instead_of_operator_id() {
    use registry_coordinator::protocol::ReconciliationOutcome;
    let issuer = issuer().await;
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let adapters =
        HttpAdapters::new(&config(root.path(), &issuer, &server.uri(), &server.uri())).unwrap();
    Mock::given(method("POST"))
        .and(path("/v1/messages/receipt"))
        .and(wiremock::matchers::header(
            "idempotency-key",
            "stable-command",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("traceparent", TRACE)
                .set_body_json(receipt()),
        )
        .expect(1)
        .mount(&server)
        .await;
    let command = CallRequest {
        connection: "notices".into(),
        operation: Operation::SubmitMessage,
        input: submission(),
        idempotency_key: Some("stable-command".into()),
    };
    assert!(
        matches!(adapters.reconcile(&command,Some(&json!({"id":"operator-invented-id"}))).await,
        ReconciliationOutcome::Confirmed(value) if value==receipt())
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/v1/messages/receipt");
    assert_eq!(requests[0].headers["idempotency-key"], "stable-command");
    issuer.stop().await;
}
