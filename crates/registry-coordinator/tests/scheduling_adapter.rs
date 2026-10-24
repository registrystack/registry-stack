// SPDX-License-Identifier: Apache-2.0
mod support;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_coordinator::{
    adapters::{ConnectionConfig, HttpAdapters, TaskAuthorityConfig},
    contracts::contract,
    protocol::{AdapterSet, CallOutcome, CallRequest, Operation, ReconciliationOutcome},
};
use registry_platform_crypto::{sign, PrivateJwk};
use registry_scheduling_client::{
    BearerToken, SchedulingAuth, SchedulingClient, SchedulingClientConfig, SchedulingClientError,
};
use serde_json::{json, Value};
use wiremock::{
    matchers::{body_json, body_string_contains, header, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

const GRANT: &str = "00000000-0000-4000-8000-000000000003";
const APPOINTMENT: &str = "appt-accepted";

#[test]
fn lifecycle_contracts_accept_native_uuid_identifiers() {
    let id = "00000000-0000-4000-8000-000000000001";
    let grant = json!({"id": GRANT, "expiresAt": 2_000_000_000});
    let cases = [
        (Operation::ReadAppointment, json!({"appointmentId": id})),
        (
            Operation::ReleaseHold,
            json!({"holdId": id, "grant": grant}),
        ),
        (
            Operation::ConfirmHold,
            json!({"appointment": {"hold": id}, "grant": grant}),
        ),
        (
            Operation::RescheduleAppointment,
            json!({
                "appointmentId": id, "grant": grant,
                "reschedule": {"observedRevision": 1, "admission": admission()["admission"]}
            }),
        ),
        (
            Operation::CancelAppointment,
            json!({
                "appointmentId": id, "grant": grant,
                "cancellation": {"observedRevision": 1, "reason": "withdrawn"}
            }),
        ),
    ];
    for (operation, input) in cases {
        assert_eq!(
            contract(operation).check_input(&input),
            Ok(()),
            "{operation:?}"
        );
    }
}

#[test]
fn hold_lifecycle_contracts_reject_non_uuid_identifiers() {
    let grant = json!({"id": GRANT, "expiresAt": 2_000_000_000});
    for (operation, input) in [
        (
            Operation::ReleaseHold,
            json!({"holdId": "hold-one", "grant": grant}),
        ),
        (
            Operation::ConfirmHold,
            json!({"appointment": {"hold": "hold-one"}, "grant": grant}),
        ),
    ] {
        assert!(
            contract(operation).check_input(&input).is_err(),
            "{operation:?} accepted a hold identifier Scheduling cannot issue"
        );
    }
}

fn admission() -> Value {
    json!({"hold":null,"admission":{"offering":"application-review","start":"2026-10-10T10:00:00Z",
        "party":{"recipients":1,"attendees":1},"channel":null,"duplicateKey":support::RECORD,
        "policyRevision":1,"windowRevision":null,"capabilities":[],"prerequisites":[],
        "externalReferences":[{"product":"breg","recordType":"applications","identifier":support::RECORD}]}})
}

fn admission_request() -> Value {
    admission()["admission"].clone()
}

fn grant(deadline: i64) -> Value {
    json!({"id":GRANT,"expiresAt":deadline})
}

#[tokio::test]
async fn protocol_transient_http_failures_retry_reads_but_hold_ambiguous_mutations() {
    for (status, response) in [408, 429, 500, 503, 599].into_iter().flat_map(|status| {
        [
            ResponseTemplate::new(status).set_body_string("private-rate-limit-canary"),
            ResponseTemplate::new(status)
                .insert_header("traceparent", support::TRACE)
                .insert_header("cache-control", "no-store")
                .set_body_raw(
                    json!({"code":"edge.rate-limited","detail":"private-rate-limit-canary"})
                        .to_string(),
                    "application/problem+json",
                ),
        ]
        .map(|response| (status, response))
    }) {
        let token = MockServer::start().await;
        let authority = MockServer::start().await;
        let product = MockServer::start().await;
        let root = tempfile::tempdir().unwrap();
        let deadline = chrono::Utc::now().timestamp() + 120;
        let adapters = fixture(
            root.path(),
            &token,
            &authority,
            &product,
            deadline,
            FixtureBinding::default(),
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/v1/availability"))
            .respond_with(response.clone())
            .expect(2)
            .mount(&product)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/appointments"))
            .and(header("idempotency-key", "original-booking-command"))
            .and(body_json(admission()))
            .respond_with(response)
            .expect(1)
            .mount(&product)
            .await;
        let client = SchedulingClient::new(
            SchedulingClientConfig::new(product.uri().parse().unwrap())
                .with_maximum_mutation_retries(0),
        )
        .unwrap();
        let bearer = BearerToken::new("fixture-token").unwrap();
        let error = client
            .availability(
                SchedulingAuth::new(&bearer),
                "application-review",
                None,
                None,
                None,
                Some(20),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            &error,
            SchedulingClientError::Protocol { status: observed, .. } if *observed == status
        ));
        assert!(error.is_outcome_unknown());
        assert!(!format!("{error:?}").contains("private-rate-limit-canary"));
        assert_eq!(product.received_requests().await.unwrap().len(), 1);
        let original = command(deadline);
        assert!(matches!(adapters.call(&original).await,
            CallOutcome::Uncertain { code } if code == "transport-uncertain"));
        assert_eq!(
            product.received_requests().await.unwrap().len(),
            2,
            "an ambiguous mutation must be sent once and held for recovery"
        );
        assert_eq!(
            original.idempotency_key.as_deref(),
            Some("original-booking-command")
        );
        assert_eq!(original.input["appointment"], admission());
        let read = CallRequest {
            operation_contract: None,
            connection: "bookings".into(),
            operation: Operation::ReadAvailability,
            input: json!({"grant":{"id":GRANT,"expiresAt":deadline},
                "offering":"application-review","start":"2026-10-10T10:00:00Z",
                "end":"2026-10-10T11:00:00Z","limit":20}),
            idempotency_key: None,
        };
        let outcome = adapters.call(&read).await;
        assert_eq!(
            product.received_requests().await.unwrap().len(),
            3,
            "read throttling must not cause an immediate client resend"
        );
        match outcome {
            CallOutcome::Retryable { code, .. } => assert_eq!(
                code,
                if status == 429 {
                    "rate-limited"
                } else {
                    "transport-unavailable"
                }
            ),
            CallOutcome::Refused { code } => {
                panic!("temporary Scheduling HTTP {status} read was permanently refused: {code}")
            }
            _ => panic!("temporary Scheduling read failure must use bounded workflow retry"),
        }
    }
}

#[tokio::test]
async fn token_http_failures_preserve_transience_without_effect_or_standing_fallback() {
    for (status, exchange) in [408, 429, 400, 401, 403].into_iter().flat_map(|status| {
        [false, true]
            .into_iter()
            .map(move |exchange| (status, exchange))
    }) {
        let token = MockServer::start().await;
        let authority = MockServer::start().await;
        let product = MockServer::start().await;
        let root = tempfile::tempdir().unwrap();
        let deadline = chrono::Utc::now().timestamp() + 120;
        let adapters = fixture(
            root.path(),
            &token,
            &authority,
            &product,
            deadline,
            FixtureBinding {
                observe: true,
                ..Default::default()
            },
        )
        .await;
        let grant_type = if exchange {
            "subject_token="
        } else {
            "grant_type=client_credentials"
        };
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains(grant_type))
            .respond_with(ResponseTemplate::new(status))
            .with_priority(1)
            .expect(1)
            .mount(&token)
            .await;
        let original = command(deadline);
        let outcome = adapters.call(&original).await;
        if matches!(status, 408 | 429) {
            assert!(
                matches!(outcome, CallOutcome::Retryable { code, .. } if code == "credential-unavailable")
            );
        } else {
            assert!(
                matches!(outcome, CallOutcome::Refused { code } if code == "credential-refused")
            );
        }
        assert_eq!(
            original.idempotency_key.as_deref(),
            Some("original-booking-command")
        );
        assert_eq!(original.input["appointment"], admission());
        assert!(product.received_requests().await.unwrap().is_empty());
        assert_eq!(
            authority.received_requests().await.unwrap().len(),
            usize::from(exchange)
        );
        assert_eq!(
            token.received_requests().await.unwrap().len(),
            if exchange { 2 } else { 1 },
            "no immediate retry or observation-credential fallback is permitted"
        );
    }
}

fn appointment() -> Value {
    json!({"appointmentId":APPOINTMENT,"offering":"application-review","start":"2026-10-10T10:00:00Z",
        "end":"2026-10-10T10:30:00Z","resource":"room-one","units":1,"channel":null,
        "revision":1,"state":"confirmed","policyRevision":1,"createdAt":"2026-10-09T10:00:00Z",
        "cancelledAt":null,"externalReferences":[{"product":"breg","recordType":"applications","identifier":support::RECORD}]})
}

fn command(deadline: i64) -> CallRequest {
    CallRequest {
        operation_contract: None,
        connection: "bookings".into(),
        operation: Operation::CreateAppointment,
        input: json!({"grant":{"id":GRANT,"expiresAt":deadline},"appointment":admission()}),
        idempotency_key: Some("original-booking-command".into()),
    }
}

fn scheduling_command(operation: Operation, _deadline: i64, input: Value) -> CallRequest {
    CallRequest {
        operation_contract: None,
        connection: "bookings".into(),
        operation,
        input,
        idempotency_key: operation
            .requires_key()
            .then(|| "original-lifecycle-command".into()),
    }
}

fn grant_assertion(deadline: i64, subject: &str, resource: &str) -> (String, i64) {
    let now = chrono::Utc::now().timestamp();
    let header =
        URL_SAFE_NO_PAD.encode(json!({"alg":"EdDSA","kid":"fixture","typ":"JWT"}).to_string());
    let payload = URL_SAFE_NO_PAD.encode(
        json!({"iss":"https://casework.example","sub":subject,
        "aud":"urn:example:exchange","iat":now,"exp":now+50,"jti":"fresh-authority",
        "scope":"scheduling:read scheduling:book","registry_actor_kind":"agent",
        "registry_grant_id":GRANT,"registry_grant_client":"application-reader",
        "registry_grant_resource":resource,"registry_grant_exp":deadline})
        .to_string(),
    );
    let signing = format!("{header}.{payload}");
    let key = PrivateJwk::parse(registry_platform_testing::fixtures::ED25519_PRIVATE_JWK).unwrap();
    (
        format!(
            "{signing}.{}",
            URL_SAFE_NO_PAD.encode(sign(signing.as_bytes(), &key).unwrap())
        ),
        now + 50,
    )
}

struct FixtureBinding<'a> {
    task: bool,
    subject: &'a str,
    resource: &'a str,
    observe: bool,
}

impl Default for FixtureBinding<'_> {
    fn default() -> Self {
        Self {
            task: true,
            subject: "approved-agent",
            resource: "urn:example:scheduling",
            observe: true,
        }
    }
}

async fn fixture(
    root: &std::path::Path,
    token: &MockServer,
    authority: &MockServer,
    scheduling: &MockServer,
    deadline: i64,
    binding: FixtureBinding<'_>,
) -> HttpAdapters {
    let FixtureBinding {
        task,
        subject,
        resource,
        observe,
    } = binding;
    let issuer = support::issuer().await;
    let mut config = support::config(root, &issuer, &scheduling.uri(), &scheduling.uri());
    let mut auth = config.connections["applications"]
        .authorization()
        .unwrap()
        .clone();
    auth.token_endpoint = format!("{}/token", token.uri()).parse().unwrap();
    auth.resource = "urn:example:scheduling".into();
    auth.scopes = vec!["scheduling:read".into(), "scheduling:book".into()];
    if task {
        auth.task_authority = Some(TaskAuthorityConfig {
            base_url: authority.uri().parse().unwrap(),
            issuer: "https://casework.example".into(),
            subject: "approved-agent".into(),
            exchange_audience: "urn:example:exchange".into(),
            bootstrap_resource: "urn:example:casework".into(),
        });
    }
    let observation_authorization = if observe {
        let mut observation = auth.clone();
        observation.task_authority = None;
        observation.scopes = vec!["scheduling:read".into()];
        Some(observation)
    } else {
        None
    };
    config.connections.insert(
        "bookings".into(),
        ConnectionConfig::Scheduling(Box::new(
            registry_coordinator::runtime::SchedulingConnectionConfig {
                base_url: scheduling.uri().parse().unwrap(),
                authorization: auth,
                observation_authorization,
            },
        )),
    );
    Mock::given(method("POST")).and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":"fixture-token",
            "token_type":"Bearer","expires_in":40,"issued_token_type":"urn:ietf:params:oauth:token-type:access_token"})))
        .mount(token).await;
    let (assertion, assertion_expiry) = grant_assertion(deadline, subject, resource);
    Mock::given(method("POST"))
        .and(path(format!("/v1/task-grants/{GRANT}/assertion")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("traceparent", support::TRACE)
                .set_body_json(json!({"assertion":assertion,
                "expiresAt":assertion_expiry,"grantExpiresAt":deadline})),
        )
        .mount(authority)
        .await;
    let adapters = HttpAdapters::new(&config).unwrap();
    issuer.stop().await;
    adapters
}

#[tokio::test]
async fn lifecycle_operations_use_exact_public_client_routes_bodies_and_keys() {
    let token = MockServer::start().await;
    let authority = MockServer::start().await;
    let product = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let deadline = chrono::Utc::now().timestamp() + 120;
    let adapters = fixture(
        root.path(),
        &token,
        &authority,
        &product,
        deadline,
        FixtureBinding::default(),
    )
    .await;

    let hold = json!({"holdId":"hold-one","offering":"application-review",
        "start":"2026-10-10T10:00:00Z","end":"2026-10-10T10:30:00Z",
        "resource":"room-one","units":1,"expiresAt":"2026-10-10T09:55:00Z",
        "policyRevision":1,"externalReferences":[]});
    Mock::given(method("GET"))
        .and(path(format!("/v1/appointments/{APPOINTMENT}")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("traceparent", support::TRACE)
                .set_body_json(appointment()),
        )
        .expect(1)
        .mount(&product)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/holds"))
        .and(header("idempotency-key", "original-lifecycle-command"))
        .and(body_json(admission_request()))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("traceparent", support::TRACE)
                .set_body_json(&hold),
        )
        .expect(1)
        .mount(&product)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/v1/holds/hold-one"))
        .respond_with(ResponseTemplate::new(204).insert_header("traceparent", support::TRACE))
        .expect(1)
        .mount(&product)
        .await;
    let confirmation = json!({"hold":"hold-one","admission":null});
    Mock::given(method("POST"))
        .and(path("/v1/appointments"))
        .and(header("idempotency-key", "original-lifecycle-command"))
        .and(body_json(&confirmation))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("traceparent", support::TRACE)
                .set_body_json(appointment()),
        )
        .expect(1)
        .mount(&product)
        .await;
    let reschedule = json!({"observedRevision":1,"admission":admission_request()});
    Mock::given(method("POST"))
        .and(path(format!("/v1/appointments/{APPOINTMENT}/reschedule")))
        .and(header("idempotency-key", "original-lifecycle-command"))
        .and(body_json(&reschedule))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("traceparent", support::TRACE)
                .set_body_json(appointment()),
        )
        .expect(1)
        .mount(&product)
        .await;
    let cancellation = json!({"observedRevision":1,"reason":"request-withdrawn"});
    Mock::given(method("POST"))
        .and(path(format!("/v1/appointments/{APPOINTMENT}/cancel")))
        .and(header("idempotency-key", "original-lifecycle-command"))
        .and(body_json(&cancellation))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("traceparent", support::TRACE)
                .set_body_json(appointment()),
        )
        .expect(1)
        .mount(&product)
        .await;

    let cases = [
        (
            Operation::ReadAppointment,
            json!({"grant":grant(deadline),"appointmentId":APPOINTMENT}),
            appointment(),
        ),
        (
            Operation::CreateHold,
            json!({"grant":grant(deadline),"admission":admission_request()}),
            hold,
        ),
        (
            Operation::ReleaseHold,
            json!({"grant":grant(deadline),"holdId":"hold-one"}),
            Value::Null,
        ),
        (
            Operation::ConfirmHold,
            json!({"grant":grant(deadline),"appointment":confirmation}),
            appointment(),
        ),
        (
            Operation::RescheduleAppointment,
            json!({"grant":grant(deadline),"appointmentId":APPOINTMENT,"reschedule":reschedule}),
            appointment(),
        ),
        (
            Operation::CancelAppointment,
            json!({"grant":grant(deadline),"appointmentId":APPOINTMENT,"cancellation":cancellation}),
            appointment(),
        ),
    ];
    for (operation, input, expected) in cases {
        let CallOutcome::Success(value) = adapters
            .call(&scheduling_command(operation, deadline, input))
            .await
        else {
            panic!("{operation:?} did not succeed");
        };
        assert_eq!(value, expected, "{operation:?}");
        assert_eq!(contract(operation).check_output(&value), Ok(()));
    }
    product.verify().await;
}

#[tokio::test]
async fn unkeyed_hold_release_holds_an_ambiguous_dispatch_without_replay() {
    let token = MockServer::start().await;
    let authority = MockServer::start().await;
    let product = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let deadline = chrono::Utc::now().timestamp() + 120;
    let adapters = fixture(
        root.path(),
        &token,
        &authority,
        &product,
        deadline,
        FixtureBinding::default(),
    )
    .await;
    Mock::given(method("DELETE"))
        .and(path("/v1/holds/hold-one"))
        .respond_with(ResponseTemplate::new(500).insert_header("traceparent", support::TRACE))
        .expect(1)
        .mount(&product)
        .await;
    let request = scheduling_command(
        Operation::ReleaseHold,
        deadline,
        json!({"grant":grant(deadline),"holdId":"hold-one"}),
    );
    assert!(request.idempotency_key.is_none());
    assert!(matches!(adapters.call(&request).await,
        CallOutcome::Uncertain { code } if code == "transport-uncertain"));
    assert_eq!(product.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn only_appointment_creation_and_confirmation_have_original_result_receipts() {
    let token = MockServer::start().await;
    let authority = MockServer::start().await;
    let product = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let deadline = chrono::Utc::now().timestamp() + 120;
    let adapters = fixture(
        root.path(),
        &token,
        &authority,
        &product,
        deadline,
        FixtureBinding::default(),
    )
    .await;
    let confirmation = json!({"hold":"hold-one","admission":null});
    Mock::given(method("POST"))
        .and(path("/v1/appointments/receipt"))
        .and(header("idempotency-key", "original-lifecycle-command"))
        .and(body_json(&confirmation))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("traceparent", support::TRACE)
                .set_body_json(appointment()),
        )
        .expect(1)
        .mount(&product)
        .await;
    let confirm = scheduling_command(
        Operation::ConfirmHold,
        deadline,
        json!({"grant":grant(deadline),"appointment":confirmation}),
    );
    assert!(matches!(adapters.reconcile(&confirm, None).await,
        ReconciliationOutcome::Confirmed(value) if value == appointment()));
    for request in [
        scheduling_command(
            Operation::CreateHold,
            deadline,
            json!({"grant":grant(deadline),"admission":admission_request()}),
        ),
        scheduling_command(
            Operation::RescheduleAppointment,
            deadline,
            json!({"grant":grant(deadline),"appointmentId":APPOINTMENT,"reschedule":{"observedRevision":1,"admission":admission_request()}}),
        ),
        scheduling_command(
            Operation::CancelAppointment,
            deadline,
            json!({"grant":grant(deadline),"appointmentId":APPOINTMENT,"cancellation":{"observedRevision":1,"reason":null}}),
        ),
    ] {
        assert!(matches!(adapters.reconcile(&request, None).await,
            ReconciliationOutcome::Unresolved { code } if code == "operation-unbound"));
    }
    assert_eq!(
        product.received_requests().await.unwrap().len(),
        1,
        "current appointment reads must not be used as command receipts"
    );
}

#[tokio::test]
async fn standing_reads_are_bounded_and_never_authorize_a_commitment() {
    let token = MockServer::start().await;
    let authority = MockServer::start().await;
    let product = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let deadline = chrono::Utc::now().timestamp() + 120;
    let adapters = fixture(
        root.path(),
        &token,
        &authority,
        &product,
        deadline,
        FixtureBinding {
            task: false,
            observe: false,
            ..Default::default()
        },
    )
    .await;
    Mock::given(method("GET")).and(path("/v1/scheduling"))
        .respond_with(ResponseTemplate::new(200).insert_header("traceparent",support::TRACE)
            .set_body_json(json!({"schedulingId":"appointments","policyRevision":1,"policyDigest":"sha256:policy"})))
        .expect(1).mount(&product).await;
    Mock::given(method("GET"))
        .and(path("/v1/availability"))
        .and(query_param("offering", "application-review"))
        .and(query_param("limit", "20"))
        .and(query_param("start", "2026-10-10T10:00:00Z"))
        .and(query_param("end", "2026-10-10T11:00:00Z"))
        .and(query_param("resource", "room-a"))
        .and(query_param("durationMinutes", "120"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("traceparent", support::TRACE)
                .set_body_json(json!({"items":[],"nextCursor":null})),
        )
        .expect(1)
        .mount(&product)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/appointments/{APPOINTMENT}")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("traceparent", support::TRACE)
                .set_body_json(appointment()),
        )
        .expect(1)
        .mount(&product)
        .await;
    let metadata = CallRequest {
        operation_contract: None,
        connection: "bookings".into(),
        operation: Operation::ReadScheduling,
        input: json!({}),
        idempotency_key: None,
    };
    let CallOutcome::Success(service) = adapters.call(&metadata).await else {
        panic!("the scheduling metadata read succeeds");
    };
    assert_eq!(
        contract(Operation::ReadScheduling).check_output(&service),
        Ok(())
    );
    let mut read = CallRequest {
        operation_contract: None,
        connection: "bookings".into(),
        operation: Operation::ReadAvailability,
        input: json!({"offering":"application-review","start":"2026-10-10T10:00:00Z","end":"2026-10-10T11:00:00Z","limit":20,"resource":"room-a","durationMinutes":120}),
        idempotency_key: None,
    };
    assert_eq!(
        contract(Operation::ReadAvailability).check_input(&read.input),
        Ok(())
    );
    let CallOutcome::Success(page) = adapters.call(&read).await else {
        panic!("the availability read succeeds");
    };
    assert_eq!(
        contract(Operation::ReadAvailability).check_output(&page),
        Ok(())
    );
    let preview_operation = Operation::parse("scheduling.preview-availability/v1")
        .expect("physical preview is a registered read");
    let preview_body = json!({"offering":"application-review","start":"2026-10-10T10:00:00Z","additionalAllocations":[{"offering":"chairs","units":30}]});
    let preview_answer = json!({"offering":"application-review","start":"2026-10-10T10:00:00Z","end":"2026-10-10T11:00:00Z","capacityAvailable":true});
    Mock::given(method("POST"))
        .and(path("/v1/availability/preview"))
        .and(body_json(&preview_body))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("traceparent", support::TRACE)
                .set_body_json(&preview_answer),
        )
        .expect(1)
        .mount(&product)
        .await;
    let preview = CallRequest {
        operation_contract: None,
        connection: "bookings".into(),
        operation: preview_operation,
        input: json!({"preview":preview_body}),
        idempotency_key: None,
    };
    assert_eq!(
        contract(preview_operation).check_input(&preview.input),
        Ok(())
    );
    assert!(matches!(adapters.call(&preview).await,
        CallOutcome::Success(value) if value == preview_answer));
    for forbidden in [
        "manager",
        "duplicateKey",
        "externalReferences",
        "capabilities",
    ] {
        let mut bad = preview.clone();
        bad.input["preview"][forbidden] = json!("not-authority");
        assert!(contract(preview_operation).check_input(&bad.input).is_err());
        assert!(matches!(adapters.call(&bad).await,
            CallOutcome::Refused { code } if code == "invalid-command"));
    }
    let appointment_read = scheduling_command(
        Operation::ReadAppointment,
        deadline,
        json!({"appointmentId":APPOINTMENT}),
    );
    let CallOutcome::Success(appointment) = adapters.call(&appointment_read).await else {
        panic!("the appointment read succeeds");
    };
    assert_eq!(
        contract(Operation::ReadAppointment).check_output(&appointment),
        Ok(())
    );
    for bad in [
        0,
        registry_scheduling_client::MAXIMUM_BOOKING_DURATION_MINUTES + 1,
    ] {
        read.input["durationMinutes"] = json!(bad);
        assert!(contract(Operation::ReadAvailability)
            .check_input(&read.input)
            .is_err());
        assert!(
            matches!(adapters.call(&read).await,CallOutcome::Refused{code} if code=="invalid-command")
        );
    }
    read.input["durationMinutes"] = json!(120);
    let mut invalid_resource = read.input.clone();
    invalid_resource["resource"] = json!("../room-a");
    assert!(contract(Operation::ReadAvailability)
        .check_input(&invalid_resource)
        .is_err());
    for bad in [json!(0), json!(101)] {
        read.input["limit"] = bad;
        assert!(
            matches!(adapters.call(&read).await,CallOutcome::Refused{code} if code=="invalid-command")
        );
    }
    for request in [
        command(deadline),
        scheduling_command(
            Operation::CreateHold,
            deadline,
            json!({"grant":grant(deadline),"admission":admission_request()}),
        ),
        scheduling_command(
            Operation::ReleaseHold,
            deadline,
            json!({"grant":grant(deadline),"holdId":"hold-one"}),
        ),
        scheduling_command(
            Operation::ConfirmHold,
            deadline,
            json!({"grant":grant(deadline),"appointment":{"hold":"hold-one","admission":null}}),
        ),
        scheduling_command(
            Operation::RescheduleAppointment,
            deadline,
            json!({"grant":grant(deadline),"appointmentId":APPOINTMENT,
                "reschedule":{"observedRevision":1,"admission":admission_request()}}),
        ),
        scheduling_command(
            Operation::CancelAppointment,
            deadline,
            json!({"grant":grant(deadline),"appointmentId":APPOINTMENT,
                "cancellation":{"observedRevision":1,"reason":null}}),
        ),
    ] {
        assert!(
            matches!(adapters.call(&request).await,CallOutcome::Refused{code} if code=="invalid-command"),
            "{:?}",
            request.operation,
        );
    }
    assert!(authority.received_requests().await.unwrap().is_empty());
    assert_eq!(product.received_requests().await.unwrap().len(), 4);
}

#[tokio::test]
async fn each_attempt_reacquires_exact_task_authority_and_never_retries_in_the_client() {
    let token = MockServer::start().await;
    let authority = MockServer::start().await;
    let product = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let deadline = chrono::Utc::now().timestamp() + 120;
    let adapters = fixture(
        root.path(),
        &token,
        &authority,
        &product,
        deadline,
        FixtureBinding::default(),
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/v1/appointments"))
        .and(header("idempotency-key", "original-booking-command"))
        .and(body_json(admission()))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("traceparent", support::TRACE)
                .set_body_string("private-response-canary"),
        )
        .expect(2)
        .mount(&product)
        .await;
    for _ in 0..2 {
        assert!(
            matches!(adapters.call(&command(deadline)).await,CallOutcome::Uncertain{code} if code=="transport-uncertain")
        );
    }
    let grants = authority.received_requests().await.unwrap();
    assert_eq!(grants.len(), 2);
    assert!(grants.iter().all(|request| request.body.is_empty()
        && request.headers.get("registry-casework-profile").is_none()));
    assert_eq!(product.received_requests().await.unwrap().len(), 2);
    assert_eq!(
        token.received_requests().await.unwrap().len(),
        4,
        "bootstrap and task exchange freshly on every durable attempt"
    );
}

#[tokio::test]
async fn mismatched_principal_resource_deadline_and_revocation_refuse_without_product_io() {
    for (subject, resource) in [
        ("unapproved-agent", "urn:example:scheduling"),
        ("approved-agent", "urn:example:other"),
    ] {
        let token = MockServer::start().await;
        let authority = MockServer::start().await;
        let product = MockServer::start().await;
        let root = tempfile::tempdir().unwrap();
        let deadline = chrono::Utc::now().timestamp() + 120;
        let adapters = fixture(
            root.path(),
            &token,
            &authority,
            &product,
            deadline,
            FixtureBinding {
                subject,
                resource,
                ..Default::default()
            },
        )
        .await;
        assert!(
            matches!(adapters.call(&command(deadline)).await,CallOutcome::Refused{code} if code=="credential-refused")
        );
        assert!(product.received_requests().await.unwrap().is_empty());
        assert_eq!(
            token.received_requests().await.unwrap().len(),
            1,
            "mismatch refuses before token exchange"
        );
    }
    let token = MockServer::start().await;
    let authority = MockServer::start().await;
    let product = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let deadline = chrono::Utc::now().timestamp() + 120;
    let adapters = fixture(
        root.path(),
        &token,
        &authority,
        &product,
        deadline,
        FixtureBinding::default(),
    )
    .await;
    assert!(
        matches!(adapters.call(&command(deadline+1)).await,CallOutcome::Refused{code} if code=="credential-refused")
    );
    assert!(
        matches!(adapters.call(&command(chrono::Utc::now().timestamp()-1)).await,CallOutcome::Refused{code} if code=="credential-refused")
    );
    authority.reset().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_string("revoked-canary"))
        .expect(1)
        .mount(&authority)
        .await;
    assert!(
        matches!(adapters.call(&command(deadline)).await,CallOutcome::Refused{code} if code=="credential-refused")
    );
    assert!(product.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn reconciliation_uses_original_key_and_exact_request_without_a_fresh_effect() {
    let token = MockServer::start().await;
    let authority = MockServer::start().await;
    let product = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let deadline = chrono::Utc::now().timestamp() + 120;
    let adapters = fixture(
        root.path(),
        &token,
        &authority,
        &product,
        deadline,
        FixtureBinding::default(),
    )
    .await;
    assert_eq!(
        contract(Operation::CreateAppointment).check_output(&appointment()),
        Ok(())
    );
    Mock::given(method("POST"))
        .and(path("/v1/appointments/receipt"))
        .and(header("idempotency-key", "original-booking-command"))
        .and(body_json(admission()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("traceparent", support::TRACE)
                .set_body_json(appointment()),
        )
        .expect(1)
        .mount(&product)
        .await;
    assert!(
        matches!(adapters.reconcile(&command(deadline),None).await,ReconciliationOutcome::Confirmed(value) if value==appointment())
    );
    let received = product.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].url.path(), "/v1/appointments/receipt");
}

#[tokio::test]
async fn observation_identity_can_read_original_receipt_after_deadline_but_cannot_commit() {
    let token = MockServer::start().await;
    let authority = MockServer::start().await;
    let product = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let deadline = chrono::Utc::now().timestamp() - 1;
    let adapters = fixture(
        root.path(),
        &token,
        &authority,
        &product,
        deadline,
        FixtureBinding {
            observe: true,
            ..Default::default()
        },
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/v1/appointments/receipt"))
        .and(header("idempotency-key", "original-booking-command"))
        .and(body_json(admission()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("traceparent", support::TRACE)
                .set_body_json(appointment()),
        )
        .expect(1)
        .mount(&product)
        .await;
    assert!(
        matches!(adapters.call(&command(deadline)).await,CallOutcome::Refused{code} if code=="credential-refused")
    );
    assert!(
        matches!(adapters.reconcile(&command(deadline),None).await,ReconciliationOutcome::Confirmed(value) if value==appointment())
    );
    assert!(
        authority.received_requests().await.unwrap().is_empty(),
        "observation never renews an expired approval"
    );
    assert_eq!(product.received_requests().await.unwrap().len(), 1);
    let acquired = token.received_requests().await.unwrap();
    assert_eq!(acquired.len(), 1);
    let form: std::collections::BTreeMap<String, String> =
        url::form_urlencoded::parse(&acquired[0].body)
            .into_owned()
            .collect();
    assert_eq!(form["grant_type"], "client_credentials");
    assert_eq!(form["scope"], "scheduling:read");
    assert!(!form.contains_key("subject_token"));
}

#[tokio::test]
async fn unavailable_observation_never_reacquires_task_authority_or_replays_command() {
    let token = MockServer::start().await;
    let authority = MockServer::start().await;
    let product = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let deadline = chrono::Utc::now().timestamp() - 1;
    let adapters = fixture(
        root.path(),
        &token,
        &authority,
        &product,
        deadline,
        FixtureBinding::default(),
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(403))
        .with_priority(1)
        .expect(1)
        .mount(&token)
        .await;
    assert!(matches!(adapters.reconcile(&command(deadline), None).await,
        ReconciliationOutcome::Unresolved { code } if code == "observation-unavailable"));
    assert!(authority.received_requests().await.unwrap().is_empty());
    assert!(product.received_requests().await.unwrap().is_empty());
    assert_eq!(token.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn absent_expired_or_mismatched_receipts_never_become_evidence_of_no_effect() {
    let token = MockServer::start().await;
    let authority = MockServer::start().await;
    let product = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let deadline = chrono::Utc::now().timestamp() + 120;
    let adapters = fixture(
        root.path(),
        &token,
        &authority,
        &product,
        deadline,
        FixtureBinding {
            observe: true,
            ..Default::default()
        },
    )
    .await;
    let code = registry_scheduling_client::ProblemCode::ReceiptUnresolved;
    Mock::given(method("POST")).and(path("/v1/appointments/receipt"))
        .respond_with(ResponseTemplate::new(code.http_status()).insert_header("traceparent",support::TRACE)
            .set_body_raw(json!({"type":registry_scheduling_client::type_uri(code.code()),"title":code.title(),
                "status":code.http_status(),"detail":code.detail(),"code":code.code(),"traceId":"4bf92f3577b34da6a3ce929d0e0e4736"}).to_string(),"application/problem+json"))
        .expect(1).mount(&product).await;
    assert!(
        matches!(adapters.reconcile(&command(deadline),Some(&json!({"appointmentId":"operator-invented-id"}))).await,
        ReconciliationOutcome::Unresolved{code} if code=="receipt-unresolved")
    );
    assert!(authority.received_requests().await.unwrap().is_empty());
    assert_eq!(product.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn expired_mutation_receipt_and_bounded_invalid_answer_have_distinct_safe_outcomes() {
    let token = MockServer::start().await;
    let authority = MockServer::start().await;
    let product = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let deadline = chrono::Utc::now().timestamp() + 120;
    let adapters = fixture(
        root.path(),
        &token,
        &authority,
        &product,
        deadline,
        FixtureBinding::default(),
    )
    .await;
    let code = registry_scheduling_client::ProblemCode::IdempotencyExpired;
    Mock::given(method("POST")).and(path("/v1/appointments"))
        .respond_with(ResponseTemplate::new(code.http_status()).insert_header("traceparent",support::TRACE)
            .set_body_raw(json!({"type":registry_scheduling_client::type_uri(code.code()),"title":code.title(),
                "status":code.http_status(),"detail":code.detail(),"code":code.code(),"traceId":"4bf92f3577b34da6a3ce929d0e0e4736"}).to_string(),"application/problem+json"))
        .expect(1).mount(&product).await;
    assert!(matches!(
        adapters.call(&command(deadline)).await,
        CallOutcome::ReceiptExpired
    ));
    product.verify().await;
    product.reset().await;
    Mock::given(method("POST"))
        .and(path("/v1/appointments"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("traceparent", support::TRACE)
                .set_body_raw("x".repeat(65_537), "application/json"),
        )
        .expect(1)
        .mount(&product)
        .await;
    assert!(
        matches!(adapters.call(&command(deadline)).await,CallOutcome::Uncertain{code} if code=="transport-uncertain")
    );
    assert_eq!(product.received_requests().await.unwrap().len(), 1);
}
