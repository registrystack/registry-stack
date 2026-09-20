// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::Router;
use chrono::{TimeZone as _, Utc};
use registry_scheduling_client::{
    type_uri, AdmissionRequest, AvailabilityEntry, BearerToken, CancelAppointmentRequest,
    CreateAppointmentRequest, PartyCounts, ProblemCode, RescheduleAppointmentRequest,
    SchedulingAuth, SchedulingClient, SchedulingClientConfig, SchedulingClientError,
    SchedulingProtocolFailure, TransportKind,
};
use url::Url;

const TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
const TRACE_ID: &str = "0123456789abcdef0123456789abcdef";

#[derive(Clone)]
struct Captured {
    method: String,
    uri: String,
    headers: HeaderMap,
    body: Bytes,
}

type Observations = Arc<Mutex<Vec<Captured>>>;

/// One route's canned answer, plus the record of every request it received.
#[derive(Clone)]
struct Fixture {
    observations: Observations,
    status: StatusCode,
    content_type: &'static str,
    body: String,
    /// Answered when the request carries a cursor, for round-trip checks.
    continuation: Option<String>,
    traced: bool,
}

impl Fixture {
    fn json(observations: &Observations, status: StatusCode, body: &str) -> Self {
        Self {
            observations: observations.clone(),
            status,
            content_type: "application/json",
            body: body.to_owned(),
            continuation: None,
            traced: true,
        }
    }

    fn with_content_type(mut self, content_type: &'static str) -> Self {
        self.content_type = content_type;
        self
    }

    fn observe(&self, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) {
        self.observations
            .lock()
            .expect("observations")
            .push(Captured {
                method: method.to_string(),
                uri: uri.to_string(),
                headers,
                body,
            });
    }

    fn respond(&self, uri: &Uri) -> (StatusCode, HeaderMap, String) {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            self.content_type.parse().expect("fixture content type"),
        );
        if self.traced {
            headers.insert("traceparent", HeaderValue::from_static(TRACEPARENT));
        }
        let body = match (
            uri.query().unwrap_or_default().contains("cursor="),
            &self.continuation,
        ) {
            (true, Some(continuation)) => continuation.clone(),
            _ => self.body.clone(),
        };
        (self.status, headers, body)
    }
}

async fn capture_get(
    State(fixture): State<Fixture>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    fixture.observe(method, uri.clone(), headers, Bytes::new());
    fixture.respond(&uri)
}

async fn capture_call(
    State(fixture): State<Fixture>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    fixture.observe(method, uri.clone(), headers, body);
    fixture.respond(&uri)
}

async fn spawn(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address").to_string();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });
    (address, server)
}

fn client(address: &str) -> SchedulingClient {
    SchedulingClient::new(SchedulingClientConfig::new(
        Url::parse(&format!("http://{address}/")).expect("fixture URL"),
    ))
    .expect("client")
}

fn auth(token: &BearerToken) -> SchedulingAuth<'_> {
    SchedulingAuth::new(token)
}

fn admission() -> AdmissionRequest {
    AdmissionRequest {
        offering: "registry-update-30".to_owned(),
        start: Utc.with_ymd_and_hms(2026, 10, 5, 2, 0, 0).unwrap(),
        party: PartyCounts {
            recipients: 1,
            attendees: 2,
        },
        channel: Some("public".to_owned()),
        duplicate_key: Some("subject:one".to_owned()),
        policy_revision: 4,
        window_revision: None,
        capabilities: Vec::new(),
        prerequisites: Vec::new(),
    }
}

const SCHEDULING_DOCUMENT: &str =
    r#"{"schedulingId":"scheduling-1","policyRevision":4,"policyDigest":"sha256:aa"}"#;

const APPOINTMENT_DOCUMENT: &str = concat!(
    r#"{"appointmentId":"appt-1","offering":"registry-update-30","#,
    r#""start":"2026-10-05T02:00:00Z","end":"2026-10-05T02:30:00Z","#,
    r#""resource":"station-1","units":1,"channel":null,"revision":2,"state":"confirmed","#,
    r#""policyRevision":4,"createdAt":"2026-10-04T09:00:00Z","cancelledAt":null}"#
);

#[tokio::test]
async fn scheduling_document_answers_with_the_parsed_service_and_trace() {
    let observations: Observations = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/v1/scheduling", get(capture_get))
        .with_state(Fixture::json(
            &observations,
            StatusCode::OK,
            SCHEDULING_DOCUMENT,
        ));
    let (address, server) = spawn(app).await;

    let token = BearerToken::new("fixture-secret").expect("fixture token");
    let complete = client(&address)
        .get_scheduling(auth(&token))
        .await
        .expect("scheduling document");

    assert_eq!(complete.value.scheduling_id, "scheduling-1");
    assert_eq!(complete.value.policy_revision, 4);
    assert_eq!(complete.value.policy_digest, "sha256:aa");
    assert_eq!(complete.trace_id, TRACE_ID);

    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 1);
    let captured = &observations[0];
    assert_eq!(captured.method, "GET");
    assert_eq!(captured.uri, "/v1/scheduling");
    assert_eq!(captured.headers["authorization"], "Bearer fixture-secret");
    assert_eq!(captured.headers["accept"], "application/json");
    assert!(!captured.headers.contains_key("registry-scheduling-profile"));
    assert!(!captured.headers.contains_key("idempotency-key"));
    server.abort();
}

#[tokio::test]
async fn catalogue_listings_forward_and_round_trip_the_cursor() {
    let observations: Observations = Arc::new(Mutex::new(Vec::new()));
    let page = r#"{"items":[],"nextCursor":"next"}"#;
    let app = Router::new()
        .route("/v1/services", get(capture_get))
        .route("/v1/offerings", get(capture_get))
        .route("/v1/resources", get(capture_get))
        .route("/v1/locations", get(capture_get))
        .with_state(Fixture::json(&observations, StatusCode::OK, page));
    let (address, server) = spawn(app).await;

    let token = BearerToken::new("fixture-secret").expect("fixture token");
    let client = client(&address);

    let services = client
        .list_services(auth(&token), None)
        .await
        .expect("first services page");
    assert_eq!(services.value.next_cursor.as_deref(), Some("next"));
    let services = client
        .list_services(auth(&token), services.value.next_cursor.as_deref())
        .await
        .expect("second services page");
    assert!(services.value.items.is_empty());

    let offerings = client
        .list_offerings(auth(&token), None)
        .await
        .expect("first offerings page");
    assert_eq!(offerings.value.next_cursor.as_deref(), Some("next"));
    let offerings = client
        .list_offerings(auth(&token), offerings.value.next_cursor.as_deref())
        .await
        .expect("second offerings page");
    assert!(offerings.value.items.is_empty());

    let resources = client
        .list_resources(auth(&token), None)
        .await
        .expect("first resources page");
    assert_eq!(resources.value.next_cursor.as_deref(), Some("next"));
    let resources = client
        .list_resources(auth(&token), resources.value.next_cursor.as_deref())
        .await
        .expect("second resources page");
    assert!(resources.value.items.is_empty());

    let locations = client
        .list_locations(auth(&token), None)
        .await
        .expect("first locations page");
    assert_eq!(locations.value.next_cursor.as_deref(), Some("next"));
    let locations = client
        .list_locations(auth(&token), locations.value.next_cursor.as_deref())
        .await
        .expect("second locations page");
    assert!(locations.value.items.is_empty());

    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 8);
    assert_eq!(observations[0].uri, "/v1/services");
    assert_eq!(observations[1].uri, "/v1/services?cursor=next");
    assert_eq!(observations[2].uri, "/v1/offerings");
    assert_eq!(observations[3].uri, "/v1/offerings?cursor=next");
    assert_eq!(observations[4].uri, "/v1/resources");
    assert_eq!(observations[5].uri, "/v1/resources?cursor=next");
    assert_eq!(observations[6].uri, "/v1/locations");
    assert_eq!(observations[7].uri, "/v1/locations?cursor=next");
    server.abort();
}

#[tokio::test]
async fn availability_forwards_the_exact_query_and_validates_its_selectors_locally() {
    let observations: Observations = Arc::new(Mutex::new(Vec::new()));
    let first_page = concat!(
        r#"{"items":[{"kind":"slot","start":"2026-10-05T02:00:00Z","#,
        r#""end":"2026-10-05T02:30:00Z","free":2}],"nextCursor":"next"}"#
    );
    // The continuation page answers in windows: the kind tag travels
    // untouched through the same bounded page envelope.
    let continuation = concat!(
        r#"{"items":[{"kind":"window","window":"household-morning-window","#,
        r#""start":"2026-10-10T08:00:00Z","end":"2026-10-10T10:00:00Z","#,
        r#""remaining":3,"channelRemaining":null}],"nextCursor":null}"#
    );
    let mut fixture = Fixture::json(&observations, StatusCode::OK, first_page);
    fixture.continuation = Some(continuation.to_owned());
    let app = Router::new()
        .route("/v1/availability", get(capture_get))
        .with_state(fixture);
    let (address, server) = spawn(app).await;

    let token = BearerToken::new("fixture-secret").expect("fixture token");
    let client = client(&address);
    let start = Utc.with_ymd_and_hms(2026, 10, 5, 2, 0, 0).unwrap();
    let end = Utc.with_ymd_and_hms(2026, 10, 5, 2, 30, 0).unwrap();

    let first = client
        .availability(
            auth(&token),
            "registry-update-30",
            Some(start),
            Some(end),
            None,
            Some(25),
        )
        .await
        .expect("first availability page");
    assert_eq!(
        first.value.items,
        vec![AvailabilityEntry::Slot {
            start,
            end,
            free: 2,
        }]
    );
    let second = client
        .availability(
            auth(&token),
            "registry-update-30",
            Some(start),
            Some(end),
            first.value.next_cursor.as_deref(),
            Some(25),
        )
        .await
        .expect("second availability page");
    assert_eq!(
        second.value.items,
        vec![AvailabilityEntry::Window {
            window: "household-morning-window".to_owned(),
            start: Utc.with_ymd_and_hms(2026, 10, 10, 8, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2026, 10, 10, 10, 0, 0).unwrap(),
            remaining: 3,
            channel_remaining: None,
        }]
    );
    assert_eq!(second.trace_id, TRACE_ID);

    assert!(matches!(
        client
            .availability(auth(&token), "", None, None, None, None)
            .await,
        Err(SchedulingClientError::InvalidRequest { .. })
    ));
    assert!(matches!(
        client
            .availability(
                auth(&token),
                "registry-update-30",
                None,
                None,
                Some(""),
                None
            )
            .await,
        Err(SchedulingClientError::InvalidRequest { .. })
    ));
    assert!(matches!(
        client
            .availability(
                auth(&token),
                "registry-update-30",
                None,
                None,
                None,
                Some(0)
            )
            .await,
        Err(SchedulingClientError::InvalidRequest { .. })
    ));
    client
        .availability(
            auth(&token),
            "registry-update-30",
            Some(start),
            Some(start),
            None,
            None,
        )
        .await
        .expect("equal bounds reach the runtime for normalization");
    client
        .availability(
            auth(&token),
            "registry-update-30",
            Some(end),
            Some(start),
            None,
            None,
        )
        .await
        .expect("reversed bounds reach the runtime for normalization");

    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 4);
    assert_eq!(
        observations[0].uri,
        "/v1/availability?offering=registry-update-30&start=2026-10-05T02%3A00%3A00Z&end=2026-10-05T02%3A30%3A00Z&limit=25"
    );
    assert_eq!(
        observations[1].uri,
        "/v1/availability?offering=registry-update-30&start=2026-10-05T02%3A00%3A00Z&end=2026-10-05T02%3A30%3A00Z&cursor=next&limit=25"
    );
    assert_eq!(
        observations[2].uri,
        "/v1/availability?offering=registry-update-30&start=2026-10-05T02%3A00%3A00Z&end=2026-10-05T02%3A00%3A00Z"
    );
    assert_eq!(
        observations[3].uri,
        "/v1/availability?offering=registry-update-30&start=2026-10-05T02%3A30%3A00Z&end=2026-10-05T02%3A00%3A00Z"
    );
    server.abort();
}

#[tokio::test]
async fn explain_forwards_offering_and_start() {
    let observations: Observations = Arc::new(Mutex::new(Vec::new()));
    let explain = concat!(
        r#"{"offering":"registry-update-30","start":"2026-10-05T02:00:00Z","#,
        r#""publicCode":"capacity.exhausted","detailedCode":"resource.unavailable","#,
        r#""explanation":"every capable member is unavailable"}"#
    );
    let app = Router::new()
        .route("/v1/availability/explain", get(capture_get))
        .with_state(Fixture::json(&observations, StatusCode::OK, explain));
    let (address, server) = spawn(app).await;

    let token = BearerToken::new("fixture-secret").expect("fixture token");
    let start = Utc.with_ymd_and_hms(2026, 10, 5, 2, 0, 0).unwrap();
    let complete = client(&address)
        .explain(auth(&token), "registry-update-30", start)
        .await
        .expect("explain document");
    assert_eq!(
        complete.value.public_code.as_deref(),
        Some("capacity.exhausted")
    );
    assert_eq!(
        complete.value.detailed_code.as_deref(),
        Some("resource.unavailable")
    );

    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 1);
    assert_eq!(
        observations[0].uri,
        "/v1/availability/explain?offering=registry-update-30&start=2026-10-05T02%3A00%3A00Z"
    );
    server.abort();
}

#[tokio::test]
async fn create_hold_sends_the_admission_body_under_its_idempotency_key() {
    let observations: Observations = Arc::new(Mutex::new(Vec::new()));
    let hold = concat!(
        r#"{"holdId":"hold-7","offering":"registry-update-30","#,
        r#""start":"2026-10-05T02:00:00Z","end":"2026-10-05T02:30:00Z","#,
        r#""resource":"station-1","units":1,"expiresAt":"2026-10-05T01:45:00Z","#,
        r#""policyRevision":4}"#
    );
    let app = Router::new()
        .route("/v1/holds", post(capture_call))
        .with_state(Fixture::json(&observations, StatusCode::CREATED, hold));
    let (address, server) = spawn(app).await;

    let token = BearerToken::new("fixture-secret").expect("fixture token");
    let request = admission();
    let complete = client(&address)
        .create_hold(auth(&token), "hold-7", &request)
        .await
        .expect("minted hold");
    assert_eq!(complete.value.hold_id, "hold-7");
    assert_eq!(complete.value.resource.as_deref(), Some("station-1"));

    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 1, "a hold is never retried");
    let captured = &observations[0];
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.uri, "/v1/holds");
    assert_eq!(captured.headers["idempotency-key"], "hold-7");
    assert_eq!(captured.headers["authorization"], "Bearer fixture-secret");
    let sent: AdmissionRequest = serde_json::from_slice(&captured.body).expect("sent admission");
    assert_eq!(sent, request);
    server.abort();
}

#[tokio::test]
async fn release_hold_deletes_and_accepts_an_exactly_empty_answer() {
    let observations: Observations = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/v1/holds/hold-7", delete(capture_call))
        .with_state(Fixture::json(&observations, StatusCode::NO_CONTENT, ""));
    let (address, server) = spawn(app).await;

    let token = BearerToken::new("fixture-secret").expect("fixture token");
    let complete = client(&address)
        .release_hold(auth(&token), "hold-7")
        .await
        .expect("released hold");
    assert_eq!(complete.value, ());
    assert_eq!(complete.trace_id, TRACE_ID);

    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 1);
    let captured = &observations[0];
    assert_eq!(captured.method, "DELETE");
    assert_eq!(captured.uri, "/v1/holds/hold-7");
    assert!(captured.body.is_empty());
    assert!(!captured.headers.contains_key("idempotency-key"));
    server.abort();
}

#[tokio::test]
async fn appointment_commands_carry_their_keys_and_exact_bodies() {
    let observations: Observations = Arc::new(Mutex::new(Vec::new()));
    let history = concat!(
        r#"{"items":[{"eventId":"event-1","kind":"created","revision":1,"occurredAt":"2026-10-04T09:00:00Z","#,
        r#""actor":"hmac-sha256:v2:8f0a","detail":{}}],"nextCursor":null}"#
    );
    let created = Fixture::json(&observations, StatusCode::CREATED, APPOINTMENT_DOCUMENT);
    let shown = Fixture::json(&observations, StatusCode::OK, APPOINTMENT_DOCUMENT);
    let moved = Fixture::json(&observations, StatusCode::OK, APPOINTMENT_DOCUMENT);
    let cancelled = Fixture::json(&observations, StatusCode::OK, APPOINTMENT_DOCUMENT);
    let history_page = Fixture::json(&observations, StatusCode::OK, history);
    let app = Router::new()
        .route("/v1/appointments", post(capture_call).with_state(created))
        .route(
            "/v1/appointments/appt-1",
            get(capture_get).with_state(shown),
        )
        .route(
            "/v1/appointments/appt-1/reschedule",
            post(capture_call).with_state(moved),
        )
        .route(
            "/v1/appointments/appt-1/cancel",
            post(capture_call).with_state(cancelled),
        )
        .route(
            "/v1/appointments/appt-1/history",
            get(capture_get).with_state(history_page),
        );
    let (address, server) = spawn(app).await;

    let token = BearerToken::new("fixture-secret").expect("fixture token");
    let client = client(&address);

    let create = CreateAppointmentRequest {
        hold: Some("hold-7".to_owned()),
        admission: None,
    };
    let confirmed = client
        .create_appointment(auth(&token), "create-1", &create)
        .await
        .expect("confirmed appointment");
    assert_eq!(confirmed.value.appointment_id, "appt-1");
    assert_eq!(confirmed.value.state.as_str(), "confirmed");

    let read = client
        .get_appointment(auth(&token), "appt-1")
        .await
        .expect("appointment");
    assert_eq!(read.value.revision, 2);

    let reschedule_admission = admission();
    let moved = client
        .reschedule_appointment(
            auth(&token),
            "appt-1",
            "move-1",
            &RescheduleAppointmentRequest {
                observed_revision: 2,
                admission: reschedule_admission.clone(),
            },
        )
        .await
        .expect("rescheduled appointment");
    assert_eq!(moved.trace_id, TRACE_ID);

    let cancelled = client
        .cancel_appointment(
            auth(&token),
            "appt-1",
            "cancel-1",
            &CancelAppointmentRequest {
                observed_revision: 2,
                reason: Some("plans changed".to_owned()),
            },
        )
        .await
        .expect("cancelled appointment");
    assert_eq!(cancelled.value.appointment_id, "appt-1");

    let history = client
        .appointment_history(auth(&token), "appt-1", Some("h-next"))
        .await
        .expect("history page");
    assert_eq!(history.value.items[0].event_id, "event-1");

    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 5);
    assert_eq!(observations[0].method, "POST");
    assert_eq!(observations[0].uri, "/v1/appointments");
    assert_eq!(observations[0].headers["idempotency-key"], "create-1");
    let sent_create: CreateAppointmentRequest =
        serde_json::from_slice(&observations[0].body).expect("sent create");
    assert_eq!(sent_create, create);
    assert_eq!(observations[1].method, "GET");
    assert_eq!(observations[1].uri, "/v1/appointments/appt-1");
    assert!(!observations[1].headers.contains_key("idempotency-key"));
    assert_eq!(observations[2].uri, "/v1/appointments/appt-1/reschedule");
    assert_eq!(observations[2].headers["idempotency-key"], "move-1");
    let sent_reschedule: RescheduleAppointmentRequest =
        serde_json::from_slice(&observations[2].body).expect("sent reschedule");
    assert_eq!(sent_reschedule.admission, reschedule_admission);
    assert_eq!(sent_reschedule.observed_revision, 2);
    // The wire request carries no exclusion of its own: the runtime supplies
    // the appointment's own claim from inside the reschedule transaction, so
    // the serialized admission names no claim to leave out of the check.
    let sent_reschedule_value: serde_json::Value =
        serde_json::from_slice(&observations[2].body).expect("sent reschedule as json");
    assert!(!sent_reschedule_value["admission"]
        .as_object()
        .expect("the admission is an object")
        .contains_key("rescheduleOf"));
    assert_eq!(observations[3].uri, "/v1/appointments/appt-1/cancel");
    assert_eq!(observations[3].headers["idempotency-key"], "cancel-1");
    let sent_cancel: CancelAppointmentRequest =
        serde_json::from_slice(&observations[3].body).expect("sent cancel");
    assert_eq!(sent_cancel.observed_revision, 2);
    assert_eq!(sent_cancel.reason.as_deref(), Some("plans changed"));
    assert_eq!(
        observations[4].uri,
        "/v1/appointments/appt-1/history?cursor=h-next"
    );
    server.abort();
}

#[tokio::test]
async fn an_exact_problem_document_maps_to_the_typed_runtime_code() {
    let observations: Observations = Arc::new(Mutex::new(Vec::new()));
    let problem = serde_json::json!({
        "type": type_uri(ProblemCode::CapacityExhausted.code()),
        "title": ProblemCode::CapacityExhausted.title(),
        "status": ProblemCode::CapacityExhausted.http_status(),
        "detail": ProblemCode::CapacityExhausted.detail(),
        "code": ProblemCode::CapacityExhausted.code(),
        "traceId": TRACE_ID,
    })
    .to_string();
    let app = Router::new()
        .route("/v1/holds", post(capture_call))
        .with_state(
            Fixture::json(&observations, StatusCode::CONFLICT, &problem)
                .with_content_type("application/problem+json"),
        );
    let (address, server) = spawn(app).await;

    let token = BearerToken::new("fixture-secret").expect("fixture token");
    let result = client(&address)
        .create_hold(auth(&token), "hold-7", &admission())
        .await;
    assert_eq!(
        result.as_ref().expect_err("refused hold").to_string(),
        "Registry Scheduling refused the request (HTTP 409, problem capacity.exhausted)"
    );
    match result {
        Err(SchedulingClientError::Problem {
            status: 409,
            code: ProblemCode::CapacityExhausted,
            trace_id,
        }) => assert_eq!(trace_id.as_deref(), Some(TRACE_ID)),
        other => panic!("expected a typed capacity problem, got {other:?}"),
    }
    server.abort();
}

#[tokio::test]
async fn edge_answers_stay_edge_talk() {
    let observations: Observations = Arc::new(Mutex::new(Vec::new()));
    let foreign_problem = serde_json::json!({
        "type": "https://example.test/problems/other/request/not-found",
        "title": "Route not found",
        "status": 404,
        "detail": "The requested route does not exist.",
        "code": "request.not-found",
        "traceId": TRACE_ID,
    })
    .to_string();
    let mut untraced = Fixture::json(&observations, StatusCode::OK, SCHEDULING_DOCUMENT);
    untraced.traced = false;
    let not_found = Fixture::json(&observations, StatusCode::NOT_FOUND, &foreign_problem)
        .with_content_type("application/problem+json");
    let plain_json = Fixture::json(
        &observations,
        StatusCode::INTERNAL_SERVER_ERROR,
        r#"{"nope":true}"#,
    );
    let garbage_problem = Fixture::json(
        &observations,
        StatusCode::INTERNAL_SERVER_ERROR,
        "this is not a problem document",
    )
    .with_content_type("application/problem+json");
    let wrong_media = Fixture::json(&observations, StatusCode::OK, r#"{"items":[]}"#)
        .with_content_type("text/plain");
    let unparseable = Fixture::json(&observations, StatusCode::CREATED, "not json");
    let app = Router::new()
        .route("/v1/scheduling", get(capture_get).with_state(untraced))
        .route("/v1/services", get(capture_get).with_state(not_found))
        .route("/v1/offerings", get(capture_get).with_state(plain_json))
        .route(
            "/v1/locations",
            get(capture_get).with_state(garbage_problem),
        )
        .route("/v1/resources", get(capture_get).with_state(wrong_media))
        .route("/v1/holds", post(capture_call).with_state(unparseable));
    let (address, server) = spawn(app).await;

    let token = BearerToken::new("fixture-secret").expect("fixture token");
    let client = client(&address);

    // A route-not-found problem from a foreign dialect carries a type base
    // outside this product's vocabulary: the edge talking. The product's own
    // request-edge codes are typed by the error taxonomy tests.
    assert!(matches!(
        client.list_services(auth(&token), None).await,
        Err(SchedulingClientError::Protocol {
            status: 404,
            failure: SchedulingProtocolFailure::Problem,
            ..
        })
    ));
    // A failure answer that is not a problem document at all.
    assert!(matches!(
        client.list_offerings(auth(&token), None).await,
        Err(SchedulingClientError::Protocol {
            status: 500,
            failure: SchedulingProtocolFailure::Status,
            ..
        })
    ));
    // A success answer in the wrong media type.
    assert!(matches!(
        client.list_resources(auth(&token), None).await,
        Err(SchedulingClientError::Protocol {
            status: 200,
            failure: SchedulingProtocolFailure::MediaType,
            ..
        })
    ));
    // A success answer with no trace context.
    assert!(matches!(
        client.get_scheduling(auth(&token)).await,
        Err(SchedulingClientError::Protocol {
            status: 200,
            failure: SchedulingProtocolFailure::TraceContext,
            ..
        })
    ));
    // A problem answer whose body is not an exact problem document.
    assert!(matches!(
        client.list_locations(auth(&token), None).await,
        Err(SchedulingClientError::Protocol {
            status: 500,
            failure: SchedulingProtocolFailure::Problem,
            ..
        })
    ));
    // A success answer whose body does not parse.
    assert!(matches!(
        client
            .create_hold(auth(&token), "hold-7", &admission())
            .await,
        Err(SchedulingClientError::Protocol {
            status: 201,
            failure: SchedulingProtocolFailure::Body,
            ..
        })
    ));

    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 6, "no failure is ever retried");
    server.abort();
}

#[tokio::test]
async fn oversized_answers_stay_bounded() {
    let observations: Observations = Arc::new(Mutex::new(Vec::new()));
    let page = format!("{{\"items\":[],\"nextCursor\":\"{}\"}}", "x".repeat(200));
    let app = Router::new()
        .route("/v1/resources", get(capture_get))
        .with_state(Fixture::json(&observations, StatusCode::OK, &page));
    let (address, server) = spawn(app).await;

    let token = BearerToken::new("fixture-secret").expect("fixture token");
    let bounded = SchedulingClient::new(
        SchedulingClientConfig::new(
            Url::parse(&format!("http://{address}/")).expect("fixture URL"),
        )
        .with_max_response_bytes(64),
    )
    .expect("client");
    match bounded.list_resources(auth(&token), None).await {
        Err(SchedulingClientError::Transport {
            kind: TransportKind::ResponseTooLarge,
        }) => {}
        other => panic!("expected a bounded-read refusal, got {other:?}"),
    }
    let observations = observations.lock().expect("observations");
    assert_eq!(observations.len(), 1);
    server.abort();
}

#[tokio::test]
async fn invalid_client_input_never_reaches_the_wire() {
    // Port 1 refuses every connection, so any attempted round trip would
    // surface as a transport failure instead of a request defect.
    let client = SchedulingClient::new(SchedulingClientConfig::new(
        Url::parse("http://127.0.0.1:1/").expect("fixture URL"),
    ))
    .expect("client");
    let token = BearerToken::new("fixture-secret").expect("fixture token");

    assert!(matches!(
        client.create_hold(auth(&token), "", &admission()).await,
        Err(SchedulingClientError::InvalidRequest { .. })
    ));
    let oversized_key = "x".repeat(129);
    assert!(matches!(
        client
            .create_hold(auth(&token), &oversized_key, &admission())
            .await,
        Err(SchedulingClientError::InvalidRequest { .. })
    ));
    assert!(matches!(
        client
            .cancel_appointment(
                auth(&token),
                "appt-1",
                "line\nbreak",
                &CancelAppointmentRequest {
                    observed_revision: 2,
                    reason: None,
                },
            )
            .await,
        Err(SchedulingClientError::InvalidRequest { .. })
    ));
    assert!(matches!(
        client.list_services(auth(&token), Some("")).await,
        Err(SchedulingClientError::InvalidRequest { .. })
    ));
    // An identifier that would split into several path segments never reaches
    // the wire as a different route.
    assert!(matches!(
        client.get_appointment(auth(&token), "appt/1").await,
        Err(SchedulingClientError::InvalidRequest { .. })
    ));
    assert!(matches!(
        client.release_hold(auth(&token), "../holds").await,
        Err(SchedulingClientError::InvalidRequest { .. })
    ));
}
