// SPDX-License-Identifier: Apache-2.0

//! A platform-signed event admission to Registry Coordinator. This
//! connector deliberately links no Coordinator crate or client: it uses
//! the shared hook envelope, Standard Webhooks signature, and fixed event
//! destination transport that the Coordinator receiver verifies.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use registry_platform_crypto::delivery_signature::{sign, DeliveryKeys};
use registry_platform_hooks::{Causation, EnvelopeLimits, EventSubject, HookEnvelope};
use registry_platform_httputil::destination::{
    DestinationDeliveryCertainty, EventDestinationPolicy, EventDestinationRequestTemplate,
    SignedEventHeaders, MAX_DESTINATION_REQUEST_HEADER_BYTES, MAX_DESTINATION_TARGET_BYTES,
};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

const MAX_PROBLEM_BYTES: usize = 65_536;
const MAX_REQUEST_BYTES: usize = registry_platform_hooks::MAX_ENVELOPE_BYTES
    + MAX_DESTINATION_REQUEST_HEADER_BYTES
    + MAX_DESTINATION_TARGET_BYTES;
const CANONICAL_BODY_IDENTITY_DOMAIN: &[u8] = b"registry-adapter/coordinator-canonical-body/v1";

/// Stable, value-free outcomes of one signed Coordinator admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinatorEventOutcome {
    /// Coordinator admitted or recovered the event's one Run.
    Admitted { run_id: String },
    /// The item cannot produce one valid Standard Webhooks event. Nothing was
    /// sent, so the job may record an item-scoped refusal and continue.
    Unsignable,
    /// The event itself does not satisfy the reviewed trigger contract.
    Refused { code: &'static str },
    /// The deployment, authority, or response contract is unavailable.
    Stop { code: &'static str },
    /// The request may have been admitted but no trustworthy answer arrived.
    Uncertain,
}

/// Item-owned event material. Destination identity and signing authority
/// remain connector configuration, outside the mapping seam.
#[derive(Clone, Debug)]
pub struct CoordinatorEvent {
    /// Stable UUID derived by the job host from job and item identity.
    pub id: String,
    /// Source commit time, normalized by [`HookEnvelope`].
    pub time: OffsetDateTime,
    /// The source resource and positive revision.
    pub subject: EventSubject,
    /// The job's reviewed projection under the trigger's data contract.
    pub data: Value,
}

impl CoordinatorEvent {
    /// Build the job destination's fixed projection event. The event time is
    /// the persisted item-table sequence event time, never the delivery attempt's
    /// current clock, so a lost answer re-signs identical envelope bytes.
    pub fn projected(
        id: impl Into<String>,
        first_seen: SystemTime,
        record_reference: impl Into<String>,
        record_revision: i64,
        data: Value,
    ) -> Result<Self, CoordinatorEventConfigError> {
        if record_revision < 1 {
            return Err(CoordinatorEventConfigError::Invalid);
        }
        let time = OffsetDateTime::from(first_seen);
        Ok(Self {
            id: id.into(),
            time,
            subject: EventSubject::record(record_reference, record_revision),
            data,
        })
    }
}

/// Value-free activation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CoordinatorEventConfigError {
    #[error("the Coordinator event destination configuration is invalid")]
    Invalid,
}

/// One reviewed event trigger contract under the connector's shared
/// destination authority and authenticated source.
pub struct CoordinatorEventReceiver {
    template: EventDestinationRequestTemplate,
    keys: DeliveryKeys,
    event_type: String,
    data_schema: String,
}

impl std::fmt::Debug for CoordinatorEventReceiver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CoordinatorEventReceiver([REDACTED])")
    }
}

impl CoordinatorEventReceiver {
    /// Freeze one workflow trigger, its exact request target, and its event
    /// contract and its delivery keys. The destination policy and source
    /// remain shared connector state.
    pub fn new(
        workflow: &str,
        trigger: &str,
        event_type: &str,
        data_schema: &str,
        keys: DeliveryKeys,
    ) -> Result<Self, CoordinatorEventConfigError> {
        if !local_id(workflow)
            || !local_id(trigger)
            || !visible_bounded(event_type, 256)
            || !visible_bounded(data_schema, 2_048)
        {
            return Err(CoordinatorEventConfigError::Invalid);
        }
        let target = format!("/v1/events/{workflow}/{trigger}");
        let template = EventDestinationRequestTemplate::signed_event_delivery(
            &target,
            registry_platform_hooks::MAX_ENVELOPE_BYTES,
            MAX_REQUEST_BYTES,
        )
        .map_err(|_| CoordinatorEventConfigError::Invalid)?;
        Ok(Self {
            template,
            keys,
            event_type: event_type.to_string(),
            data_schema: data_schema.to_string(),
        })
    }
}

/// One frozen destination authority and source. One
/// connector may serve the primary and optional revised trigger of the same
/// workflow without duplicating or widening that authority.
pub struct CoordinatorEventConnector {
    policy: Arc<EventDestinationPolicy>,
    source: String,
    timeout: Duration,
}

impl std::fmt::Debug for CoordinatorEventConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CoordinatorEventConnector([REDACTED])")
    }
}

impl CoordinatorEventConnector {
    /// Freeze a reviewed workflow trigger on an already validated event
    /// destination policy. The path and complete header shape cannot vary
    /// per item.
    pub fn new(
        policy: Arc<EventDestinationPolicy>,
        source: &str,
        timeout: Duration,
    ) -> Result<Self, CoordinatorEventConfigError> {
        if !visible_bounded(source, 2_048)
            || timeout.is_zero()
            || timeout > registry_platform_httputil::destination::MAX_DESTINATION_OPERATION_TIMEOUT
        {
            return Err(CoordinatorEventConfigError::Invalid);
        }
        Ok(Self {
            policy,
            source: source.to_string(),
            timeout,
        })
    }

    /// Hash the exact canonical envelope bytes this connector would send for
    /// one event. A job host persists this digest as progress metadata before
    /// the first wire attempt, so a pending retry cannot change an event body
    /// while retaining or replacing its logical admission identity.
    pub fn canonical_body_digest(
        &self,
        receiver: &CoordinatorEventReceiver,
        event: &CoordinatorEvent,
    ) -> Result<[u8; 32], CoordinatorEventConfigError> {
        let (_, body) = self.canonical_envelope(receiver, event.clone())?;
        Ok(registry_platform_crypto::domain_separated_sha256(
            CANONICAL_BODY_IDENTITY_DOMAIN,
            &body,
        ))
    }

    fn canonical_envelope(
        &self,
        receiver: &CoordinatorEventReceiver,
        event: CoordinatorEvent,
    ) -> Result<(HookEnvelope, Vec<u8>), CoordinatorEventConfigError> {
        if Uuid::parse_str(&event.id).is_err() {
            return Err(CoordinatorEventConfigError::Invalid);
        }
        let envelope = HookEnvelope {
            id: event.id,
            event_type: receiver.event_type.clone(),
            source: self.source.clone(),
            time: event.time,
            subject: event.subject,
            dataschema: receiver.data_schema.clone(),
            data: event.data,
            causation: Causation::root(""),
        };
        let mut envelope = envelope;
        envelope.causation = Causation::root(&envelope.id);
        let body = envelope
            .to_canonical_bytes(&EnvelopeLimits::default())
            .map_err(|_| CoordinatorEventConfigError::Invalid)?;
        Ok((envelope, body))
    }

    /// Sign and send one canonical envelope. A retry reuses `event.id` and
    /// body, while delivery time and signature are fresh transport fields.
    pub async fn admit(
        &self,
        receiver: &CoordinatorEventReceiver,
        event: CoordinatorEvent,
        generation: i64,
        delivery_attempt: i64,
    ) -> CoordinatorEventOutcome {
        if generation < 1 || delivery_attempt < 1 {
            return CoordinatorEventOutcome::Stop {
                code: "coordinator.event.invalid-metadata",
            };
        }
        let (envelope, body) = match self.canonical_envelope(receiver, event) {
            Ok(envelope) => envelope,
            Err(_) => return CoordinatorEventOutcome::Unsignable,
        };
        let Ok(send_time) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) else {
            return CoordinatorEventOutcome::Stop {
                code: "coordinator.event.signing-unavailable",
            };
        };
        let timestamp = send_time.as_secs();
        let Ok(signature) = sign(&receiver.keys, &envelope.id, timestamp, &body) else {
            return CoordinatorEventOutcome::Unsignable;
        };
        let timestamp = timestamp.to_string();
        let request = match receiver.template.render_signed_event(
            SignedEventHeaders {
                id: envelope.id.as_bytes(),
                timestamp: timestamp.as_bytes(),
                signature: signature.as_bytes(),
            },
            body,
        ) {
            Ok(request) => request,
            Err(_) => return CoordinatorEventOutcome::Unsignable,
        };
        let response = match self.policy.send(request, self.timeout).await {
            Ok(response) => response,
            Err(error) => {
                return if error.delivery_certainty() == DestinationDeliveryCertainty::MaybeSent {
                    CoordinatorEventOutcome::Uncertain
                } else {
                    CoordinatorEventOutcome::Stop {
                        code: "coordinator.event.unavailable",
                    }
                };
            }
        };
        let status = response.status();
        if status.as_u16() == 204 {
            let selected =
                response.selected_script_response_headers(["x-coordinator-run-id"].into_iter());
            let run_id = match selected {
                Ok(values) => values.into_iter().next().flatten(),
                Err(_) => None,
            };
            return match run_id.filter(|run| Uuid::parse_str(run).is_ok()) {
                Some(run_id) => CoordinatorEventOutcome::Admitted { run_id },
                None => CoordinatorEventOutcome::Uncertain,
            };
        }
        let content_type = response
            .selected_script_response_headers(["content-type"].into_iter())
            .ok()
            .and_then(|values| values.into_iter().next().flatten());
        if content_type.as_deref() != Some("application/problem+json") {
            return CoordinatorEventOutcome::Stop {
                code: "coordinator.event.invalid-answer",
            };
        }
        let body = match response.read_bounded(MAX_PROBLEM_BYTES).await {
            Ok(body) => body.to_event_answer(),
            Err(_) => {
                return CoordinatorEventOutcome::Stop {
                    code: "coordinator.event.invalid-answer",
                };
            }
        };
        let problem = serde_json::from_slice::<Value>(&body).ok();
        let code = problem
            .as_ref()
            .and_then(|problem| problem.get("code"))
            .and_then(Value::as_str);
        let document_status = problem
            .as_ref()
            .and_then(|problem| problem.get("status"))
            .and_then(Value::as_u64);
        if document_status != Some(u64::from(status.as_u16())) {
            return CoordinatorEventOutcome::Stop {
                code: "coordinator.event.invalid-answer",
            };
        }
        classify_problem(status.as_u16(), code)
    }
}

fn classify_problem(status: u16, code: Option<&str>) -> CoordinatorEventOutcome {
    match (status, code) {
        (400, Some("event.invalid")) => CoordinatorEventOutcome::Refused {
            code: "event.invalid",
        },
        (400, Some("input.invalid")) => CoordinatorEventOutcome::Refused {
            code: "input.invalid",
        },
        (413, Some("event.too-large")) => CoordinatorEventOutcome::Refused {
            code: "event.too-large",
        },
        (401, Some("event.unauthenticated")) => CoordinatorEventOutcome::Stop {
            code: "event.unauthenticated",
        },
        (405, Some("request.method-not-allowed")) => CoordinatorEventOutcome::Stop {
            code: "request.method-not-allowed",
        },
        (409, Some("admission.held")) => CoordinatorEventOutcome::Stop {
            code: "admission.held",
        },
        (409, Some("admission.recovery-only")) => CoordinatorEventOutcome::Stop {
            code: "admission.recovery-only",
        },
        (409, Some("binding.conflict")) => CoordinatorEventOutcome::Stop {
            code: "binding.conflict",
        },
        (409, Some("binding.live-conflict")) => CoordinatorEventOutcome::Stop {
            code: "binding.live-conflict",
        },
        (409, Some("definition.refused")) => CoordinatorEventOutcome::Stop {
            code: "definition.refused",
        },
        (409, Some("deployment.activation-changed")) => CoordinatorEventOutcome::Stop {
            code: "deployment.activation-changed",
        },
        (409, Some("deployment.refused")) => CoordinatorEventOutcome::Stop {
            code: "deployment.refused",
        },
        (409, Some("execution.held")) => CoordinatorEventOutcome::Stop {
            code: "execution.held",
        },
        (409, Some("idempotency.key-reused")) => CoordinatorEventOutcome::Stop {
            code: "idempotency.key-reused",
        },
        (400, Some("request.invalid")) => CoordinatorEventOutcome::Stop {
            code: "request.invalid",
        },
        (413, Some("request.body-too-large")) => CoordinatorEventOutcome::Stop {
            code: "request.body-too-large",
        },
        (500, Some("runtime.failure")) => CoordinatorEventOutcome::Stop {
            code: "runtime.failure",
        },
        (503, Some("audit.response-unavailable")) => CoordinatorEventOutcome::Stop {
            code: "audit.response-unavailable",
        },
        (503, Some("event.source-unavailable")) => CoordinatorEventOutcome::Stop {
            code: "event.source-unavailable",
        },
        (503, Some("service.unavailable")) => CoordinatorEventOutcome::Stop {
            code: "service.unavailable",
        },
        _ => CoordinatorEventOutcome::Stop {
            code: "coordinator.event.invalid-answer",
        },
    }
}

fn local_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn visible_bounded(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..0x7f).contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    use axum::body::{to_bytes, Body};
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
    use axum::routing::any;
    use axum::Router;
    use registry_platform_crypto::delivery_signature::{
        verify, DeliveryKey, DeliveryKeys, SignedContent, DELIVERY_TOLERANCE,
    };
    use registry_platform_httputil::destination::{DestinationProfile, EventDestinationPolicy};
    use serde_json::json;
    use tokio::net::TcpListener;

    use super::*;

    const EVENT_ID: &str = "572bbca9-8e29-456c-8d97-973303538349";
    const RUN_ID: &str = "20000000-0000-4000-8000-00000000000b";
    const SOURCE: &str = "urn:registry-adapter:job:case-daily";
    const EVENT_TYPE: &str = "org.example.case-submitted.v1";
    const DATA_SCHEMA: &str = "urn:example:schema:case-submitted:v1";
    const KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

    #[derive(Clone)]
    struct CapturedRequest {
        method: String,
        target: String,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    #[derive(Clone)]
    struct Answer {
        status: StatusCode,
        content_type: &'static str,
        body: Vec<u8>,
        run_id: Option<&'static str>,
    }

    impl Answer {
        fn admitted() -> Self {
            Self {
                status: StatusCode::NO_CONTENT,
                content_type: "application/json",
                body: Vec::new(),
                run_id: Some(RUN_ID),
            }
        }

        fn problem(status: u16, code: &str) -> Self {
            Self {
                status: StatusCode::from_u16(status).expect("a response status"),
                content_type: "application/problem+json",
                body: serde_json::to_vec(&json!({"code": code, "status": status}))
                    .expect("a problem document"),
                run_id: None,
            }
        }
    }

    #[derive(Clone)]
    struct ReceiverState {
        captured: Arc<Mutex<Vec<CapturedRequest>>>,
        answers: Arc<Mutex<VecDeque<Answer>>>,
    }

    async fn answer(State(state): State<ReceiverState>, request: Request<Body>) -> Response<Body> {
        let method = request.method().to_string();
        let target = request.uri().to_string();
        let headers = request.headers().clone();
        let body = to_bytes(
            request.into_body(),
            registry_platform_hooks::MAX_ENVELOPE_BYTES,
        )
        .await
        .expect("the fixture request stays bounded")
        .to_vec();
        state
            .captured
            .lock()
            .expect("the capture lock")
            .push(CapturedRequest {
                method,
                target,
                headers,
                body,
            });
        let answer = state
            .answers
            .lock()
            .expect("the answer lock")
            .pop_front()
            .expect("one scripted answer per request");
        let mut response = Response::new(Body::from(answer.body));
        *response.status_mut() = answer.status;
        response.headers_mut().insert(
            "content-type",
            HeaderValue::from_static(answer.content_type),
        );
        if let Some(run_id) = answer.run_id {
            response
                .headers_mut()
                .insert("x-coordinator-run-id", HeaderValue::from_static(run_id));
        }
        response
    }

    struct FixtureReceiver {
        origin: String,
        captured: Arc<Mutex<Vec<CapturedRequest>>>,
        server: tokio::task::JoinHandle<()>,
    }

    impl FixtureReceiver {
        async fn start(answers: Vec<Answer>) -> Self {
            let captured = Arc::new(Mutex::new(Vec::new()));
            let state = ReceiverState {
                captured: Arc::clone(&captured),
                answers: Arc::new(Mutex::new(VecDeque::from(answers))),
            };
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind the fixture receiver");
            let address = listener.local_addr().expect("the fixture address");
            let server = tokio::spawn(async move {
                axum::serve(
                    listener,
                    Router::new().fallback(any(answer)).with_state(state),
                )
                .await
                .expect("serve the fixture receiver");
            });
            Self {
                origin: format!("http://{address}/"),
                captured,
                server,
            }
        }

        fn requests(&self) -> Vec<CapturedRequest> {
            self.captured.lock().expect("the capture lock").clone()
        }
    }

    impl Drop for FixtureReceiver {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    fn connector(
        fixture: &FixtureReceiver,
    ) -> (CoordinatorEventConnector, CoordinatorEventReceiver) {
        let policy = EventDestinationPolicy::new(
            "coordinator-test",
            &fixture.origin,
            DestinationProfile::LoopbackHttp,
            &[],
        )
        .expect("the fixture origin is permitted");
        let connector =
            CoordinatorEventConnector::new(Arc::new(policy), SOURCE, Duration::from_secs(2))
                .expect("the connector configuration is valid");
        let receiver = CoordinatorEventReceiver::new(
            "case-ingestion",
            "submitted",
            EVENT_TYPE,
            DATA_SCHEMA,
            keys(KEY, None),
        )
        .expect("the receiver contract is valid");
        (connector, receiver)
    }

    fn event(data: Value) -> CoordinatorEvent {
        CoordinatorEvent::projected(
            EVENT_ID,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_225_600),
            "submissions/a",
            1,
            data,
        )
        .expect("the event is valid")
    }

    #[tokio::test]
    async fn an_unsignable_item_is_refused_without_sending() {
        let fixture = FixtureReceiver::start(vec![Answer::admitted()]).await;
        let (connector, receiver) = connector(&fixture);
        let outcome = connector
            .admit(
                &receiver,
                event(json!({"value": "x".repeat(registry_platform_hooks::MAX_ENVELOPE_BYTES)})),
                1,
                1,
            )
            .await;
        assert_eq!(outcome, CoordinatorEventOutcome::Unsignable);
        assert!(fixture.requests().is_empty());
    }

    #[tokio::test]
    async fn a_signed_event_carries_the_envelope_id_as_webhook_id_on_every_attempt() {
        let fixture = FixtureReceiver::start(vec![Answer::admitted(), Answer::admitted()]).await;
        let (connector, receiver) = connector(&fixture);
        let event = event(json!({"item": {"age": "045"}}));
        assert_eq!(
            connector.admit(&receiver, event.clone(), 1, 1).await,
            CoordinatorEventOutcome::Admitted {
                run_id: RUN_ID.to_string()
            }
        );
        assert_eq!(
            connector.admit(&receiver, event, 1, 2).await,
            CoordinatorEventOutcome::Admitted {
                run_id: RUN_ID.to_string()
            }
        );
        let requests = fixture.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].body, requests[1].body);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].target, "/v1/events/case-ingestion/submitted");
        for request in &requests {
            assert_eq!(request.headers["webhook-id"], EVENT_ID);
            let envelope =
                HookEnvelope::from_canonical_bytes(&request.body, &EnvelopeLimits::default())
                    .unwrap();
            assert_eq!(envelope.id, EVENT_ID);
        }
    }

    #[tokio::test]
    async fn a_signed_event_signs_id_timestamp_and_the_exact_body() {
        let fixture = FixtureReceiver::start(vec![Answer::admitted()]).await;
        let (connector, receiver) = connector(&fixture);
        connector
            .admit(&receiver, event(json!({"item": "value"})), 1, 1)
            .await;
        let requests = fixture.requests();
        let request = &requests[0];
        let header = |name: &str| request.headers[name].to_str().unwrap();
        assert_eq!(header("accept"), "application/json");
        assert_eq!(header("content-type"), "application/json");
        let mut application_headers = request
            .headers
            .keys()
            .map(|name| name.as_str())
            .filter(|name| !matches!(*name, "host" | "content-length"))
            .collect::<Vec<_>>();
        application_headers.sort_unstable();
        assert_eq!(
            application_headers,
            [
                "accept",
                "content-type",
                "webhook-id",
                "webhook-signature",
                "webhook-timestamp",
            ]
        );
        verify(
            &keys(KEY, None),
            SignedContent {
                id: header("webhook-id"),
                timestamp: header("webhook-timestamp"),
                signature: header("webhook-signature"),
                body: &request.body,
            },
            SystemTime::now(),
            DELIVERY_TOLERANCE,
        )
        .expect("the signature covers the id, timestamp and exact body");
    }

    #[tokio::test]
    async fn a_revised_trigger_signs_with_its_own_key() {
        let fixture = FixtureReceiver::start(vec![Answer::admitted()]).await;
        let (connector, _) = connector(&fixture);
        let revised_key = &[0x6a; 32];
        let receiver = CoordinatorEventReceiver::new(
            "case-ingestion",
            "revised",
            EVENT_TYPE,
            DATA_SCHEMA,
            keys(revised_key, None),
        )
        .unwrap();
        connector
            .admit(&receiver, event(json!({"item": "value"})), 1, 1)
            .await;
        let requests = fixture.requests();
        let request = &requests[0];
        assert_eq!(request.target, "/v1/events/case-ingestion/revised");
        let content = || SignedContent {
            id: request.headers["webhook-id"].to_str().unwrap(),
            timestamp: request.headers["webhook-timestamp"].to_str().unwrap(),
            signature: request.headers["webhook-signature"].to_str().unwrap(),
            body: &request.body,
        };
        let now = SystemTime::now();
        assert!(verify(&keys(KEY, None), content(), now, DELIVERY_TOLERANCE).is_err());
        verify(&keys(revised_key, None), content(), now, DELIVERY_TOLERANCE).unwrap();
    }

    #[tokio::test]
    async fn a_rotating_trigger_sends_the_current_signature_first() {
        let fixture = FixtureReceiver::start(vec![Answer::admitted()]).await;
        let (connector, _) = connector(&fixture);
        let previous_key = &[0x7a; 32];
        let receiver = CoordinatorEventReceiver::new(
            "case-ingestion",
            "submitted",
            EVENT_TYPE,
            DATA_SCHEMA,
            keys(KEY, Some(previous_key)),
        )
        .unwrap();
        connector
            .admit(&receiver, event(json!({"item": "value"})), 1, 1)
            .await;
        let requests = fixture.requests();
        let request = &requests[0];
        let timestamp = request.headers["webhook-timestamp"]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let current = sign(&keys(KEY, None), EVENT_ID, timestamp, &request.body).unwrap();
        let previous = sign(
            &keys(previous_key, None),
            EVENT_ID,
            timestamp,
            &request.body,
        )
        .unwrap();
        assert_eq!(
            request.headers["webhook-signature"],
            format!("{current} {previous}")
        );
    }

    fn keys(current: &[u8], previous: Option<&[u8]>) -> DeliveryKeys {
        DeliveryKeys::new(
            DeliveryKey::new(current).unwrap(),
            previous.map(|key| DeliveryKey::new(key).unwrap()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn the_current_coordinator_admission_matrix_is_closed() {
        let item_refusals = [
            (400, "event.invalid"),
            (400, "input.invalid"),
            (413, "event.too-large"),
        ];
        let deployment_stops = [
            (401, "event.unauthenticated"),
            (405, "request.method-not-allowed"),
            (409, "admission.held"),
            (409, "admission.recovery-only"),
            (409, "binding.conflict"),
            (409, "binding.live-conflict"),
            (409, "definition.refused"),
            (409, "deployment.activation-changed"),
            (409, "deployment.refused"),
            (409, "execution.held"),
            (409, "idempotency.key-reused"),
            (400, "request.invalid"),
            (413, "request.body-too-large"),
            (500, "runtime.failure"),
            (503, "audit.response-unavailable"),
            (503, "event.source-unavailable"),
            (503, "service.unavailable"),
        ];
        let answers = item_refusals
            .iter()
            .chain(&deployment_stops)
            .map(|(status, code)| Answer::problem(*status, code))
            .collect();
        let fixture = FixtureReceiver::start(answers).await;
        let (connector, receiver) = connector(&fixture);
        for (status, code) in item_refusals {
            assert_eq!(
                connector
                    .admit(&receiver, event(json!({"status": status})), 1, 1)
                    .await,
                CoordinatorEventOutcome::Refused { code },
                "{status} {code}"
            );
        }
        for (status, code) in deployment_stops {
            assert_eq!(
                connector
                    .admit(&receiver, event(json!({"status": status})), 1, 1)
                    .await,
                CoordinatorEventOutcome::Stop { code },
                "{status} {code}"
            );
        }
    }

    #[tokio::test]
    async fn an_unknown_mismatched_or_non_problem_answer_fails_closed() {
        let fixture = FixtureReceiver::start(vec![
            Answer::problem(409, "event.invalid"),
            Answer::problem(409, "future.problem"),
            Answer {
                status: StatusCode::BAD_REQUEST,
                content_type: "application/json",
                body: serde_json::to_vec(&json!({"code": "event.invalid", "status": 400})).unwrap(),
                run_id: None,
            },
        ])
        .await;
        let (connector, receiver) = connector(&fixture);
        for _ in 0..3 {
            assert_eq!(
                connector
                    .admit(&receiver, event(json!({"item": true})), 1, 1)
                    .await,
                CoordinatorEventOutcome::Stop {
                    code: "coordinator.event.invalid-answer"
                }
            );
        }
    }

    #[test]
    fn event_receiver_validation_is_value_free_and_bounded() {
        assert_eq!(
            CoordinatorEventReceiver::new(
                "Bad",
                "trigger",
                EVENT_TYPE,
                DATA_SCHEMA,
                keys(KEY, None)
            )
            .expect_err("the workflow id is invalid"),
            CoordinatorEventConfigError::Invalid
        );
        assert_eq!(
            CoordinatorEventReceiver::new("workflow", "trigger", "", DATA_SCHEMA, keys(KEY, None))
                .expect_err("the event type is empty"),
            CoordinatorEventConfigError::Invalid
        );
    }
}
