// SPDX-License-Identifier: Apache-2.0
//! Native Scheduling lifecycle events admitted by Coordinator and delivered
//! once to native Messaging through independently built public services.
#![cfg(feature = "postgres-test")]

mod support;

use axum::{
    body::Bytes, extract::State, http::HeaderMap, response::IntoResponse, routing::post, Router,
};
use chrono::{DateTime, Duration as ChronoDuration, Timelike, Utc};
use registry_coordinator::{
    deployment, problem::ProblemCode as CoordinatorProblemCode, runtime::RuntimeConfig,
};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_crypto::delivery_signature::{sign_v1, SignatureFields};
use registry_scheduling_client::{
    AdmissionRequest, CancelAppointmentRequest, CreateAppointmentRequest, ProblemCode,
    RescheduleAppointmentRequest, SchedulingClientError,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use support::{messaging::Messaging, scheduling::Scheduling};

const CONFIRMED_TARGET: &str = "/v1/events/scheduling-lifecycle/confirmed";
const RESCHEDULED_TARGET: &str = "/v1/events/scheduling-lifecycle/rescheduled";
const CANCELLED_TARGET: &str = "/v1/events/scheduling-lifecycle/cancelled";
const REMINDER_CONFIRMATION_TARGET: &str = "/v1/events/scheduling-lifecycle/reminder-confirmation";
const REMINDER_TARGET: &str = "/v1/events/scheduling-lifecycle/reminder";
type Delivery = (String, HeaderMap, Vec<u8>, u16, Option<String>);

#[derive(Clone, Default)]
struct Relay {
    destination: Arc<Mutex<Option<String>>>,
    deliveries: Arc<Mutex<Vec<Delivery>>>,
    responses: Arc<Mutex<Vec<(u16, Option<String>)>>>,
}

async fn forward(
    State((relay, target)): State<(Relay, &'static str)>,
    mut headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    headers.remove("host");
    let origin = relay
        .destination
        .lock()
        .unwrap()
        .clone()
        .expect("Coordinator starts before the lifecycle command");
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("{origin}{target}"))
        .headers(headers.clone())
        .body(body.clone())
        .send()
        .await
        .unwrap();
    let status = response.status();
    let run_id = response
        .headers()
        .get("x-coordinator-run-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let answer = response.bytes().await.unwrap();
    let problem_code = serde_json::from_slice::<Value>(&answer)
        .ok()
        .and_then(|document| {
            document["code"]
                .as_str()
                .and_then(CoordinatorProblemCode::from_code)
        })
        .map(|code| code.code().to_owned());
    relay
        .responses
        .lock()
        .unwrap()
        .push((status.as_u16(), problem_code));
    relay.deliveries.lock().unwrap().push((
        target.to_owned(),
        headers,
        body.to_vec(),
        status.as_u16(),
        run_id,
    ));
    (status, [("content-type", "application/json")], answer)
}

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct OwnedCoordinator {
    database: String,
    namespace: String,
    role: String,
}

impl OwnedCoordinator {
    async fn run_summary(&self) -> Option<Vec<(String, Option<String>, i64)>> {
        let (client, connection) = tokio::time::timeout(
            Duration::from_secs(2),
            tokio_postgres::connect(&self.database, tokio_postgres::NoTls),
        )
        .await
        .ok()?
        .ok()?;
        let task = tokio::spawn(connection);
        let rows = tokio::time::timeout(
            Duration::from_secs(2),
            client.query(
                &format!(
                    "SELECT state, failure_code, count(*) FROM {}.runs \
                     GROUP BY state, failure_code ORDER BY state, failure_code",
                    self.namespace
                ),
                &[],
            ),
        )
        .await;
        task.abort();
        Some(
            rows.ok()?
                .ok()?
                .iter()
                .map(|row| (row.get(0), row.get(1), row.get(2)))
                .collect(),
        )
    }
}

impl Drop for OwnedCoordinator {
    fn drop(&mut self) {
        let database = self.database.clone();
        let namespace = self.namespace.clone();
        let role = self.role.clone();
        let result = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let (admin, connection) =
                        tokio_postgres::connect(&database, tokio_postgres::NoTls).await?;
                    let task = tokio::spawn(connection);
                    admin
                        .batch_execute(&format!(
                            "DROP SCHEMA IF EXISTS {namespace} CASCADE; DROP ROLE IF EXISTS {role}"
                        ))
                        .await?;
                    task.abort();
                    Ok::<(), tokio_postgres::Error>(())
                })
        })
        .join();
        if !matches!(result, Ok(Ok(()))) {
            eprintln!("fixture-owned Coordinator cleanup failed");
        }
    }
}

async fn start_coordinator(config: &Path, origin: &str) -> Process {
    let log_path = config.with_extension("log");
    support::private_file(&log_path, b"");
    let log = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .unwrap();
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_coordinator"))
            .arg("--runtime-config")
            .arg(config)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "native Coordinator exited; inspect {}",
            log_path.display()
        );
        if reqwest::get(format!("{origin}/ready"))
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return process;
        }
        assert!(
            Instant::now() < deadline,
            "Coordinator not ready; inspect {}",
            log_path.display()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn data_schema(trigger: &str, projection: &[&str]) -> String {
    let mut projection = projection.to_vec();
    projection.sort_unstable();
    let canonical = canonicalize_json(&json!({
        "schemaVersion":"registry.scheduling-hook-data/v1",
        "trigger":trigger,
        "projection":projection,
    }))
    .unwrap();
    let digest = Sha256::digest(canonical);
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("urn:registrystack:scheduling:hook-data:sha256:{hex}")
}

fn next_minute(moment: DateTime<Utc>) -> DateTime<Utc> {
    let floor = moment.with_second(0).unwrap().with_nanosecond(0).unwrap();
    if floor == moment {
        floor
    } else {
        floor + ChronoDuration::minutes(1)
    }
}

fn write_project(root: &Path) {
    let projection = [
        "appointmentId",
        "offering",
        "start",
        "end",
        "policyRevision",
        "revision",
        "state",
    ];
    let cancellation = ["appointmentId", "revision", "state"];
    let event_schema = json!({"type":"object","required":["data"],"properties":{"data":{
        "type":"object","required":["appointmentId","state"],"properties":{
            "appointmentId":{"type":"string","format":"uuid"},
            "state":{"type":"string","enum":["confirmed","cancelled"]}
        }
    }}});
    let mapping = json!({"type":"fields","fields":{
        "appointmentId":{"type":"input","path":"/data/appointmentId"},
        "state":{"type":"input","path":"/data/state"}
    }});
    let reminder_event_schema = json!({"type":"object","required":["data"],"properties":{"data":{
        "type":"object","required":["appointmentId"],"properties":{
            "appointmentId":{"type":"string","format":"uuid"}
        }
    }}});
    let reminder_mapping = json!({"type":"fields","fields":{
        "appointmentId":{"type":"input","path":"/data/appointmentId"},
        "state":{"type":"literal","value":"confirmed"}
    }});
    let trigger = |source_trigger: &str, event_type: &str, fields: &[&str]| {
        json!({
            "source":"scheduling",
            "eventType":event_type,
            "dataSchema":data_schema(source_trigger, fields),
            "event":event_schema,
            "input":mapping,
        })
    };
    let workflow = json!({
        "apiVersion":"id.registrystack.org/formats/coordinator/project/v1alpha1",
        "kind":"CoordinatorProject",
        "project":{"id":"scheduling-lifecycle","version":"1"},
        "types":{"lifecycle-input":{"type":"object","additionalProperties":false,
            "required":["appointmentId","state"],"properties":{
                "appointmentId":{"type":"string","format":"uuid"},
                "state":{"type":"string","enum":["confirmed","cancelled"]}
            }}},
        "functions":{"notice-request":{"runtime":"rhai","source":"functions.rhai","entrypoint":"notice_request",
            "inputs":{"input":{"typeRef":"lifecycle-input"}},"output":{"operationInput":"send-message"}}},
        "operations":{"send-message":{"uses":"messaging.submit-message/v1","connection":"notices"}},
        "workflow":{
            "eventTriggers":{
                "confirmed":trigger("appointment.confirmed", "appointment-confirmed", &projection),
                "rescheduled":trigger("appointment.rescheduled", "appointment-rescheduled", &projection),
                "cancelled":trigger("appointment.cancelled", "appointment-cancelled", &cancellation),
                "reminder-confirmation":{
                    "source":"scheduling",
                    "eventType":"org.registrystack.scheduling.confirmation",
                    "dataSchema":"urn:registrystack:scheduling:reminder-data:confirmation",
                    "event":reminder_event_schema,
                    "input":reminder_mapping
                },
                "reminder":{
                    "source":"scheduling",
                    "eventType":"org.registrystack.scheduling.reminder",
                    "dataSchema":"urn:registrystack:scheduling:reminder-data:reminder",
                    "event":reminder_event_schema,
                    "input":reminder_mapping
                }
            },
            "input":{"typeRef":"lifecycle-input"},
            "deadlineSeconds":300,
            "start":"notify",
            "steps":{
                "notify":{"type":"call","operation":"send-message","input":{"type":"function","function":"notice-request","inputs":{"input":{"type":"input"}}},"next":"accepted"},
                "accepted":{"type":"finish","outcome":"message-accepted","output":{"type":"fields","fields":{"messageId":{"type":"step","step":"notify","path":"/id"}}}}
            },
            "outcomes":{"message-accepted":{"type":"object","additionalProperties":false,"required":["messageId"],"properties":{"messageId":{"type":"string","format":"uuid"}}}}
        }
    });
    std::fs::write(
        root.join("workflow.yaml"),
        serde_norway::to_string(&workflow).unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join("functions.rhai"),
        r#"fn notice_request(args) {
    #{senderProfile: "transactional", to: #{email: "person@example.invalid"},
      template: #{id: "application-follow-up", version: "1"}, locale: "en",
      data: #{applicationReference: args.input.appointmentId}}
}
"#,
    )
    .unwrap();
}

async fn coordinator(
    root: &Path,
    issuer: &registry_platform_testing::TestAuthorizationServer,
    messaging: &Messaging,
) -> (String, Process, OwnedCoordinator) {
    let project = root.join("project");
    std::fs::create_dir(&project).unwrap();
    write_project(&project);
    let package = root.join("package");
    let digest = deployment::package(&project, &package).unwrap();
    let database = std::env::var("COORDINATOR_TEST_DATABASE_URL")
        .expect("owned disposable Coordinator PostgreSQL");
    let (admin, connection) = tokio_postgres::connect(&database, tokio_postgres::NoTls)
        .await
        .unwrap();
    let admin_task = tokio::spawn(connection);
    let role = format!("coord_sched_{}", uuid::Uuid::new_v4().simple());
    let password = uuid::Uuid::new_v4().simple().to_string();
    admin.batch_execute(&format!("CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS")).await.unwrap();
    let mut runtime_url = url::Url::parse(&database).unwrap();
    runtime_url.set_username(&role).unwrap();
    runtime_url.set_password(Some(&password)).unwrap();
    support::private_file(&root.join("runtime-url"), runtime_url.as_str().as_bytes());
    support::private_file(&root.join("migration-url"), database.as_bytes());
    for (name, byte) in [("state-key", 81), ("admission-key", 82), ("audit-key", 83)] {
        support::private_file(&root.join(name), &[byte; 32]);
    }
    support::private_file(&root.join("event-key"), support::scheduling::HOOK_KEY);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let origin = format!("http://{address}");
    let mut runtime = support::config(root, issuer, "http://127.0.0.1:1", &messaging.base_url)
        .document()
        .unwrap();
    runtime["connections"]
        .as_object_mut()
        .unwrap()
        .remove("applications");
    runtime["database"] = json!({"runtimeUrlRef":"secret:file/runtime-url","migrationUrlRef":"secret:file/migration-url"});
    runtime["eventSources"] = json!({"scheduling":{
        "source":format!("urn:registrystack:scheduling:{}", support::scheduling::SCHEDULING_ID),
        "signingKeyRef":"secret:file/event-key"
    }});
    runtime["deployment"] = json!({
        "databaseId":format!("coordinator-scheduling-{}", uuid::Uuid::new_v4().simple()),
        "runtimeRole":role,
        "packages":[{"root":package,"expectedDigest":digest}],
        "listener":{"bind":address.to_string(),"tlsTermination":"development-loopback"},
        "authentication":{"issuer":issuer.issuer(),"audience":"urn:coordinator:scheduling-lifecycle",
            "scopeClaim":"scope","jwksSource":{"type":"uri","uri":issuer.jwks_uri()},
            "policies":{"lifecycle-operator":{"requiredScopes":["coordinator:operate"],
                "workflows":["scheduling-lifecycle"],"actions":["status","inspect"],"operator":true}}},
        "auditFile":root.join("audit/coordinator.ndjson"),
        "auditKeyRef":"secret:file/audit-key",
        "activeStateKey":1,
        "stateKeys":{"1":{"keyRef":"secret:file/state-key"}},
        "admissionKeyRef":"secret:file/admission-key"
    });
    let owned = OwnedCoordinator {
        database: database.clone(),
        namespace: runtime["namespace"].as_str().unwrap().to_owned(),
        role: role.clone(),
    };
    let config = root.join("runtime.yaml");
    std::fs::write(&config, serde_norway::to_string(&runtime).unwrap()).unwrap();
    let loaded = RuntimeConfig::load(&config).unwrap();
    let workflows = deployment::load_workflows(deployment::config(&loaded).unwrap()).unwrap();
    let migration = deployment::open_ctl(&loaded, true).await.unwrap();
    deployment::apply(&migration, &loaded, &workflows, &[])
        .await
        .unwrap();
    drop(migration);
    let process = start_coordinator(&config, &origin).await;
    admin_task.abort();
    (origin, process, owned)
}

async fn endpoint_status(origin: &str, path: &str) -> Option<u16> {
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .ok()?
        .get(format!("{origin}{path}"))
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .ok()
        .map(|response| response.status().as_u16())
}

async fn scheduling_outbox_summary(
    scheduling: &Scheduling,
) -> Option<Vec<(String, String, i32, i64)>> {
    let rows = tokio::time::timeout(
        Duration::from_secs(2),
        scheduling.admin.query(
            "SELECT purpose, delivery_state, max(attempts), count(*) \
             FROM scheduling_outbox GROUP BY purpose, delivery_state \
             ORDER BY purpose, delivery_state",
            &[],
        ),
    )
    .await
    .ok()?
    .ok()?;
    Some(
        rows.iter()
            .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
            .collect(),
    )
}

struct TimeoutContext<'a> {
    relay: &'a Relay,
    coordinator_origin: &'a str,
    coordinator: &'a OwnedCoordinator,
    scheduling: &'a Scheduling,
}

async fn wait_for_messages(messaging: &Messaging, expected: i64, context: &TimeoutContext<'_>) {
    wait_for_messages_for(messaging, expected, context, Duration::from_secs(30)).await;
}

async fn wait_for_messages_for(
    messaging: &Messaging,
    expected: i64,
    context: &TimeoutContext<'_>,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        let count = messaging.count().await;
        if count == expected {
            return;
        }
        assert!(count < expected, "unexpected duplicate Messaging request");
        if Instant::now() >= deadline {
            let coordinator_runs = context.coordinator.run_summary().await;
            let scheduling_outbox = scheduling_outbox_summary(context.scheduling).await;
            let relay_responses = context.relay.responses.lock().unwrap();
            let relay_response_count = relay_responses.len();
            let relay_recent_responses: Vec<_> =
                relay_responses.iter().rev().take(16).cloned().collect();
            drop(relay_responses);
            let (coordinator_status, scheduling_status, messaging_status) = tokio::join!(
                endpoint_status(context.coordinator_origin, "/ready"),
                endpoint_status(&context.scheduling.base_url, "/readyz"),
                endpoint_status(&messaging.base_url, "/ready"),
            );
            panic!(
                "lifecycle event did not reach Messaging; messaging_count={count}; \
                 relay_response_count={relay_response_count}; \
                 relay_recent_responses={relay_recent_responses:?}; \
                 coordinator_runs={coordinator_runs:?}; \
                 scheduling_outbox={scheduling_outbox:?}; service_statuses=\
                 {{coordinator:{coordinator_status:?}, scheduling:{scheduling_status:?}, \
                 messaging:{messaging_status:?}}}"
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_delivery(relay: &Relay, event_type: &str) -> Delivery {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(delivery) = relay
            .deliveries
            .lock()
            .unwrap()
            .iter()
            .find(|(_, headers, _, _, _)| {
                headers
                    .get("ce-type")
                    .is_some_and(|value| value == event_type)
            })
            .cloned()
        {
            return delivery;
        }
        assert!(
            Instant::now() < deadline,
            "Scheduling hook was not delivered"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn refresh_signature(headers: &mut HeaderMap, body: &[u8], target: &str) {
    headers.insert(
        "x-registry-delivery-time",
        Utc::now()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            .parse()
            .unwrap(),
    );
    let value = |name| headers.get(name).unwrap().to_str().unwrap();
    let signature = sign_v1(
        support::scheduling::HOOK_KEY,
        SignatureFields {
            id: value("ce-id"),
            source: value("ce-source"),
            event_type: value("ce-type"),
            time: value("ce-time"),
            data_schema: value("ce-dataschema"),
            generation: value("x-registry-event-generation"),
            attempt: value("x-registry-delivery-attempt"),
            delivery_time: value("x-registry-delivery-time"),
            method: "POST",
            request_target: target,
            content_type: "application/json",
            idempotency_key: value("idempotency-key"),
            body,
        },
    )
    .unwrap();
    headers.insert("x-registry-signature", signature.parse().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native Scheduling, Coordinator, Messaging, and PostgreSQL prerequisites; run products/coordinator/scripts/test-postgres.sh"]
async fn native_scheduling_lifecycle_drives_one_message_per_signed_event() {
    let issuer = support::issuer().await;
    let messaging = Messaging::start(&issuer).await;
    let relay = Relay::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_origin = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route(
            CONFIRMED_TARGET,
            post(forward).with_state((relay.clone(), CONFIRMED_TARGET)),
        )
        .route(
            RESCHEDULED_TARGET,
            post(forward).with_state((relay.clone(), RESCHEDULED_TARGET)),
        )
        .route(
            CANCELLED_TARGET,
            post(forward).with_state((relay.clone(), CANCELLED_TARGET)),
        );
    let relay_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let (coordinator_origin, coordinator_process, owned) =
        coordinator(root.path(), &issuer, &messaging).await;
    *relay.destination.lock().unwrap() = Some(coordinator_origin.clone());
    let scheduling = Scheduling::start(&relay_origin).await;
    let timeout_context = TimeoutContext {
        relay: &relay,
        coordinator_origin: &coordinator_origin,
        coordinator: &owned,
        scheduling: &scheduling,
    };
    let agent = scheduling.agent_token();
    let reader = scheduling.reader_token();
    let catalogue = scheduling
        .client
        .get_scheduling(scheduling.auth(&agent))
        .await
        .unwrap()
        .value;
    let start = (Utc::now() + ChronoDuration::days(2))
        .with_hour(10)
        .unwrap()
        .with_minute(0)
        .unwrap()
        .with_second(0)
        .unwrap()
        .with_nanosecond(0)
        .unwrap();
    let admission = |start, duplicate: &str| -> AdmissionRequest {
        serde_json::from_value(json!({
            "offering":"registry-update-30",
            "start":start,
            "party":{"recipients":1,"attendees":1},
            "channel":"public",
            "duplicateKey":duplicate,
            "policyRevision":catalogue.policy_revision,
            "capabilities":[],
            "prerequisites":[],
            "externalReferences":[]
        }))
        .unwrap()
    };
    let unauthorized = scheduling
        .client
        .create_appointment(
            scheduling.auth(&reader),
            "native-lifecycle-no-authority",
            &CreateAppointmentRequest {
                hold: None,
                admission: Some(admission(start + ChronoDuration::hours(2), "refused")),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(
        unauthorized,
        SchedulingClientError::Problem {
            status: 403,
            code: ProblemCode::OperationNotAuthorized,
            ..
        }
    ));
    assert_eq!(
        messaging.count().await,
        0,
        "refused authority has no downstream effect"
    );
    let appointment = scheduling
        .client
        .create_appointment(
            scheduling.auth(&agent),
            "native-lifecycle-create",
            &CreateAppointmentRequest {
                hold: None,
                admission: Some(admission(start, "synthetic-subject")),
            },
        )
        .await
        .unwrap()
        .value;
    wait_for_messages(&messaging, 1, &timeout_context).await;
    let (target, headers, body, status, _) =
        wait_for_delivery(&relay, "appointment-confirmed").await;
    assert_eq!(status, 204, "native signed event is admitted");
    let event: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(event["data"]["appointmentId"], appointment.appointment_id);
    assert_eq!(event["data"]["state"], "confirmed");
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    for _ in 0..2 {
        assert_eq!(
            http.post(format!("{coordinator_origin}{target}"))
                .headers(headers.clone())
                .body(body.clone())
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::NO_CONTENT,
            "exact signed event redelivery is accepted"
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        messaging.count().await,
        1,
        "duplicate event does not repeat Messaging"
    );
    let mut unsigned = headers.clone();
    unsigned.remove("x-registry-signature");
    assert_eq!(
        http.post(format!("{coordinator_origin}{target}"))
            .headers(unsigned)
            .body(body.clone())
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let mut wrong_source = headers.clone();
    wrong_source.insert(
        "ce-source",
        "urn:registrystack:scheduling:untrusted".parse().unwrap(),
    );
    refresh_signature(&mut wrong_source, &body, &target);
    assert_eq!(
        http.post(format!("{coordinator_origin}{target}"))
            .headers(wrong_source)
            .body(body)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "a correctly signed event from an unbound authority is refused"
    );
    assert_eq!(messaging.count().await, 1);
    let rescheduled = scheduling
        .client
        .reschedule_appointment(
            scheduling.auth(&agent),
            &appointment.appointment_id,
            "native-lifecycle-reschedule",
            &RescheduleAppointmentRequest {
                observed_revision: appointment.revision,
                admission: admission(start + ChronoDuration::hours(1), "synthetic-subject"),
            },
        )
        .await
        .unwrap()
        .value;
    wait_for_messages(&messaging, 2, &timeout_context).await;
    let (_, _, rescheduled_body, rescheduled_status, _) =
        wait_for_delivery(&relay, "appointment-rescheduled").await;
    assert_eq!(rescheduled_status, 204);
    let rescheduled_event: Value = serde_json::from_slice(&rescheduled_body).unwrap();
    assert_eq!(rescheduled_event["data"]["revision"], rescheduled.revision);
    assert_eq!(
        rescheduled_event["data"]["start"]
            .as_str()
            .unwrap()
            .parse::<DateTime<Utc>>()
            .unwrap(),
        rescheduled.start
    );
    let cancelled = scheduling
        .client
        .cancel_appointment(
            scheduling.auth(&agent),
            &appointment.appointment_id,
            "native-lifecycle-cancel",
            &CancelAppointmentRequest {
                observed_revision: rescheduled.revision,
                reason: Some("Synthetic cancellation".to_owned()),
            },
        )
        .await
        .unwrap()
        .value;
    wait_for_messages(&messaging, 3, &timeout_context).await;
    let (_, _, cancelled_body, cancelled_status, _) =
        wait_for_delivery(&relay, "appointment-cancelled").await;
    assert_eq!(cancelled_status, 204);
    let cancelled_event: Value = serde_json::from_slice(&cancelled_body).unwrap();
    assert_eq!(cancelled_event["data"]["revision"], cancelled.revision);
    assert_eq!(cancelled_event["data"]["state"], "cancelled");
    assert!(
        cancelled_event["data"].get("reason").is_none(),
        "private cancellation reason is not disclosed"
    );
    drop(coordinator_process);
    scheduling.stop().await;
    messaging.stop().await;
    relay_task.abort();
    drop(owned);
    issuer.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native Scheduling, Coordinator, Messaging, and PostgreSQL prerequisites; run products/coordinator/scripts/test-postgres.sh"]
async fn native_signed_scheduling_confirmation_drives_one_deduplicated_message() {
    let issuer = support::issuer().await;
    let messaging = Messaging::start(&issuer).await;
    let relay = Relay::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_origin = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().route(
        REMINDER_CONFIRMATION_TARGET,
        post(forward).with_state((relay.clone(), REMINDER_CONFIRMATION_TARGET)),
    );
    let relay_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let (coordinator_origin, coordinator_process, owned) =
        coordinator(root.path(), &issuer, &messaging).await;
    *relay.destination.lock().unwrap() = Some(coordinator_origin.clone());
    let scheduling = Scheduling::start_with_signed_reminders(
        &relay_origin,
        REMINDER_CONFIRMATION_TARGET,
        None,
        None,
    )
    .await;
    let timeout_context = TimeoutContext {
        relay: &relay,
        coordinator_origin: &coordinator_origin,
        coordinator: &owned,
        scheduling: &scheduling,
    };
    let agent = scheduling.agent_token();
    let catalogue = scheduling
        .client
        .get_scheduling(scheduling.auth(&agent))
        .await
        .unwrap()
        .value;
    let start = (Utc::now() + ChronoDuration::days(2))
        .with_hour(14)
        .unwrap()
        .with_minute(0)
        .unwrap()
        .with_second(0)
        .unwrap()
        .with_nanosecond(0)
        .unwrap();
    let admission: AdmissionRequest = serde_json::from_value(json!({
        "offering":"registry-update-30",
        "start":start,
        "party":{"recipients":1,"attendees":1},
        "channel":"public",
        "duplicateKey":"synthetic-reminder-subject",
        "policyRevision":catalogue.policy_revision,
        "capabilities":[],
        "prerequisites":[],
        "externalReferences":[]
    }))
    .unwrap();
    let appointment = scheduling
        .client
        .create_appointment(
            scheduling.auth(&agent),
            "native-confirmation-create",
            &CreateAppointmentRequest {
                hold: None,
                admission: Some(admission),
            },
        )
        .await
        .unwrap()
        .value;

    wait_for_messages(&messaging, 1, &timeout_context).await;
    let (target, headers, body, status, original_run_id) =
        wait_for_delivery(&relay, "org.registrystack.scheduling.confirmation").await;
    let problem = relay
        .responses
        .lock()
        .unwrap()
        .last()
        .and_then(|(_, problem)| problem.clone());
    assert_eq!(
        status, 204,
        "native signed confirmation is admitted; problem={problem:?}"
    );
    assert!(
        original_run_id.is_some(),
        "confirmation admission returns a run identity"
    );
    let event: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(event["data"]["appointmentId"], appointment.appointment_id);
    assert_eq!(target, REMINDER_CONFIRMATION_TARGET);
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("{coordinator_origin}{target}"))
        .headers(headers)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
    assert_eq!(
        response
            .headers()
            .get("x-coordinator-run-id")
            .and_then(|value| value.to_str().ok()),
        original_run_id.as_deref(),
        "confirmation replay returns the admitted run"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        messaging.count().await,
        1,
        "confirmation replay is deduplicated"
    );

    drop(coordinator_process);
    scheduling.stop().await;
    messaging.stop().await;
    relay_task.abort();
    drop(owned);
    issuer.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native Scheduling, Coordinator, Messaging, and PostgreSQL prerequisites; run products/coordinator/scripts/test-postgres.sh"]
async fn native_authored_scheduling_reminder_drives_one_deduplicated_message() {
    let issuer = support::issuer().await;
    let messaging = Messaging::start(&issuer).await;
    let relay = Relay::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_origin = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route(
            REMINDER_CONFIRMATION_TARGET,
            post(forward).with_state((relay.clone(), REMINDER_CONFIRMATION_TARGET)),
        )
        .route(
            REMINDER_TARGET,
            post(forward).with_state((relay.clone(), REMINDER_TARGET)),
        );
    let relay_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let (coordinator_origin, coordinator_process, owned) =
        coordinator(root.path(), &issuer, &messaging).await;
    *relay.destination.lock().unwrap() = Some(coordinator_origin.clone());

    // The policy accepts whole-minute offsets. Choose a real due minute with
    // enough time to start Scheduling and create the appointment on its grid.
    let due_at = next_minute(Utc::now() + ChronoDuration::seconds(90));
    let start = (due_at + ChronoDuration::days(2))
        .with_hour(14)
        .unwrap()
        .with_minute(0)
        .unwrap();
    let reminder_offset = u32::try_from(start.signed_duration_since(due_at).num_minutes()).unwrap();
    let scheduling = Scheduling::start_with_signed_reminders(
        &relay_origin,
        REMINDER_TARGET,
        Some(REMINDER_CONFIRMATION_TARGET),
        Some(reminder_offset),
    )
    .await;
    let timeout_context = TimeoutContext {
        relay: &relay,
        coordinator_origin: &coordinator_origin,
        coordinator: &owned,
        scheduling: &scheduling,
    };
    let agent = scheduling.agent_token();
    let catalogue = scheduling
        .client
        .get_scheduling(scheduling.auth(&agent))
        .await
        .unwrap()
        .value;
    let admission: AdmissionRequest = serde_json::from_value(json!({
        "offering":"registry-update-30",
        "start":start,
        "party":{"recipients":1,"attendees":1},
        "channel":"public",
        "duplicateKey":"synthetic-authored-reminder-subject",
        "policyRevision":catalogue.policy_revision,
        "capabilities":[],
        "prerequisites":[],
        "externalReferences":[]
    }))
    .unwrap();
    let appointment = scheduling
        .client
        .create_appointment(
            scheduling.auth(&agent),
            "native-authored-reminder-create",
            &CreateAppointmentRequest {
                hold: None,
                admission: Some(admission),
            },
        )
        .await
        .unwrap()
        .value;

    let (
        confirmation_target,
        confirmation_headers,
        confirmation_body,
        confirmation_status,
        confirmation_run_id,
    ) = wait_for_delivery(&relay, "org.registrystack.scheduling.confirmation").await;
    assert_eq!(confirmation_target, REMINDER_CONFIRMATION_TARGET);
    let confirmation_problem = relay
        .responses
        .lock()
        .unwrap()
        .last()
        .and_then(|(_, problem)| problem.clone());
    assert_eq!(
        confirmation_status, 204,
        "native confirmation is admitted; problem={confirmation_problem:?}"
    );
    assert!(
        confirmation_run_id.is_some(),
        "confirmation admission returns a run identity"
    );
    let confirmation_event: Value = serde_json::from_slice(&confirmation_body).unwrap();
    assert_eq!(
        confirmation_event["type"],
        "org.registrystack.scheduling.confirmation"
    );
    assert_eq!(
        confirmation_event["data"]["appointmentId"],
        appointment.appointment_id
    );
    wait_for_messages(&messaging, 1, &timeout_context).await;
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let confirmation_replay = http
        .post(format!("{coordinator_origin}{confirmation_target}"))
        .headers(confirmation_headers)
        .body(confirmation_body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        confirmation_replay.status(),
        reqwest::StatusCode::NO_CONTENT,
        "exact confirmation replay is accepted"
    );
    assert_eq!(
        confirmation_replay
            .headers()
            .get("x-coordinator-run-id")
            .and_then(|value| value.to_str().ok()),
        confirmation_run_id.as_deref(),
        "confirmation replay returns the admitted run"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        messaging.count().await,
        1,
        "confirmation replay is deduplicated"
    );

    wait_for_messages_for(&messaging, 2, &timeout_context, Duration::from_secs(180)).await;
    let (target, headers, body, status, reminder_run_id) =
        wait_for_delivery(&relay, "org.registrystack.scheduling.reminder").await;
    assert_eq!(status, 204, "native signed reminder is admitted");
    assert!(
        reminder_run_id.is_some(),
        "reminder admission returns a run identity"
    );
    assert_eq!(target, REMINDER_TARGET);
    let event: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(event["type"], "org.registrystack.scheduling.reminder");
    assert_eq!(event["data"]["appointmentId"], appointment.appointment_id);
    assert_eq!(event["data"]["minutesBefore"], reminder_offset);
    let event_due = DateTime::parse_from_rfc3339(event["time"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    assert_eq!(event_due, due_at);

    let response = http
        .post(format!("{coordinator_origin}{target}"))
        .headers(headers)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
    assert_eq!(
        response
            .headers()
            .get("x-coordinator-run-id")
            .and_then(|value| value.to_str().ok()),
        reminder_run_id.as_deref(),
        "reminder replay returns the admitted run"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        messaging.count().await,
        2,
        "authored reminder replay is deduplicated"
    );

    drop(coordinator_process);
    scheduling.stop().await;
    messaging.stop().await;
    relay_task.abort();
    drop(owned);
    issuer.stop().await;
}
