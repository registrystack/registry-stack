// SPDX-License-Identifier: Apache-2.0
//! A native BReg Proposal transition delivered to native authenticated ingress.
#![cfg(feature = "postgres-test")]
#[path = "support/breg_service.rs"]
mod breg_service;
mod support;

use axum::{
    body::Bytes, extract::State, http::HeaderMap, response::IntoResponse, routing::post, Router,
};
use registry_breg_client::{
    BRegActionInvocationRequest, BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey,
    BRegRecordFormat, BRegRecordOptions,
};
use registry_coordinator::{deployment, runtime::RuntimeConfig};
use registry_platform_crypto::delivery_signature::{sign_v1, SignatureFields};
use serde_json::{json, Value};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const TARGET: &str = "/v1/events/proposal-event-proof/submitted";
const KEY: &[u8] = &[0x5a; 32];
type Delivery = (HeaderMap, Vec<u8>, u16);
#[derive(Clone, Default)]
struct Relay {
    destination: Arc<Mutex<Option<String>>>,
    deliveries: Arc<Mutex<Vec<Delivery>>>,
}
async fn forward(
    State(relay): State<Relay>,
    mut headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    headers.remove("host");
    let origin = relay
        .destination
        .lock()
        .unwrap()
        .clone()
        .expect("ingress started before Submit");
    let response = reqwest::Client::new()
        .post(format!("{origin}{TARGET}"))
        .headers(headers.clone())
        .body(body.clone())
        .send()
        .await
        .unwrap();
    let status = response.status();
    let answer = response.bytes().await.unwrap();
    relay
        .deliveries
        .lock()
        .unwrap()
        .push((headers, body.to_vec(), status.as_u16()));
    (status, [("content-type", "application/json")], answer)
}
struct OwnedCoordinator {
    database: String,
    namespace: String,
    role: String,
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
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn start(config: &Path, origin: &str) -> Process {
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
            .is_ok_and(|r| r.status().is_success())
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
fn refresh_signature(headers: &mut HeaderMap, body: &[u8]) {
    headers.insert(
        "x-registry-delivery-time",
        chrono::Utc::now()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            .parse()
            .unwrap(),
    );
    let value = |name| headers.get(name).unwrap().to_str().unwrap();
    let signature = sign_v1(
        KEY,
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
            request_target: TARGET,
            content_type: "application/json",
            idempotency_key: value("idempotency-key"),
            body,
        },
    )
    .unwrap();
    headers.insert("x-registry-signature", signature.parse().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native BReg prerequisites; run products/coordinator/scripts/test-breg-action.py"]
async fn native_proposal_event_admits_one_run_without_conferring_apply_authority() {
    let issuer = support::issuer().await;
    let relay = Relay::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_origin = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route(TARGET, post(forward))
        .with_state(relay.clone());
    let relay_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let breg = breg_service::Breg::start_events(&issuer, &relay_origin).await;
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap()
        .keep();
    let project = root.as_path().join("project");
    std::fs::create_dir(&project).unwrap();
    let schema: Value = serde_json::from_str(include_str!(
        "../../../products/breg/generated/event-schemas/proposal-lifecycle.schema.json"
    ))
    .unwrap();
    // Coordinator schema positions are local projections. Reuse the exact
    // producer property schemas needed by this mapping, without importing its
    // resource-level $id or altering the native envelope delivered below.
    let projection = json!({"type":"object","required":["proposalId","revision","transition"],
        "properties":{"proposalId":schema["properties"]["proposalId"],
            "revision":schema["properties"]["revision"],"transition":schema["properties"]["transition"]}});
    let workflow = json!({"apiVersion":"id.registrystack.org/formats/coordinator/project/v1alpha1","kind":"CoordinatorProject",
        "project":{"id":"proposal-event-proof","version":"1"},
        "workflow":{"input":{"type":"object","additionalProperties":false,"required":["proposalId"],"properties":{"proposalId":{"type":"string","format":"uuid"}}},
            "eventTriggers":{"submitted":{"source":"registry","eventType":"proposal.submitted","dataSchema":"https://id.registrystack.org/contracts/breg/proposal-event/v1",
                "event":{"type":"object","required":["data"],"properties":{"data":projection}},
                "input":{"type":"fields","fields":{"proposalId":{"type":"input","path":"/data/proposalId"}}}}},
            "deadlineSeconds":300,"start":"observed","steps":{"observed":{"type":"finish","outcome":"observed","output":{"type":"input"}}},
            "outcomes":{"observed":{"type":"object","additionalProperties":false,"required":["proposalId"],"properties":{"proposalId":{"type":"string","format":"uuid"}}}}}});
    std::fs::write(
        project.join("workflow.yaml"),
        serde_norway::to_string(&workflow).unwrap(),
    )
    .unwrap();
    let package = root.as_path().join("package");
    let digest = deployment::package(&project, &package).unwrap();
    let database = std::env::var("COORDINATOR_TEST_DATABASE_URL")
        .expect("owned disposable Coordinator PostgreSQL");
    let (admin, connection) = tokio_postgres::connect(&database, tokio_postgres::NoTls)
        .await
        .unwrap();
    let admin_task = tokio::spawn(connection);
    let role = format!("coord_event_{}", uuid::Uuid::new_v4().simple());
    let password = uuid::Uuid::new_v4().simple().to_string();
    admin.batch_execute(&format!("CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS")).await.unwrap();
    let mut runtime_url = url::Url::parse(&database).unwrap();
    runtime_url.set_username(&role).unwrap();
    runtime_url.set_password(Some(&password)).unwrap();
    support::private_file(
        &root.as_path().join("runtime-url"),
        runtime_url.as_str().as_bytes(),
    );
    support::private_file(&root.as_path().join("migration-url"), database.as_bytes());
    for (name, byte) in [
        ("state-key", 71),
        ("admission-key", 72),
        ("audit-key", 73),
        ("event-key", 0x5a),
    ] {
        support::private_file(&root.as_path().join(name), &[byte; 32]);
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let origin = format!("http://{address}");
    let mut runtime = support::config(
        root.as_path(),
        &issuer,
        &breg.base_url,
        "http://127.0.0.1:1",
    )
    .document()
    .unwrap();
    runtime["connections"]
        .as_object_mut()
        .unwrap()
        .remove("notices");
    runtime["connections"]["applications"]["profile"] = json!("reader");
    runtime["database"] = json!({"runtimeUrlRef":"secret:file/runtime-url","migrationUrlRef":"secret:file/migration-url"});
    runtime["eventSources"] = json!({"registry":{"source":"urn:registrystack:registry:coordinator-action-proof:instance:coordinator-action-proof","signingKeyRef":"secret:file/event-key"}});
    runtime["deployment"] = json!({"databaseId":"native-event-proof","runtimeRole":role,"packages":[{"root":package,"expectedDigest":digest}],
        "listener":{"bind":address.to_string(),"tlsTermination":"development-loopback"},
        "authentication":{"issuer":issuer.issuer(),"audience":"urn:coordinator:native-event","scopeClaim":"scope","jwksSource":{"type":"uri","uri":issuer.jwks_uri()},
            "policies":{"application-reader":{"requiredScopes":["coordinator:operate"],"workflows":["proposal-event-proof"],"actions":["status","inspect"],"operator":true}}},
        "auditFile":root.as_path().join("audit/events.jsonl"),"auditKeyRef":"secret:file/audit-key","activeStateKey":1,"stateKeys":{"1":{"keyRef":"secret:file/state-key"}},"admissionKeyRef":"secret:file/admission-key"});
    let owned = OwnedCoordinator {
        database: database.clone(),
        namespace: runtime["namespace"].as_str().unwrap().to_owned(),
        role: role.clone(),
    };
    let config = root.as_path().join("runtime.yaml");
    std::fs::write(&config, serde_norway::to_string(&runtime).unwrap()).unwrap();
    let runtime = RuntimeConfig::load(&config).unwrap();
    let workflows = deployment::load_workflows(deployment::config(&runtime).unwrap()).unwrap();
    let migration = deployment::open_ctl(&runtime, true).await.unwrap();
    deployment::apply(&migration, &runtime, &workflows, &[])
        .await
        .unwrap();
    drop(migration);
    let process = start(&config, &origin).await;
    *relay.destination.lock().unwrap() = Some(origin.clone());
    let client = breg.client(&issuer);
    let metadata = client.registry_contract(Some("writer")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.item.create", "writer")
        .unwrap()
    else {
        panic!("native Create grant")
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(
                json!({"owner":"coordinator-reader","label":"Before"})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap(),
            &BRegIdempotencyKey::parse("native-event-seed").unwrap(),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap()
        .value
        .data
        .record_identifier;
    let action = metadata
        .value
        .select_action("manual-item", "writer")
        .unwrap();
    // The applicant starts and submits the Proposal in BReg; Coordinator
    // only follows the resulting product event.
    let invocation = BRegActionInvocationRequest::new(
        &action,
        json!({"targetId":record,"label":"After"})
            .as_object()
            .unwrap()
            .clone(),
        None,
    )
    .unwrap();
    let draft = client
        .start_proposal(
            &action,
            &invocation,
            &BRegIdempotencyKey::parse("native-event-start").unwrap(),
        )
        .await
        .unwrap()
        .value;
    let prepared = client
        .prepare_proposal(
            &draft,
            "submit",
            json!({}),
            &BRegIdempotencyKey::parse("native-event-submit").unwrap(),
        )
        .unwrap();
    let submitted =
        serde_json::to_value(client.execute_proposal(&prepared).await.unwrap().value).unwrap();
    let proposal = submitted["id"].as_str().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if !relay.deliveries.lock().unwrap().is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "real BReg outbox delivery did not arrive"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (headers, body, status) = relay.deliveries.lock().unwrap()[0].clone();
    assert_eq!(status, 204, "native producer signature passes real ingress");
    let event: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(event["data"]["proposalId"], proposal);
    assert_eq!(event["data"]["transition"], "submitted");
    assert!(
        !String::from_utf8_lossy(&body).contains("After"),
        "event contains no editable input values"
    );
    // The native service owns the sole audit writer. Observe its persisted
    // state through its authenticated public API, as an operator does.
    let http = reqwest::Client::new();
    let operator = issuer.issue_access_token(
        "application-reader",
        "coordinator-reader",
        "urn:coordinator:native-event",
        "coordinator:operate",
        chrono::Utc::now().timestamp() + 300,
    );
    let response = http
        .get(format!("{origin}/v1/runs?limit=100"))
        .bearer_auth(&operator)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let runs: Value = response.json().await.unwrap();
    assert_eq!(runs["runs"].as_array().unwrap().len(), 1);
    let run = runs["runs"][0]["runId"].as_str().unwrap().to_owned();
    for _ in 0..2 {
        let response = http
            .post(format!("{origin}{TARGET}"))
            .headers(headers.clone())
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 204, "exact native event redelivery");
    }
    let mut changed = event.clone();
    changed["data"]["revision"] = json!(event["data"]["revision"].as_u64().unwrap() + 1);
    let changed = registry_platform_canonical_json::canonicalize_json(&changed).unwrap();
    let mut authenticated = headers.clone();
    refresh_signature(&mut authenticated, &changed);
    assert_eq!(
        http.post(format!("{origin}{TARGET}"))
            .headers(authenticated)
            .body(changed)
            .send()
            .await
            .unwrap()
            .status(),
        409,
        "authenticated changed event identity conflicts"
    );
    let mut unauthenticated = headers.clone();
    unauthenticated.remove("x-registry-signature");
    assert_eq!(
        http.post(format!("{origin}{TARGET}"))
            .headers(unauthenticated)
            .body(body)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let response = http
        .get(format!("{origin}/v1/runs?limit=100"))
        .bearer_auth(&operator)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let runs: Value = response.json().await.unwrap();
    assert_eq!(runs["runs"].as_array().unwrap().len(), 1);
    assert_eq!(runs["runs"][0]["runId"], run);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = http
            .get(format!("{origin}/v1/runs/{run}"))
            .bearer_auth(&operator)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let state: Value = response.json().await.unwrap();
        if state["state"] == "finished" {
            assert_eq!(state["output"], json!({"proposalId":proposal}));
            break;
        }
        assert!(Instant::now() < deadline, "native event Run did not finish");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    // The producer's event authentication and its Run do not confer BReg Apply.
    let bearer = issuer.issue_access_token(
        "application-reader",
        "coordinator-reader",
        "urn:example:applications",
        "applications:read",
        chrono::Utc::now().timestamp() + 300,
    );
    let refused = http.post(format!("{}/v1/proposals/{proposal}/apply?accessProfile=reader", breg.base_url))
        .bearer_auth(bearer).header("idempotency-key", "event-direct-apply-refusal")
        .header("if-match", submitted["links"]["apply"]["ifMatch"].as_str().unwrap())
        .json(&json!({"submissionVersion":submitted["submissionVersion"],"effectDigest":submitted["effectDigest"]}))
        .send().await.unwrap();
    assert_eq!(
        refused.status(),
        404,
        "BReg independently refuses Apply under the reader profile"
    );
    let unchanged = client
        .get_record(
            "items",
            &record,
            &BRegRecordOptions::default()
                .access_profile("writer")
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unchanged.value.data.domain_data["label"], "Before");
    assert_eq!(unchanged.value.data.revision_identifier, "1");
    drop(process);
    drop(client);
    breg.finish();
    relay_task.abort();
    drop(owned);
    admin_task.abort();
    issuer.stop().await;
    std::fs::remove_dir_all(root).unwrap();
}
