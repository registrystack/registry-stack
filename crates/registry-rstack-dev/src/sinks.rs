// SPDX-License-Identifier: Apache-2.0
//! The mock HTTP gateway a run connects every Messaging `http` provider to.
//! It speaks the JSON shape of the example provider under
//! `products/messaging/examples/providers/mock`: a send is a `POST` under
//! `/<provider id>/v1/`, answered with `{"id": ..., "status": "queued"}`, and
//! shortly after the gateway posts a signed `{"id": ..., "status": "delivered"}`
//! report to the runtime's callback route for that provider. A repeat carrying
//! the same `Idempotency-Key` is answered with the first id and reported once.
//!
//! The gateway keeps the sends it took, in memory, and serves them at
//! `GET /sent` so a developer can look at what Messaging sent. It listens on
//! loopback only and holds synthetic development data. It stops with the run.

use anyhow::{ensure, Context, Result};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use registry_platform_crypto::mac::{constant_time_eq, hmac_sha256};
use serde_json::{json, Value};
use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    net::{Ipv4Addr, TcpListener},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::Duration,
};
use zeroize::Zeroizing;

/// The header the gateway signs its delivery reports in, hex encoded.
pub(super) const SIGNATURE_HEADER: &str = "x-gateway-signature";
/// How many of the latest sends the gateway keeps for `GET /sent`.
const KEPT_SENDS: usize = 1000;
const HOOK_BODY_LIMIT: usize = 64 * 1024;
/// How many distinct idempotency keys the gateway remembers.
const REMEMBERED_KEYS: usize = 100_000;
/// How long after a send the gateway posts its delivery report.
const CALLBACK_DELAY: Duration = Duration::from_millis(250);
/// How many times a delivery report is offered before the gateway gives up,
/// one second apart.
const CALLBACK_ATTEMPTS: u32 = 5;
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// What the gateway needs to run.
pub(super) struct GatewaySettings {
    /// The `http` provider ids the run connects to the gateway; a send under
    /// any other path segment is refused.
    pub(super) providers: BTreeSet<String>,
    pub(super) token: Zeroizing<String>,
    pub(super) callback_key: Zeroizing<Vec<u8>>,
    /// The runtime's origin, such as `http://127.0.0.1:8107`.
    pub(super) runtime_origin: String,
}

struct Gateway {
    settings: GatewaySettings,
    sent: Mutex<VecDeque<Value>>,
    keys: Mutex<HashMap<String, String>>,
    client: reqwest::Client,
}

/// A running gateway. Dropping it stops the server and joins its thread.
pub(super) struct GatewayServer {
    /// The gateway's origin, such as `http://127.0.0.1:41233`.
    pub(super) origin: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Drop for GatewayServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl GatewayServer {
    /// The address a developer reads the gateway's sent messages at.
    pub(super) fn sent_url(&self) -> String {
        format!("{}/sent", self.origin)
    }

    pub(super) fn start(settings: GatewaySettings) -> Result<Self> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()?;
        let gateway = Arc::new(Gateway {
            settings,
            sent: Mutex::new(VecDeque::new()),
            keys: Mutex::new(HashMap::new()),
            client,
        });
        let router = Router::new()
            .route("/sent", get(list))
            .route("/{provider}/v1/{*path}", post(send))
            .with_state(gateway);
        Self::start_router(router, "rstack-dev-mock-gateway")
    }

    pub(super) fn start_hooks() -> Result<Self> {
        let router = Router::new()
            .route("/events", post(receive_hook))
            .route("/received", get(list_hooks))
            .layer(DefaultBodyLimit::max(HOOK_BODY_LIMIT))
            .with_state(Arc::new(Mutex::new(VecDeque::new())));
        Self::start_router(router, "rstack-dev-hook-sink")
    }

    fn start_router(router: Router, name: &str) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .context("cannot reserve a loopback port for the HTTP sink")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error.to_string()));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let listener = match tokio::net::TcpListener::from_std(listener) {
                        Ok(listener) => listener,
                        Err(error) => {
                            let _ = ready_tx.send(Err(error.to_string()));
                            return;
                        }
                    };
                    if ready_tx.send(Ok(())).is_err() {
                        return;
                    }
                    let (drain_tx, drain_rx) = tokio::sync::oneshot::channel::<()>();
                    let server = async move {
                        if let Err(error) = axum::serve(listener, router)
                            .with_graceful_shutdown(async move {
                                let _ = drain_rx.await;
                            })
                            .await
                        {
                            eprintln!("the development HTTP sink stopped: {error}");
                        }
                    };
                    tokio::pin!(server);
                    tokio::select! {
                        () = &mut server => return,
                        _ = shutdown_rx => {}
                    }
                    let _ = drain_tx.send(());
                    let _ = tokio::time::timeout(SHUTDOWN_GRACE, server).await;
                });
                runtime.shutdown_timeout(SHUTDOWN_GRACE);
            })?;
        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = thread.join();
                anyhow::bail!("cannot start the development HTTP sink: {error}");
            }
            Err(error) => {
                let _ = shutdown_tx.send(());
                let _ = thread.join();
                anyhow::bail!("the development HTTP sink did not initialize: {error}");
            }
        }
        ensure!(
            address.ip().is_loopback(),
            "the development HTTP sink must bind loopback"
        );
        Ok(Self {
            origin: format!("http://{address}"),
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        })
    }
}

type HookDeliveries = Arc<Mutex<VecDeque<Value>>>;

async fn receive_hook(
    State(deliveries): State<HookDeliveries>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let headers: Vec<_> = headers
        .iter()
        .map(|(name, value)| {
            let value = match value.to_str() {
                Ok(text) => json!(text),
                Err(_) => json!({"base64": STANDARD.encode(value.as_bytes())}),
            };
            json!({"name": name.as_str(), "value": value})
        })
        .collect();
    let mut deliveries = deliveries.lock().expect("hook sink lock");
    if deliveries.len() == KEPT_SENDS {
        deliveries.pop_front();
    }
    deliveries.push_back(json!({
        "headers": headers,
        "body": String::from_utf8(body.to_vec()).map_or_else(
            |invalid| json!({"base64": STANDARD.encode(invalid.as_bytes())}),
            |text| json!(text),
        ),
    }));
    StatusCode::NO_CONTENT
}

async fn list_hooks(State(deliveries): State<HookDeliveries>) -> Json<Value> {
    Json(json!(*deliveries.lock().expect("hook sink lock")))
}

/// `GET /sent`: the latest sends the gateway took, oldest first.
async fn list(State(gateway): State<Arc<Gateway>>) -> Json<Value> {
    let sent = gateway.sent.lock().expect("the gateway's sent list");
    Json(json!({"sent": sent.iter().collect::<Vec<_>>()}))
}

fn authorized(headers: &HeaderMap, token: &str) -> bool {
    let expected = format!("Bearer {token}");
    headers
        .get(header::AUTHORIZATION)
        .is_some_and(|value| constant_time_eq(value.as_bytes(), expected.as_bytes()))
}

fn refusal(status: StatusCode, reason: &str) -> Response {
    (status, Json(json!({"error": {"reason": reason}}))).into_response()
}

async fn send(
    State(gateway): State<Arc<Gateway>>,
    Path((provider, _path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !authorized(&headers, &gateway.settings.token) {
        return refusal(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !gateway.settings.providers.contains(&provider) {
        return refusal(StatusCode::NOT_FOUND, "unknown-provider");
    }
    let key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let (id, first) = {
        let mut keys = gateway.keys.lock().expect("the gateway's key map");
        match key.as_ref().and_then(|key| keys.get(key)) {
            Some(id) => (id.clone(), false),
            None => {
                let id = format!("mock-{}", uuid::Uuid::new_v4().simple());
                if let Some(key) = &key {
                    if keys.len() >= REMEMBERED_KEYS {
                        keys.clear();
                    }
                    keys.insert(key.clone(), id.clone());
                }
                (id, true)
            }
        }
    };
    if first {
        let body = serde_json::from_slice::<Value>(&body)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned()));
        let mut sent = gateway.sent.lock().expect("the gateway's sent list");
        if sent.len() >= KEPT_SENDS {
            sent.pop_front();
        }
        sent.push_back(json!({
            "id": id, "provider": provider, "idempotencyKey": key, "body": body,
        }));
        drop(sent);
        tokio::spawn(report(Arc::clone(&gateway), provider, id.clone()));
    }
    Json(json!({"id": id, "status": "queued"})).into_response()
}

/// The signature the runtime's `hmac-sha256-body` verifier checks, hex
/// encoded.
fn signature(key: &[u8], body: &[u8]) -> String {
    use std::fmt::Write as _;
    hmac_sha256(key, body)
        .iter()
        .fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// Post one signed delivery report, retrying while the runtime cannot take
/// it yet. A report the runtime refuses is logged on the supervisor's log.
async fn report(gateway: Arc<Gateway>, provider: String, id: String) {
    tokio::time::sleep(CALLBACK_DELAY).await;
    let body = serde_json::to_vec(&json!({"id": id, "status": "delivered"}))
        .expect("a delivery report serializes");
    let tag = signature(&gateway.settings.callback_key, &body);
    let url = format!(
        "{}/v1/provider-callbacks/{provider}",
        gateway.settings.runtime_origin
    );
    let mut last = None;
    for attempt in 0..CALLBACK_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        match gateway
            .client
            .post(&url)
            .header("content-type", "application/json")
            .header(SIGNATURE_HEADER, &tag)
            .body(body.clone())
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => return,
            Ok(response) if response.status().is_client_error() => {
                last = Some(response.status().as_u16());
                break;
            }
            Ok(response) => last = Some(response.status().as_u16()),
            Err(_) => last = None,
        }
    }
    eprintln!(
        "the development mock gateway's delivery report for provider {provider} was not taken (status {last:?})"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::IntoFuture;

    struct Received {
        signature: String,
        body: Vec<u8>,
        provider: String,
    }

    /// A stand-in for the Messaging runtime's callback route.
    fn runtime_stub() -> (String, mpsc::Receiver<Received>, thread::JoinHandle<()>) {
        let (sender, receiver) = mpsc::channel();
        let sender = Arc::new(Mutex::new(sender));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let router = Router::new().route(
                    "/v1/provider-callbacks/{provider}",
                    post(
                        move |Path(provider): Path<String>, headers: HeaderMap, body: Bytes| {
                            let sender = Arc::clone(&sender);
                            async move {
                                let _ = sender.lock().unwrap().send(Received {
                                    signature: headers[SIGNATURE_HEADER]
                                        .to_str()
                                        .unwrap()
                                        .to_owned(),
                                    body: body.to_vec(),
                                    provider,
                                });
                                StatusCode::ACCEPTED
                            }
                        },
                    ),
                );
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let _ = tokio::time::timeout(
                    Duration::from_secs(10),
                    axum::serve(listener, router).into_future(),
                )
                .await;
            });
        });
        (origin, receiver, thread)
    }

    fn gateway(origin: &str) -> GatewayServer {
        GatewayServer::start(GatewaySettings {
            providers: BTreeSet::from(["sms-gateway".to_owned()]),
            token: Zeroizing::new("gateway-token".to_owned()),
            callback_key: Zeroizing::new(b"callback-key".to_vec()),
            runtime_origin: origin.to_owned(),
        })
        .unwrap()
    }

    /// Run one request to completion on a throwaway runtime.
    fn call(request: impl FnOnce(&reqwest::Client) -> reqwest::RequestBuilder) -> (u16, Value) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let client = reqwest::Client::builder().no_proxy().build().unwrap();
            let response = request(&client).send().await.unwrap();
            let status = response.status().as_u16();
            let body = response.json().await.unwrap_or(Value::Null);
            (status, body)
        })
    }

    #[test]
    fn a_send_is_recorded_queued_and_reported_once_per_idempotency_key() {
        let (origin, reports, _runtime) = runtime_stub();
        let gateway = gateway(&origin);
        let url = format!("{}/sms-gateway/v1/messages", gateway.origin);
        let post = |key: &str| {
            call(|client| {
                client
                    .post(&url)
                    .bearer_auth("gateway-token")
                    .header("idempotency-key", key)
                    .json(&json!({"to": "+15555550100", "text": "hello"}))
            })
            .1
        };

        let first = post("key-1");
        let repeat = post("key-1");
        let other = post("key-2");

        assert_eq!(first["status"], "queued");
        assert_eq!(first["id"], repeat["id"]);
        assert_ne!(first["id"], other["id"]);
        let (_, sent) = call(|client| client.get(gateway.sent_url()));
        let sent = sent["sent"].as_array().unwrap();
        assert_eq!(sent.len(), 2, "a repeat is not a second send: {sent:?}");
        assert_eq!(sent[0]["id"], first["id"]);
        assert_eq!(sent[0]["provider"], "sms-gateway");
        assert_eq!(sent[0]["body"]["text"], "hello");

        let report = reports.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(report.provider, "sms-gateway");
        assert_eq!(report.signature, signature(b"callback-key", &report.body));
        let body: Value = serde_json::from_slice(&report.body).unwrap();
        assert_eq!(body["status"], "delivered");
    }

    #[test]
    fn a_send_without_the_token_or_for_another_provider_is_refused_and_not_recorded() {
        let gateway = gateway("http://127.0.0.1:9");
        let base = &gateway.origin;

        let (unauthorized, _) = call(|client| {
            client
                .post(format!("{base}/sms-gateway/v1/messages"))
                .body("{}")
        });
        let (unknown, _) = call(|client| {
            client
                .post(format!("{base}/other/v1/messages"))
                .bearer_auth("gateway-token")
                .body("{}")
        });

        assert_eq!(unauthorized, 401);
        assert_eq!(unknown, 404);
        let (_, sent) = call(|client| client.get(gateway.sent_url()));
        assert_eq!(sent["sent"], json!([]));
    }

    #[test]
    fn hook_sink_refuses_oversized_deliveries() {
        let sink = GatewayServer::start_hooks().unwrap();
        let (status, _) = call(|client| {
            client
                .post(format!("{}/events", sink.origin))
                .body(vec![b'a'; 65_537])
        });
        assert_eq!(status, 413);
        let (_, received) = call(|client| client.get(format!("{}/received", sink.origin)));
        assert_eq!(received, json!([]));
    }

    #[test]
    fn hook_sink_keeps_the_last_thousand_deliveries() {
        let sink = GatewayServer::start_hooks().unwrap();
        for index in 0..=1000 {
            let (status, _) = call(|client| {
                client
                    .post(format!("{}/events", sink.origin))
                    .header("x-delivery-number", index.to_string())
                    .body(format!("body {index}"))
            });
            assert_eq!(status, 204);
        }
        let (status, received) = call(|client| client.get(format!("{}/received", sink.origin)));
        assert_eq!(status, 200);
        let deliveries = received.as_array().unwrap();
        assert_eq!(deliveries.len(), 1000);
        assert_eq!(deliveries[0]["body"], "body 1");
        assert_eq!(deliveries[999]["body"], "body 1000");
        assert!(deliveries[999]["headers"]
            .as_array()
            .unwrap()
            .contains(&json!({"name": "x-delivery-number", "value": "1000"})));
    }

    #[test]
    fn dropping_the_gateway_stops_its_listener() {
        let gateway = gateway("http://127.0.0.1:9");
        let address = gateway.origin.trim_start_matches("http://").to_owned();
        assert!(std::net::TcpStream::connect(&address).is_ok());

        drop(gateway);

        assert!(std::net::TcpStream::connect(&address).is_err());
    }
}
