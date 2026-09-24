// SPDX-License-Identifier: Apache-2.0

//! The mock HTTP gateway a development session connects every `http`
//! provider to. It speaks the JSON shape of the example provider under
//! `products/messaging/examples/providers/mock`: a send is a `POST` under
//! `/<provider id>/v1/`, answered after the configured latency with
//! `{"id": ..., "status": "queued"}`, and shortly after the gateway posts a
//! signed `{"id": ..., "status": "delivered"}` report to the runtime's
//! callback route for that provider. A repeat carrying the same
//! `Idempotency-Key` is answered with the first id and reported once.
//!
//! The gateway reads no field of a send and logs nothing a send carries.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::hmac;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::json;
use zeroize::Zeroizing;

/// The header the gateway signs its delivery reports in, hex encoded.
pub(super) const SIGNATURE_HEADER: &str = "x-gateway-signature";
/// How many distinct idempotency keys the gateway remembers.
const REMEMBERED_KEYS: usize = 100_000;
/// How many times a delivery report is offered before the gateway gives up.
const CALLBACK_ATTEMPTS: u32 = 5;

pub(super) struct GatewaySettings {
    pub token: Zeroizing<String>,
    pub callback_key: Zeroizing<Vec<u8>>,
    /// The runtime's origin, such as `http://127.0.0.1:8107`.
    pub runtime_origin: String,
    pub latency: Duration,
    pub callback_delay: Duration,
}

/// What the gateway has done, for its own tests and the session report.
#[derive(Default)]
pub(super) struct GatewayCounts {
    pub accepted: AtomicU64,
    pub unauthorized: AtomicU64,
    pub reported: AtomicU64,
    pub report_refused: AtomicU64,
}

struct Gateway {
    settings: GatewaySettings,
    counts: Arc<GatewayCounts>,
    seen: Mutex<HashMap<String, String>>,
    client: reqwest::Client,
}

/// Serve the gateway on an ephemeral loopback port until the runtime it
/// runs on stops.
pub(super) async fn start(
    settings: GatewaySettings,
) -> std::io::Result<(SocketAddr, Arc<GatewayCounts>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let counts = Arc::new(GatewayCounts::default());
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(std::io::Error::other)?;
    let gateway = Arc::new(Gateway {
        settings,
        counts: Arc::clone(&counts),
        seen: Mutex::new(HashMap::new()),
        client,
    });
    let router = Router::new()
        .route("/{provider}/v1/{*path}", post(send))
        .with_state(gateway);
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, router).await {
            tracing::error!(%error, "the mock gateway stopped");
        }
    });
    Ok((address, counts))
}

fn authorized(headers: &HeaderMap, token: &str) -> bool {
    let expected = format!("Bearer {token}");
    headers
        .get(axum::http::header::AUTHORIZATION)
        .is_some_and(|value| {
            aws_lc_rs::constant_time::verify_slices_are_equal(value.as_bytes(), expected.as_bytes())
                .is_ok()
        })
}

async fn send(
    State(gateway): State<Arc<Gateway>>,
    Path((provider, _path)): Path<(String, String)>,
    headers: HeaderMap,
    _body: Bytes,
) -> Response {
    if !authorized(&headers, &gateway.settings.token) {
        gateway.counts.unauthorized.fetch_add(1, Ordering::Relaxed);
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": {"reason": "unauthorized"}})),
        )
            .into_response();
    }
    tokio::time::sleep(gateway.settings.latency).await;
    let key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let (id, first) = {
        let mut seen = gateway.seen.lock().expect("the gateway's key map");
        match key.as_ref().and_then(|key| seen.get(key)) {
            Some(id) => (id.clone(), false),
            None => {
                let id = format!("mock-{}", uuid::Uuid::new_v4().simple());
                if let Some(key) = key {
                    if seen.len() >= REMEMBERED_KEYS {
                        seen.clear();
                    }
                    seen.insert(key, id.clone());
                }
                (id, true)
            }
        }
    };
    gateway.counts.accepted.fetch_add(1, Ordering::Relaxed);
    if first {
        tokio::spawn(report(Arc::clone(&gateway), provider, id.clone()));
    }
    Json(json!({"id": id, "status": "queued"})).into_response()
}

/// The signature the runtime's `hmac-sha256-body` verifier checks.
pub(super) fn signature(key: &[u8], body: &[u8]) -> String {
    hex::encode(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), body).as_ref())
}

/// Post one signed delivery report, retrying while the runtime cannot take
/// it yet.
async fn report(gateway: Arc<Gateway>, provider: String, id: String) {
    tokio::time::sleep(gateway.settings.callback_delay).await;
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
        let answer = gateway
            .client
            .post(&url)
            .header("content-type", "application/json")
            .header(SIGNATURE_HEADER, &tag)
            .body(body.clone())
            .send()
            .await;
        match answer {
            Ok(response) if response.status().is_success() => {
                gateway.counts.reported.fetch_add(1, Ordering::Relaxed);
                return;
            }
            Ok(response) if response.status().is_client_error() => {
                last = Some(response.status().as_u16());
                break;
            }
            Ok(response) => last = Some(response.status().as_u16()),
            Err(_) => last = None,
        }
    }
    gateway
        .counts
        .report_refused
        .fetch_add(1, Ordering::Relaxed);
    tracing::warn!(
        provider = %provider,
        status = last,
        "the mock gateway's delivery report was not taken"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Received {
        signature: String,
        body: Vec<u8>,
        path: String,
    }

    async fn runtime_stub() -> (String, tokio::sync::mpsc::UnboundedReceiver<Received>) {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let router = Router::new().route(
            "/v1/provider-callbacks/{provider}",
            post(
                move |Path(provider): Path<String>, headers: HeaderMap, body: Bytes| {
                    let sender = sender.clone();
                    async move {
                        let _ = sender.send(Received {
                            signature: headers[SIGNATURE_HEADER].to_str().unwrap().to_owned(),
                            body: body.to_vec(),
                            path: provider,
                        });
                        StatusCode::ACCEPTED
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (format!("http://{address}"), receiver)
    }

    async fn gateway(origin: String) -> (String, Arc<GatewayCounts>) {
        let (address, counts) = start(GatewaySettings {
            token: Zeroizing::new("gateway-token".to_owned()),
            callback_key: Zeroizing::new(b"callback-key".to_vec()),
            runtime_origin: origin,
            latency: Duration::from_millis(10),
            callback_delay: Duration::from_millis(10),
        })
        .await
        .unwrap();
        (format!("http://{address}/sms-gateway/v1/messages"), counts)
    }

    #[tokio::test]
    async fn a_send_is_queued_and_then_reported_delivered_under_a_valid_signature() {
        let (origin, mut received) = runtime_stub().await;
        let (url, counts) = gateway(origin).await;
        let answer: serde_json::Value = reqwest::Client::new()
            .post(&url)
            .bearer_auth("gateway-token")
            .header("idempotency-key", "key-1")
            .json(&json!({"to": "+15550000000"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(answer["status"], "queued");
        let report = tokio::time::timeout(Duration::from_secs(5), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(report.path, "sms-gateway");
        assert_eq!(report.signature, signature(b"callback-key", &report.body));
        let body: serde_json::Value = serde_json::from_slice(&report.body).unwrap();
        assert_eq!(body, json!({"id": answer["id"], "status": "delivered"}));
        assert_eq!(counts.accepted.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_repeated_idempotency_key_gets_the_first_id_and_one_report() {
        let (origin, mut received) = runtime_stub().await;
        let (url, _) = gateway(origin).await;
        let client = reqwest::Client::new();
        let mut ids = Vec::new();
        for _ in 0..2 {
            let answer: serde_json::Value = client
                .post(&url)
                .bearer_auth("gateway-token")
                .header("idempotency-key", "same")
                .body("{}")
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            ids.push(answer["id"].clone());
        }
        assert_eq!(ids[0], ids[1]);
        tokio::time::timeout(Duration::from_secs(5), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(300), received.recv())
                .await
                .is_err(),
            "a repeat is reported once"
        );
    }

    #[tokio::test]
    async fn a_send_without_the_token_is_refused_and_never_reported() {
        let (origin, mut received) = runtime_stub().await;
        let (url, counts) = gateway(origin).await;
        let status = reqwest::Client::new()
            .post(&url)
            .bearer_auth("wrong")
            .body("{}")
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
        assert_eq!(counts.unauthorized.load(Ordering::Relaxed), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), received.recv())
                .await
                .is_err()
        );
    }
}
