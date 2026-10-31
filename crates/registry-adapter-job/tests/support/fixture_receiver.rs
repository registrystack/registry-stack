// SPDX-License-Identifier: Apache-2.0

// The scripted destination fixture: one module included by more than
// one test binary, each using a different part of its receiver's
// recording surface. The allow keeps the parts one binary leaves
// unread compilable for the other.
#![allow(dead_code)]
//! The scripted fixture receiver: an in-process HTTP server the seam
//! delivers to, one scripted answer per request, and a value-complete
//! record of every delivery it received. The record is deliberately
//! value-complete, projected values included, because the tests' job is
//! to prove exactly what crossed the seam and nothing more; nothing
//! outside a test's own assertions ever sees a record.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use axum::extract::State;

/// One scripted answer the receiver sends.
#[derive(Clone, Debug)]
pub enum Scripted {
    /// Answer `acknowledged`, with the optional run reference.
    Acknowledge {
        /// The run reference the answer carries.
        run_id: Option<String>,
    },
    /// Answer an item-scoped `refused` with its code.
    Refuse {
        /// The refusal code.
        code: String,
    },
    /// Answer a deployment-level `stop` with its code.
    Stop {
        /// The stop code.
        code: String,
    },
    /// Never answer: the delivery hangs until the caller's timeout.
    Hang,
}

/// One delivery the receiver received, complete: the method, the target,
/// every header, and the body bytes.
#[derive(Clone, Debug)]
pub struct RecordedDelivery {
    /// The request method.
    pub method: String,
    /// The request target, path and query as sent.
    pub target: String,
    /// Every header, name and value, in order.
    pub headers: Vec<(String, String)>,
    /// The body bytes exactly as sent.
    pub body: Vec<u8>,
}

impl RecordedDelivery {
    /// One header's value by name, compared without case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The body as text, for the member assertions.
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

#[derive(Clone)]
struct Shared {
    script: Arc<Mutex<VecDeque<Scripted>>>,
    requests: Arc<Mutex<Vec<RecordedDelivery>>>,
}

async fn deliver(
    State(shared): State<Shared>,
    request: axum::http::Request<axum::body::Body>,
) -> axum::response::Response {
    use axum::body::Body;
    use axum::http::Response as HttpResponse;
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, 1_048_576)
        .await
        .expect("the delivery body reads");
    shared
        .requests
        .lock()
        .expect("the receiver's record lock")
        .push(RecordedDelivery {
            method: parts.method.as_str().to_string(),
            target: parts
                .uri
                .path_and_query()
                .map(|target| target.as_str().to_string())
                .unwrap_or_default(),
            headers: parts
                .headers
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_string(),
                        String::from_utf8_lossy(value.as_bytes()).into_owned(),
                    )
                })
                .collect(),
            body: bytes.to_vec(),
        });
    let answer = shared
        .script
        .lock()
        .expect("the receiver's script lock")
        .pop_front()
        .expect("the test scripted an answer for every delivery");
    let (status, body) = match answer {
        Scripted::Acknowledge { run_id } => (
            200,
            match run_id {
                Some(run_id) => serde_json::json!({"outcome": "acknowledged", "runId": run_id}),
                None => serde_json::json!({"outcome": "acknowledged"}),
            },
        ),
        Scripted::Refuse { code } => (200, serde_json::json!({"outcome": "refused", "code": code})),
        Scripted::Stop { code } => (200, serde_json::json!({"outcome": "stop", "code": code})),
        Scripted::Hang => {
            // Never answer: the delivery hangs until the caller's
            // timeout reports the receiver unreachable.
            std::future::pending::<()>().await;
            unreachable!("a pending future never resolves")
        }
    };
    HttpResponse::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&body).expect("an answer renders"),
        ))
        .expect("a scripted answer builds")
}

/// The fixture receiver: a loopback server with its scripted answers and
/// its record of every delivery.
pub struct FixtureReceiver {
    /// The receiver's base URL, for the fixture destination.
    pub url: String,
    requests: Arc<Mutex<Vec<RecordedDelivery>>>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl FixtureReceiver {
    /// Start the receiver with the answers it sends in order.
    pub async fn start(script: Vec<Scripted>) -> Self {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the fixture receiver binds");
        let address = listener.local_addr().expect("the bound address");
        let state = Shared {
            script: Arc::new(Mutex::new(script.into_iter().collect())),
            requests: Arc::clone(&requests),
        };
        let app = axum::Router::new()
            .route("/deliver", axum::routing::post(deliver))
            .with_state(state);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });
        Self {
            url: format!("http://{address}/deliver"),
            requests,
            _shutdown: shutdown,
        }
    }

    /// Every delivery the receiver received, in order.
    pub fn requests(&self) -> Vec<RecordedDelivery> {
        self.requests
            .lock()
            .expect("the receiver's record lock")
            .clone()
    }
}
