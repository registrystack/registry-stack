// SPDX-License-Identifier: Apache-2.0

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response as AxumResponse},
    routing::any,
    Router,
};
use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};
use serde_json::Value;
use std::{
    collections::VecDeque,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Bytes,
}

#[derive(Clone, Debug)]
pub enum Reply {
    Json(Value),
    Redirect,
    DelayedJson(Duration, Value),
}

#[derive(Clone)]
struct SourceState {
    replies: Arc<Mutex<VecDeque<Reply>>>,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

pub struct Source {
    pub origin: String,
    state: SourceState,
}

impl Source {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("synthetic source listens");
        let origin = format!(
            "http://{}",
            listener.local_addr().expect("synthetic source address")
        );
        let state = SourceState {
            replies: Arc::default(),
            requests: Arc::default(),
        };
        let app = Router::new()
            .route("/{*path}", any(answer))
            .with_state(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("synthetic source serves");
        });
        Self { origin, state }
    }

    pub fn respond_with(&self, replies: impl IntoIterator<Item = Reply>) {
        *self.state.replies.lock().expect("source reply script") = replies.into_iter().collect();
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.state.requests.lock().expect("source requests").clone()
    }

    pub fn request_count(&self) -> usize {
        self.state.requests.lock().expect("source requests").len()
    }
}

async fn answer(State(state): State<SourceState>, request: Request) -> AxumResponse {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 1024 * 1024)
        .await
        .expect("bounded synthetic source request body");
    state
        .requests
        .lock()
        .expect("source requests")
        .push(RecordedRequest {
            method: parts.method,
            uri: parts.uri,
            headers: parts.headers,
            body,
        });
    let reply = state
        .replies
        .lock()
        .expect("source reply script")
        .pop_front()
        .unwrap_or_else(|| Reply::Json(serde_json::json!({"unexpectedSourceCall": true})));
    match reply {
        Reply::Json(value) => axum::Json(value).into_response(),
        Reply::DelayedJson(delay, value) => {
            tokio::time::sleep(delay).await;
            axum::Json(value).into_response()
        }
        Reply::Redirect => {
            let mut response = StatusCode::FOUND.into_response();
            response.headers_mut().insert(
                header::LOCATION,
                HeaderValue::from_static("/redirect-must-not-be-followed"),
            );
            response
        }
    }
}

pub fn fixture_response(adapter_root: &Path, fixture: &str) -> Value {
    const FIXTURE_FORMAT: FormatSpec<'static> = FormatSpec {
        kind: "AdapterFixture",
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: &[ApiVersion::current(
                "id.registrystack.org/formats/adapter/fixture/v1alpha1",
            )],
            retired_api_versions: &[],
        },
        removed_keys: &[],
    };
    let path = adapter_root
        .join("fixtures/dhis2-govstack")
        .join(format!("{fixture}.yaml"));
    let bytes = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "read maintained adapter fixture {}: {error}",
            path.display()
        )
    });
    let document = Reader::new(path.display().to_string())
        .read(&bytes, &Expect::one(&FIXTURE_FORMAT))
        .unwrap_or_else(|report| panic!("maintained fixture envelope is valid: {report}"));
    let value: Value = document
        .decode()
        .unwrap_or_else(|report| panic!("maintained fixture decodes: {report}"));
    value["entries"][0]["upstream"][0]["response"]["body"].clone()
}

#[derive(Clone)]
struct ProxyState {
    target: String,
    client: reqwest::Client,
}

pub async fn start_unknown_output_proxy(target: &str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("adapter response proxy listens");
    let origin = format!(
        "http://{}",
        listener
            .local_addr()
            .expect("adapter response proxy address")
    );
    let app = Router::new()
        .route("/{*path}", any(proxy))
        .with_state(ProxyState {
            target: target.trim_end_matches('/').to_owned(),
            client: reqwest::Client::new(),
        });
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("adapter response proxy serves");
    });
    origin
}

async fn proxy(State(state): State<ProxyState>, request: Request) -> AxumResponse {
    let (parts, body) = request.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or("/", |value| value.as_str());
    let mut outbound = state
        .client
        .request(parts.method, format!("{}{path_and_query}", state.target));
    for name in [
        header::AUTHORIZATION,
        header::ACCEPT,
        header::CONTENT_TYPE,
        header::HeaderName::from_static("x-registry-adapter-contract"),
    ] {
        if let Some(value) = parts.headers.get(&name) {
            outbound = outbound.header(name, value);
        }
    }
    let bytes = to_bytes(body, 1024 * 1024)
        .await
        .expect("bounded proxy request body");
    let response = outbound
        .body(bytes)
        .send()
        .await
        .expect("proxy adapter call");
    let status = response.status();
    let content_type = response.headers().get(header::CONTENT_TYPE).cloned();
    let request_id = response
        .headers()
        .get(header::HeaderName::from_static("x-registry-request-id"))
        .cloned();
    let mut bytes = response
        .bytes()
        .await
        .expect("proxy adapter response")
        .to_vec();
    if status == StatusCode::OK
        && !path_and_query.starts_with("/.well-known/registry-adapter/effective-contract")
    {
        let mut value: Value = serde_json::from_slice(&bytes).expect("adapter success JSON");
        value["unknownOutput"] = Value::String("must be refused by the gateway".to_owned());
        bytes = serde_json::to_vec(&value).expect("mutated adapter response JSON");
    }
    let mut answer = (status, Body::from(bytes)).into_response();
    if let Some(content_type) = content_type {
        answer
            .headers_mut()
            .insert(header::CONTENT_TYPE, content_type);
    }
    if let Some(request_id) = request_id {
        answer.headers_mut().insert(
            header::HeaderName::from_static("x-registry-request-id"),
            request_id,
        );
    }
    answer
}
