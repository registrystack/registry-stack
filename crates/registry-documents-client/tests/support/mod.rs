// SPDX-License-Identifier: Apache-2.0

//! A scripted Document Store stand-in: it records every request it receives
//! and answers each with the next scripted answer, under a deployment
//! prefix the client must keep.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use registry_documents_client::{
    type_uri, BearerToken, DocumentsClient, DocumentsClientConfig, ProblemCode,
};
use sha2::{Digest as _, Sha256};
use url::Url;

pub const TRACE_ID: &str = "0af7651916cd43dd8448eb211c80319c";
pub const TRACEPARENT: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
pub const PREFIX: &str = "/store";
pub const TOKEN: &str = "fixture-access-token";
pub const IDEMPOTENCY_KEY: &str = "reserve-2026-10-22-0001";
pub const DOCUMENT_ID: &str = "6f1c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d";
pub const VERSION_ID: &str = "7a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d";
pub const UPLOAD_ID: &str = "8b3c4d5e-6f7a-4b2c-9d3e-4f5a6b7c8d9e";
pub const GRANT_ID: &str = "9c4d5e6f-7a8b-4c3d-8e4f-5a6b7c8d9e0f";
pub const CONTENT: &[u8] = b"%PDF-1.7 fixture document content";
pub const MEDIA_TYPE: &str = "application/pdf";

#[derive(Clone, Debug)]
pub struct Captured {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Bytes,
}

#[derive(Clone, Debug)]
pub enum Answer {
    /// Holds the request past the client's timeout, so the client cannot
    /// know whether it took effect.
    Stall,
    /// An exact product problem, with an optional `Retry-After` field.
    Problem(ProblemCode, Option<&'static str>),
    /// A traced answer with the given status, content type, and body.
    Raw(StatusCode, &'static str, Vec<u8>),
    /// An answer with the given status, content type, and body, but no
    /// trace.
    Untraced(StatusCode, &'static str, Vec<u8>),
    /// A traced answer with the given status and extra headers, no body.
    Headers(StatusCode, Vec<(&'static str, &'static str)>),
}

impl Answer {
    pub fn json(status: StatusCode, body: impl Into<String>) -> Self {
        Self::Raw(status, "application/json", body.into().into_bytes())
    }

    pub fn content(bytes: &[u8]) -> Self {
        Self::Raw(StatusCode::OK, MEDIA_TYPE, bytes.to_vec())
    }
}

#[derive(Clone)]
pub struct Script {
    observations: Arc<Mutex<Vec<Captured>>>,
    answers: Arc<Mutex<VecDeque<Answer>>>,
}

impl Script {
    pub fn observations(&self) -> Vec<Captured> {
        self.observations.lock().expect("observations").clone()
    }
}

async fn answer(
    State(script): State<Script>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    script
        .observations
        .lock()
        .expect("observations")
        .push(Captured {
            method,
            uri,
            headers,
            body,
        });
    let next = script.answers.lock().expect("answers").pop_front();
    match next {
        Some(Answer::Stall) => {
            tokio::time::sleep(Duration::from_secs(30)).await;
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Some(Answer::Problem(code, retry_after)) => {
            let document = serde_json::json!({
                "type": type_uri(code.code()),
                "title": code.title(),
                "status": code.http_status(),
                "detail": code.detail(),
                "code": code.code(),
                "traceId": TRACE_ID,
            })
            .to_string();
            let mut headers = traced("application/problem+json");
            if let Some(seconds) = retry_after {
                headers.insert("retry-after", HeaderValue::from_static(seconds));
            }
            let status = StatusCode::from_u16(code.http_status()).expect("problem status");
            (status, headers, document).into_response()
        }
        Some(Answer::Raw(status, content_type, body)) => {
            (status, traced(content_type), body).into_response()
        }
        Some(Answer::Untraced(status, content_type, body)) => {
            let mut headers = HeaderMap::new();
            headers.insert("content-type", HeaderValue::from_static(content_type));
            (status, headers, body).into_response()
        }
        Some(Answer::Headers(status, extra)) => {
            let mut headers = HeaderMap::new();
            headers.insert("traceparent", HeaderValue::from_static(TRACEPARENT));
            for (name, value) in extra {
                headers.insert(name, HeaderValue::from_static(value));
            }
            (status, headers).into_response()
        }
        None => StatusCode::IM_A_TEAPOT.into_response(),
    }
}

fn traced(content_type: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static(content_type));
    headers.insert("traceparent", HeaderValue::from_static(TRACEPARENT));
    headers
}

/// Serve every route from one script, in request order.
pub async fn serve(answers: Vec<Answer>) -> (Url, Script, tokio::task::JoinHandle<()>) {
    let script = Script {
        observations: Arc::new(Mutex::new(Vec::new())),
        answers: Arc::new(Mutex::new(answers.into_iter().collect())),
    };
    let app = Router::new().fallback(answer).with_state(script.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });
    let url = Url::parse(&format!("http://{address}{PREFIX}/")).expect("fixture URL");
    (url, script, server)
}

pub fn client(config: DocumentsClientConfig) -> DocumentsClient {
    DocumentsClient::new(config).expect("a client")
}

pub fn token() -> BearerToken {
    BearerToken::new(TOKEN).expect("fixture token")
}

pub fn content_digest() -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(CONTENT)))
}

pub fn document_json() -> serde_json::Value {
    serde_json::json!({
        "id": DOCUMENT_ID,
        "policy": {
            "id": "birth-certificate",
            "version": "1",
            "digest": format!("sha256:{}", "a".repeat(64)),
        },
        "custodian": { "subject": "citizen-0001" },
        "version": {
            "id": VERSION_ID,
            "status": "awaiting-content",
            "mediaType": MEDIA_TYPE,
            "expectedDigest": content_digest(),
            "length": CONTENT.len(),
            "reservedAt": "2026-10-22T08:00:00Z",
        },
        "label": "Birth certificate",
        "actions": [],
    })
}

pub fn reservation_json() -> serde_json::Value {
    serde_json::json!({
        "document": document_json(),
        "uploadPath": format!("/uploads/{UPLOAD_ID}/content"),
        "uploadExpiresAt": "2026-10-22T09:00:00Z",
    })
}

pub fn grant_json() -> serde_json::Value {
    serde_json::json!({
        "id": GRANT_ID,
        "documentId": DOCUMENT_ID,
        "versionId": VERSION_ID,
        "grantee": { "subject": "clerk-0001" },
        "state": "active",
        "issuedAt": "2026-10-22T08:05:00Z",
        "expiresAt": "2026-10-23T08:05:00Z",
    })
}

pub fn policies_json() -> serde_json::Value {
    serde_json::json!({
        "items": [{
            "id": "birth-certificate",
            "version": "1",
            "label": "Birth certificate",
            "maximumDocumentBytes": 1_048_576,
            "allowedContentTypes": [MEDIA_TYPE],
            "grantExpiryHours": 24,
            "maximumGrantExpiryHours": 168,
        }],
    })
}
