// SPDX-License-Identifier: Apache-2.0
use axum::{body::Body, extract::State, http::Response, routing::get, Router};
use registry_breg_client::{BaseRegistryClient, BaseRegistryClientConfig};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn required_attachment_problems_retain_only_a_valid_slot_location() {
    let problem = Arc::new(Mutex::new(json!({
        "type":"https://id.registrystack.org/problems/registry-breg/attachment/required",
        "title":"Unprocessable Entity","status":422,"detail":"The required attachment slot is empty.",
        "code":"attachment.required","traceId":"4bf92f3577b34da6a3ce929d0e0e4736",
        "fieldPath":"/attachments/support"
    })));
    async fn answer(State(problem): State<Arc<Mutex<Value>>>) -> Response<Body> {
        Response::builder()
            .status(422)
            .header("content-type", "application/problem+json")
            .header("cache-control", "no-store")
            .header(
                "traceparent",
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            )
            .body(Body::from(problem.lock().unwrap().to_string()))
            .unwrap()
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = problem.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/v1/registry", get(answer))
                .with_state(state),
        )
        .await
        .unwrap();
    });
    let client = BaseRegistryClient::new(BaseRegistryClientConfig::new_without_peer_policy(
        url::Url::parse(&format!("http://{address}/")).unwrap(),
    ))
    .unwrap();
    let error = client.registry_metadata(None).await.unwrap_err();
    assert_eq!(
        error.problem_code().map(|code| code.code()),
        Some("attachment.required")
    );
    assert_eq!(
        error.field_path().map(|path| path.as_str()),
        Some("/attachments/support")
    );
    problem
        .lock()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("fieldPath");
    assert_eq!(
        client.registry_metadata(None).await.unwrap_err().kind(),
        "protocol",
        "the code requires a slot location"
    );
    for invalid in [
        "/input/support",
        "/attachments",
        "/attachments/support/bytes",
        "/attachments/UPPER",
        "/attachments/a~1b",
    ] {
        problem.lock().unwrap()["fieldPath"] = json!(invalid);
        assert_eq!(
            client.registry_metadata(None).await.unwrap_err().kind(),
            "protocol",
            "{invalid}"
        );
    }
    server.abort();
}
