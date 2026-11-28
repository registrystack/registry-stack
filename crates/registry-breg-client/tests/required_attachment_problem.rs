// SPDX-License-Identifier: Apache-2.0
use axum::{body::Body, extract::State, http::Response, routing::get, Router};
use registry_breg_client::{BaseRegistryClient, BaseRegistryClientConfig};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

async fn slot_problem(code: &str, status: u16, detail: &str) {
    let problem = Arc::new(Mutex::new(json!({
        "type":format!("https://id.registrystack.org/problems/registry-breg/{}",code.replace('.',"/")),
        "title":if status == 409 {"Conflict"} else {"Unprocessable Entity"},"status":status,"detail":detail,
        "code":code,"traceId":"4bf92f3577b34da6a3ce929d0e0e4736",
        "fieldPath":"/attachments/support"
    })));
    async fn answer(State(problem): State<Arc<Mutex<Value>>>) -> Response<Body> {
        let document = problem.lock().unwrap().clone();
        Response::builder()
            .status(document["status"].as_u64().unwrap() as u16)
            .header("content-type", "application/problem+json")
            .header("cache-control", "no-store")
            .header(
                "traceparent",
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            )
            .body(Body::from(document.to_string()))
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
    assert_eq!(error.problem_code().map(|code| code.code()), Some(code));
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

#[tokio::test]
async fn required_attachment_problems_retain_only_a_valid_slot_location() {
    for code in [
        registry_breg_client::BRegProblemCode::AttachmentRequired,
        registry_breg_client::BRegProblemCode::AttachmentVerificationPending,
        registry_breg_client::BRegProblemCode::AttachmentVerificationRejected,
    ] {
        let detail = match code {
            registry_breg_client::BRegProblemCode::AttachmentRequired => "The required attachment slot is empty.",
            registry_breg_client::BRegProblemCode::AttachmentVerificationPending => "The attachment is awaiting verification. Refresh the Proposal before submitting.",
            _ => "The attachment was rejected by verification. Replace or remove the file before submitting.",
        };
        slot_problem(code.code(), code.status(), detail).await;
    }
}
