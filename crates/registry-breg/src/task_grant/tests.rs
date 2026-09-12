use super::*;
use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

#[derive(Clone)]
struct StateData {
    response: Arc<Mutex<Value>>,
    status_calls: Arc<AtomicUsize>,
    token_calls: Arc<AtomicUsize>,
}
async fn token(State(state): State<StateData>) -> Json<Value> {
    state.token_calls.fetch_add(1, Ordering::SeqCst);
    Json(
        serde_json::json!({"access_token":"synthetic-status-service","token_type":"Bearer","expires_in":300,"scope":"casework:grants:status"}),
    )
}
async fn status(State(state): State<StateData>, headers: HeaderMap) -> Json<Value> {
    assert_eq!(
        headers.get("authorization").unwrap(),
        "Bearer synthetic-status-service"
    );
    state.status_calls.fetch_add(1, Ordering::SeqCst);
    Json(state.response.lock().unwrap().clone())
}
fn binding() -> TaskGrantBinding {
    serde_json::from_value(serde_json::json!({"grantId":Uuid::new_v4().to_string(),"authority":"casework","sourceIssuer":"https://casework.test","principal":"agent","client":"agent-client","resource":"urn:breg:test","purpose":"review","bounds":{"type":"breg","permissions":[{"collection":"people","operations":["get","patch"]}]},"subjects":{"person_reference":"synthetic-person","active":true},"expiresAt":chrono::Utc::now().timestamp()+900})).unwrap()
}

#[tokio::test]
async fn each_mutating_attempt_reads_fresh_status_and_compares_every_immutable_bound() {
    let binding = binding();
    let response = Arc::new(Mutex::new(
        serde_json::json!({"active":true,"grant":binding}),
    ));
    let state = StateData {
        response: response.clone(),
        status_calls: Arc::new(AtomicUsize::new(0)),
        token_calls: Arc::new(AtomicUsize::new(0)),
    };
    let app = Router::new()
        .route("/token", post(token))
        .route("/v1/task-grants/{id}/status", get(status))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut key = registry_platform_crypto::generate_private_jwk(
        registry_platform_crypto::GeneratedKeyAlgorithm::Rs384,
    )
    .unwrap();
    key.alg = Some("RS256".into());
    let config = registry_platform_httputil::client::PrivateKeyJwtConfig::new(
        format!("http://{address}/token").parse().unwrap(),
        "breg-status",
        key,
    )
    .with_resource("urn:casework:test")
    .with_scopes(["casework:grants:status"]);
    let token = Arc::new(PrivateKeyJwt::new(config).unwrap());
    let client = TaskGrantStatusClient::new(
        "casework".into(),
        "https://casework.test".into(),
        "urn:breg:test".into(),
        format!("http://{address}").parse().unwrap(),
        token,
        None,
    )
    .unwrap();
    client.check(&binding).await.unwrap();
    *response.lock().unwrap() = serde_json::json!({"active":false});
    assert_eq!(client.check(&binding).await, Err(TaskGrantError::Refused));
    for field in [
        "grantId",
        "authority",
        "sourceIssuer",
        "principal",
        "client",
        "resource",
        "purpose",
        "bounds",
        "subjects",
        "expiresAt",
    ] {
        let mut changed = serde_json::to_value(&binding).unwrap();
        changed[field] = match field {
            "grantId" => serde_json::json!(Uuid::new_v4().to_string()),
            "bounds" => {
                serde_json::json!({"type":"breg","permissions":[{"collection":"people","operations":["get"]}]})
            }
            "subjects" => serde_json::json!({"person_reference":"other-person","active":true}),
            "expiresAt" => serde_json::json!(binding.expires_at + 1),
            _ => serde_json::json!("different"),
        };
        *response.lock().unwrap() = serde_json::json!({"active":true,"grant":changed});
        assert_eq!(
            client.check(&binding).await,
            Err(TaskGrantError::Refused),
            "{field}"
        );
    }
    *response.lock().unwrap() = serde_json::json!({"active":true,"grant":binding});
    client.check(&binding).await.unwrap();
    assert_eq!(state.status_calls.load(Ordering::SeqCst), 13);
    assert_eq!(
        state.token_calls.load(Ordering::SeqCst),
        1,
        "only the service credential can be cached"
    );
    let mut expired = binding.clone();
    expired.expires_at = 0;
    assert_eq!(client.check(&expired).await, Err(TaskGrantError::Refused));
    assert_eq!(
        state.status_calls.load(Ordering::SeqCst),
        13,
        "expired authority is refused before I/O"
    );
    server.abort();
}

#[test]
fn binding_debug_and_scalar_validation_preserve_privacy_and_exact_subjects() {
    let mut grant = binding();
    assert_eq!(format!("{grant:?}"), "TaskGrantBinding(<redacted>)");
    assert!(grant.validate().is_ok());
    for value in [
        Value::Null,
        serde_json::json!(["person"]),
        serde_json::json!({"id":"person"}),
        serde_json::json!(1.5),
    ] {
        grant.subjects.insert("person_reference".into(), value);
        assert_eq!(grant.validate(), Err(TaskGrantError::Refused));
    }
}

#[cfg(feature = "postgres-test")]
#[test]
fn write_idempotency_separates_grants_without_changing_read_authority() {
    use crate::{
        idempotency::{canonical_claim_context, resolve_binding, IdempotencyBinding},
        model::HttpMethod,
        postgres::ClaimContext,
    };
    let profile = registry_platform_audit::AuditProfile::unkeyed_dev_only();
    let base = ClaimContext::kernel_for_test(
        "agent".into(),
        "task".into(),
        Some("review".into()),
        "subject".into(),
    )
    .unwrap();
    let first = base.clone().with_task_grant(binding()).unwrap();
    let second = base.with_task_grant(binding()).unwrap();
    assert_eq!(
        canonical_claim_context(&profile, &first, "package").unwrap(),
        canonical_claim_context(&profile, &second, "package").unwrap()
    );
    let fields = std::collections::BTreeSet::from(["status".into()]);
    let resolve = |context| {
        resolve_binding(
            &profile,
            &IdempotencyBinding {
                key: "same-key",
                context,
                method: HttpMethod::Post,
                route: "/requests",
                target_record: None,
                package_revision: "package",
                response_fields: &fields,
                canonical_request_digest: [1; 32],
            },
        )
        .unwrap()
    };
    let first = resolve(&first);
    let second = resolve(&second);
    assert_eq!(first.key_reference, second.key_reference);
    assert_ne!(first.binding_reference, second.binding_reference);
}
