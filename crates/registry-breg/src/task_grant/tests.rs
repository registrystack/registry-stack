use super::*;
use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Form, Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_config::{SecretProvider, SecretResolver};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

#[derive(Clone)]
struct StateData {
    response: Arc<Mutex<Value>>,
    status_calls: Arc<AtomicUsize>,
    token_calls: Arc<AtomicUsize>,
    rejected_token_calls: Arc<AtomicUsize>,
    client_assertion_audience: String,
}
async fn token(
    State(state): State<StateData>,
    Form(form): Form<BTreeMap<String, String>>,
) -> Result<Json<Value>, axum::http::StatusCode> {
    let assertion = form
        .get("client_assertion")
        .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;
    let claims = assertion
        .split('.')
        .nth(1)
        .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
        .and_then(|value| serde_json::from_slice::<Value>(&value).ok())
        .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;
    if claims["aud"] != state.client_assertion_audience {
        state.rejected_token_calls.fetch_add(1, Ordering::SeqCst);
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }
    state.token_calls.fetch_add(1, Ordering::SeqCst);
    Ok(Json(
        serde_json::json!({"access_token":"synthetic-status-service","token_type":"Bearer","expires_in":300,"scope":"casework:grants:status"}),
    ))
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
    serde_json::from_value(serde_json::json!({"grantId":Uuid::new_v4().to_string(),"sourceIssuer":"https://casework.test","principal":"agent","client":"agent-client","resource":"urn:breg:test","purpose":"review","bounds":{"type":"breg","permissions":[{"collection":"records","operations":["get","patch"]}]},"subjects":{"subject_reference":"synthetic-subject","active":true},"expiresAt":chrono::Utc::now().timestamp()+900})).unwrap()
}

#[tokio::test]
async fn activated_status_client_uses_the_configured_assertion_audience_and_checks_each_attempt() {
    let binding = binding();
    let response = Arc::new(Mutex::new(
        serde_json::json!({"active":true,"grant":binding}),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let issuer = format!("http://{address}");
    let state = StateData {
        response: response.clone(),
        status_calls: Arc::new(AtomicUsize::new(0)),
        token_calls: Arc::new(AtomicUsize::new(0)),
        rejected_token_calls: Arc::new(AtomicUsize::new(0)),
        client_assertion_audience: issuer.clone(),
    };
    let app = Router::new()
        .route("/token", post(token))
        .route("/v1/task-grants/{id}/status", get(status))
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut key = registry_platform_crypto::generate_private_jwk(
        registry_platform_crypto::GeneratedKeyAlgorithm::Rs384,
    )
    .unwrap();
    key.alg = Some("RS256".into());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("status-key");
    let mut private = serde_json::to_value(&key).unwrap();
    for (name, value) in [
        ("d", &key.d),
        ("p", &key.p),
        ("q", &key.q),
        ("dp", &key.dp),
        ("dq", &key.dq),
        ("qi", &key.qi),
    ] {
        if let Some(value) = value {
            private[name] = Value::String(value.clone());
        }
    }
    std::fs::write(&path, serde_json::to_vec(&private).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let secrets = SecretResolver::new([SecretProvider::File], root.path()).unwrap();
    let config: TaskGrantStatusConfig = serde_json::from_value(serde_json::json!({
        "sourceIssuer":"https://casework.test",
        "baseUrl":issuer,
        "tokenEndpoint":format!("http://{address}/token"),
        "clientAssertionAudience":issuer,
        "clientId":"breg-status",
        "privateKeyRef":"secret:file/status-key",
        "caseworkResource":"urn:casework:test"
    }))
    .unwrap();
    let mut wrong = config.clone();
    wrong.client_assertion_audience = format!("http://{address}/token");
    let wrong = TaskGrantStatusRegistry::activate(&[wrong], "urn:breg:test", &secrets).unwrap();
    assert_eq!(
        wrong.check(&binding).await,
        Err(TaskGrantError::Unavailable)
    );
    assert_eq!(state.rejected_token_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.status_calls.load(Ordering::SeqCst), 0);

    let client = TaskGrantStatusRegistry::activate(&[config], "urn:breg:test", &secrets).unwrap();
    client.check(&binding).await.unwrap();
    *response.lock().unwrap() = serde_json::json!({"active":false});
    assert_eq!(client.check(&binding).await, Err(TaskGrantError::Refused));
    for field in [
        "grantId",
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
                serde_json::json!({"type":"breg","permissions":[{"collection":"records","operations":["get"]}]})
            }
            "subjects" => serde_json::json!({"subject_reference":"other-subject","active":true}),
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
    assert_eq!(state.status_calls.load(Ordering::SeqCst), 12);
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
        12,
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
        serde_json::json!(["subject"]),
        serde_json::json!({"id":"subject"}),
        serde_json::json!(1.5),
    ] {
        grant.subjects.insert("subject_reference".into(), value);
        assert_eq!(grant.validate(), Err(TaskGrantError::Refused));
    }
}

#[test]
fn a_scheduling_grant_is_refused_by_the_breg_binding() {
    // The grant union is closed, so a scheduling grant parses as a grant but
    // carries no BREG permissions; the binding refuses it before any
    // authorization decision or store access runs.
    let scheduling = serde_json::json!({
        "grantId": Uuid::new_v4().to_string(),
        "sourceIssuer": "https://casework.test",
        "principal": "agent",
        "client": "agent-client",
        "resource": "urn:breg:test",
        "purpose": "review",
        "bounds": {
            "type": "scheduling",
            "permissions": [{
                "service": "urn:service:intake",
                "location": "north",
                "actions": ["book"]
            }]
        },
        "subjects": {"subject_reference": "synthetic-subject", "active": true},
        "expiresAt": chrono::Utc::now().timestamp() + 900
    });
    let grant: TaskGrantBinding = serde_json::from_value(scheduling).unwrap();
    assert_eq!(grant.validate(), Err(TaskGrantError::Refused));
}

#[cfg(feature = "postgres-test")]
#[test]
fn write_idempotency_separates_grants_without_changing_read_authority() {
    use crate::{
        idempotency::{
            canonical_claim_context, resolve_binding, IdempotencyBinding, IdempotencyKeyDomain,
        },
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
                key_domain: IdempotencyKeyDomain::Caller,
            },
        )
        .unwrap()
    };
    let first = resolve(&first);
    let second = resolve(&second);
    assert_eq!(first.key_reference, second.key_reference);
    assert_ne!(first.binding_reference, second.binding_reference);
}
