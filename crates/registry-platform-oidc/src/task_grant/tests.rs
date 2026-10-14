use super::*;
use axum::{
    extract::State,
    http::{HeaderMap, Uri},
    routing::{get, post},
    Form, Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_config::{SecretProvider, SecretReference, SecretResolver};
use registry_platform_yaml::{ExternalId, Url};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

#[derive(Clone)]
struct StateData {
    response: Arc<Mutex<Value>>,
    status_code: Arc<AtomicUsize>,
    status_calls: Arc<AtomicUsize>,
    token_calls: Arc<AtomicUsize>,
    rejected_token_calls: Arc<AtomicUsize>,
    client_assertion_audience: String,
    requested: Arc<Mutex<Vec<(String, String)>>>,
    status_paths: Arc<Mutex<Vec<String>>>,
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
    let scope = form.get("scope").cloned().unwrap_or_default();
    state.requested.lock().unwrap().push((
        scope.clone(),
        form.get("resource").cloned().unwrap_or_default(),
    ));
    Ok(Json(
        serde_json::json!({"access_token":"synthetic-status-service","token_type":"Bearer","expires_in":300,"scope":scope}),
    ))
}
async fn status(
    State(state): State<StateData>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<Value>, axum::http::StatusCode> {
    assert_eq!(
        headers.get("authorization").unwrap(),
        "Bearer synthetic-status-service"
    );
    state.status_calls.fetch_add(1, Ordering::SeqCst);
    state
        .status_paths
        .lock()
        .unwrap()
        .push(uri.path().to_owned());
    let code = axum::http::StatusCode::from_u16(
        u16::try_from(state.status_code.load(Ordering::SeqCst)).unwrap(),
    )
    .unwrap();
    if code != axum::http::StatusCode::OK {
        return Err(code);
    }
    Ok(Json(state.response.lock().unwrap().clone()))
}
fn binding() -> TaskGrantStatusBinding {
    serde_json::from_value(serde_json::json!({"grantId":Uuid::new_v4().to_string(),"sourceIssuer":"https://authority.test","principal":"agent","client":"agent-client","resource":"urn:resource:test","purpose":"review","bounds":{"type":"breg","permissions":[{"collection":"records","operations":["get","patch"]}]},"subjects":{"subject_reference":"synthetic-subject","active":true},"expiresAt":chrono::Utc::now().timestamp()+900})).unwrap()
}
fn state(response: Value, client_assertion_audience: String) -> StateData {
    StateData {
        response: Arc::new(Mutex::new(response)),
        status_code: Arc::new(AtomicUsize::new(200)),
        status_calls: Arc::new(AtomicUsize::new(0)),
        token_calls: Arc::new(AtomicUsize::new(0)),
        rejected_token_calls: Arc::new(AtomicUsize::new(0)),
        client_assertion_audience,
        requested: Arc::default(),
        status_paths: Arc::default(),
    }
}
/// Writes an owner-only private JWK as `status-key` under `root`.
fn status_key_secrets(root: &std::path::Path) -> SecretResolver {
    let mut key = registry_platform_crypto::generate_private_jwk(
        registry_platform_crypto::GeneratedKeyAlgorithm::Rs384,
    )
    .unwrap();
    key.alg = Some("RS256".into());
    let path = root.join("status-key");
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
    SecretResolver::new([SecretProvider::File], root).unwrap()
}
fn endpoint(base: &str) -> TaskGrantStatusEndpoint {
    TaskGrantStatusEndpoint {
        source_issuer: ExternalId::new("https://authority.test").unwrap(),
        base_url: Url::new(base).unwrap(),
        status_path: "/v1/task-grants/{grantId}/status".into(),
        token_endpoint: Url::new(format!("{base}/token")).unwrap(),
        client_assertion_audience: ExternalId::new(base).unwrap(),
        client_id: ExternalId::new("status-client").unwrap(),
        private_key_ref: SecretReference::parse("secret:file/status-key").unwrap(),
        status_resource: ExternalId::new("urn:authority:test").unwrap(),
        status_scope: ExternalId::new("grants:status").unwrap(),
        ca_bundle_ref: None,
    }
}

#[tokio::test]
async fn status_client_requests_the_configured_scope_resource_and_status_path() {
    let binding = binding();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let state = state(
        serde_json::json!({"active":true,"grant":binding}),
        base.clone(),
    );
    let app = Router::new()
        .route("/token", post(token))
        .route("/authority/grants/{id}/state", get(status))
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let root = tempfile::tempdir().unwrap();
    let secrets = status_key_secrets(root.path());
    let mut endpoint = endpoint(&base);
    endpoint.status_path = "/authority/grants/{grantId}/state".into();
    endpoint.status_scope = ExternalId::new("grants:read-status").unwrap();
    endpoint.status_resource = ExternalId::new("urn:authority:status").unwrap();
    let client =
        TaskGrantStatusRegistry::activate(&[endpoint], "urn:resource:test", &secrets).unwrap();
    client.check(&binding).await.unwrap();
    assert_eq!(
        *state.requested.lock().unwrap(),
        vec![(
            "grants:read-status".to_owned(),
            "urn:authority:status".to_owned()
        )]
    );
    assert_eq!(
        *state.status_paths.lock().unwrap(),
        vec![format!("/authority/grants/{}/state", binding.grant_id)]
    );
    server.abort();
}

#[tokio::test]
async fn activated_status_client_uses_the_configured_assertion_audience_and_checks_each_attempt() {
    let binding = binding();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let issuer = format!("http://{address}");
    let state = state(
        serde_json::json!({"active":true,"grant":binding}),
        issuer.clone(),
    );
    let response = state.response.clone();
    let app = Router::new()
        .route("/token", post(token))
        .route("/v1/task-grants/{id}/status", get(status))
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let root = tempfile::tempdir().unwrap();
    let secrets = status_key_secrets(root.path());
    let config = endpoint(&issuer);
    let mut wrong = config.clone();
    wrong.client_assertion_audience =
        registry_platform_yaml::ExternalId::new(format!("http://{address}/token")).unwrap();
    let wrong = TaskGrantStatusRegistry::activate(&[wrong], "urn:resource:test", &secrets).unwrap();
    assert_eq!(
        wrong.check(&binding).await,
        Err(TaskGrantError::Unavailable)
    );
    assert_eq!(state.rejected_token_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.status_calls.load(Ordering::SeqCst), 0);

    let client =
        TaskGrantStatusRegistry::activate(&[config], "urn:resource:test", &secrets).unwrap();
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
    // A prior positive result cannot substitute for a fresh observation.
    // Rejected resource-server credentials do not prove this grant inactive.
    let mut observed = Vec::new();
    for code in [401, 403, 404] {
        state.status_code.store(code, Ordering::SeqCst);
        observed.push((code, client.check(&binding).await));
    }
    assert_eq!(state.status_calls.load(Ordering::SeqCst), 15);
    assert_eq!(state.token_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        observed,
        vec![
            (401, Err(TaskGrantError::Unavailable)),
            (403, Err(TaskGrantError::Unavailable)),
            (404, Err(TaskGrantError::Refused)),
        ]
    );
    server.abort();
}

#[test]
fn binding_debug_and_scalar_validation_preserve_privacy_and_exact_subjects() {
    let mut grant = binding();
    assert_eq!(format!("{grant:?}"), "TaskGrantStatusBinding(<redacted>)");
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

#[tokio::test]
async fn fixed_bounds_without_disclosed_claims_still_require_exact_fresh_status() {
    let mut binding = binding();
    binding.subjects.clear();
    binding.validate().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let state = state(
        serde_json::json!({"active":true,"grant":binding}),
        issuer.clone(),
    );
    let app = Router::new()
        .route("/token", post(token))
        .route("/v1/task-grants/{id}/status", get(status))
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let root = tempfile::tempdir().unwrap();
    let secrets = status_key_secrets(root.path());
    let client =
        TaskGrantStatusRegistry::activate(&[endpoint(&issuer)], "urn:resource:test", &secrets)
            .unwrap();
    client.check(&binding).await.unwrap();
    let mut changed = serde_json::to_value(&binding).unwrap();
    changed["subjects"] = serde_json::json!({"unexpected":"claim"});
    *state.response.lock().unwrap() = serde_json::json!({"active":true,"grant":changed});
    assert_eq!(client.check(&binding).await, Err(TaskGrantError::Refused));
    for field in ["principal", "bounds"] {
        let mut changed = serde_json::to_value(&binding).unwrap();
        changed[field] = if field == "principal" {
            serde_json::json!("another-agent")
        } else {
            serde_json::json!({"type":"breg","permissions":[{"collection":"records","operations":["get"]}]})
        };
        *state.response.lock().unwrap() = serde_json::json!({"active":true,"grant":changed});
        assert_eq!(client.check(&binding).await, Err(TaskGrantError::Refused));
    }
    *state.response.lock().unwrap() = serde_json::json!({"active":false});
    assert_eq!(client.check(&binding).await, Err(TaskGrantError::Refused));
    assert_eq!(state.status_calls.load(Ordering::SeqCst), 5);
    binding.subjects = (0..32)
        .map(|index| (format!("claim-{index}"), Value::Bool(true)))
        .collect();
    binding.validate().unwrap();
    binding
        .subjects
        .insert("claim-32".into(), Value::Bool(true));
    assert_eq!(binding.validate(), Err(TaskGrantError::Refused));
    server.abort();
}

#[test]
fn the_shared_status_block_maps_onto_one_endpoint_member_for_member() {
    let block: registry_platform_config::TaskGrantStatusConfig =
        serde_json::from_value(serde_json::json!({
            "sourceIssuer":"https://authority.test",
            "baseUrl":"https://authority.test",
            "tokenEndpoint":"https://authority.test/token",
            "clientAssertionAudience":"https://authority.test",
            "clientId":"status-client",
            "privateKeyRef":"secret:file/status-key",
            "caseworkResource":"urn:authority:test",
            "statusScope":"grants:status",
            "caBundleRef":"secret:file/status-ca"
        }))
        .unwrap();
    let mapped = TaskGrantStatusEndpoint::from(&block);
    let expected = endpoint("https://authority.test");
    assert_eq!(mapped.source_issuer, expected.source_issuer);
    assert_eq!(mapped.base_url, expected.base_url);
    assert_eq!(mapped.status_path, expected.status_path);
    assert_eq!(mapped.token_endpoint, expected.token_endpoint);
    assert_eq!(
        mapped.client_assertion_audience,
        expected.client_assertion_audience
    );
    assert_eq!(mapped.client_id, expected.client_id);
    assert_eq!(mapped.private_key_ref, expected.private_key_ref);
    assert_eq!(mapped.status_resource, expected.status_resource);
    assert_eq!(mapped.status_scope, expected.status_scope);
    assert_eq!(
        mapped.ca_bundle_ref.as_ref().map(SecretReference::as_str),
        Some("secret:file/status-ca")
    );
}
