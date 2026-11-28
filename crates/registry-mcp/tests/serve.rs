// SPDX-License-Identifier: Apache-2.0

#[path = "support/serve.rs"]
mod support;

use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
use registry_platform_testing::{
    ExchangeProfile, TestActorKind, TestAuthorizationServer, TestClient,
};
use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncReadExt as _, sync::oneshot};

#[tokio::test]
async fn serve_reaches_readiness_and_stops_gracefully_on_sigterm() {
    let scratch = tempfile::tempdir().expect("serve scratch directory");
    let address = support::free_address();
    let resource = format!("http://localhost:{}/mcp", address.port());
    let gateway_key =
        generate_private_jwk(GeneratedKeyAlgorithm::Es256).expect("gateway fixture private key");
    let issuer_key =
        generate_private_jwk(GeneratedKeyAlgorithm::Es256).expect("issuer fixture private key");
    let registry_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind blocking registry fixture");
    let registry_address = registry_listener
        .local_addr()
        .expect("blocking registry fixture address");
    let (registry_entered_tx, registry_entered_rx) = oneshot::channel();
    let (registry_release_tx, registry_release_rx) = oneshot::channel();
    let registry = tokio::spawn(async move {
        let (mut stream, _) = registry_listener
            .accept()
            .await
            .expect("accept gateway registry request");
        let mut request = [0_u8; 4096];
        let read = stream
            .read(&mut request)
            .await
            .expect("read gateway registry request");
        assert!(read > 0, "gateway registry request is not empty");
        let _ = registry_entered_tx.send(());
        let _ = registry_release_rx.await;
    });
    let issuer = TestAuthorizationServer::builder()
        .with_signing_key(issuer_key)
        .client(TestClient::new("chat-host").with_resource(&resource))
        .client(
            TestClient::new("citizen-gateway")
                .with_public_jwk(gateway_key.public())
                .with_resource(&resource)
                .with_resource("urn:example:breg")
                .with_actor_kind(TestActorKind::Agent)
                .with_service_subject("gateway-service"),
        )
        .exchange_profile(ExchangeProfile::Conformant)
        .start()
        .await;
    let runtime = support::write_runtime(
        scratch.path(),
        address,
        &issuer.issuer(),
        &issuer.jwks_uri(),
        &issuer.token_endpoint(),
        &format!("http://{registry_address}/"),
        &gateway_key,
    );
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_registry-mcp"));
    let mut service = support::ServiceProcess::start(&binary, &runtime);

    service
        .wait_until_ready(&format!("http://{address}/ready"))
        .await;
    let ready = reqwest::get(format!("http://{address}/ready"))
        .await
        .unwrap();
    assert_eq!(ready.headers()["registry-posture"], "development");
    assert!(!ready
        .headers()
        .contains_key(reqwest::header::STRICT_TRANSPORT_SECURITY));
    let body: serde_json::Value = ready.json().await.unwrap();
    assert_eq!(body["posture"], "development");
    let settings = body["developmentSettings"].as_array().unwrap();
    for pointer in [
        "/resourceServer/resource",
        "/resourceServer/allowInsecureHttp",
    ] {
        assert!(settings.iter().any(|setting| setting["pointer"] == pointer));
    }
    let expires_at = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs(),
    )
    .expect("time fits")
        + 300;
    let token = issuer.issue_access_token(
        "chat-host",
        "serve-smoke-caller",
        &resource,
        "citizen:self",
        expires_at,
    );
    let mut request = tokio::spawn({
        let endpoint = format!("http://{address}/mcp");
        let host = format!("localhost:{}", address.port());
        async move {
            reqwest::Client::builder()
                .no_proxy()
                .build()
                .expect("MCP smoke client")
                .post(endpoint)
                .header("host", host)
                .bearer_auth(token)
                .header("accept", "application/json, text/event-stream")
                .json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_my_details","arguments":{}}}))
                .send()
                .await
        }
    });
    let mut registry_entered_rx = registry_entered_rx;
    tokio::select! {
        entered = &mut registry_entered_rx => {
            entered.expect("blocking registry entry signal");
        }
        result = &mut request => {
            let response = result
                .expect("MCP request task finishes")
                .expect("MCP request receives a response");
            let status = response.status();
            let body = response.text().await.expect("MCP response body");
            panic!("MCP request completed before reaching the registry: {status} {body}");
        }
        () = tokio::time::sleep(Duration::from_secs(5)) => {
            panic!("gateway did not reach blocking registry fixture");
        }
    }

    service.signal_terminate();
    service.assert_running_for(Duration::from_millis(300));
    let _ = registry_release_tx.send(());
    registry.await.expect("blocking registry fixture finishes");
    let _ = request.await.expect("MCP request task finishes");
    let output = service.finish();

    assert!(
        output.status.success(),
        "serve status: {}; stdout: {}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let audit = std::fs::read_to_string(scratch.path().join("audit.jsonl")).expect("audit journal");
    let line: serde_json::Value =
        serde_json::from_str(audit.lines().next().expect("audit record")).unwrap();
    assert_eq!(line["posture"], "development");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 operational log");
    assert!(stdout.contains("gateway listening"), "{stdout}");
    assert!(stdout.contains("posture declared"), "{stdout}");
    assert!(
        stdout.contains("platform.posture.mcp-http-resource"),
        "{stdout}"
    );
    assert!(
        stdout.contains("platform.posture.insecure-issuer-http"),
        "{stdout}"
    );
    assert!(stdout.contains("shutting down"), "{stdout}");
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn assembled_bindings_accept_development_responses_only_in_development() {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        routing::{get, post},
        Json, Router,
    };
    use registry_mcp::config::RuntimeConfig;
    use registry_platform_config::{DeclaredPosture, Posture, PostureSource};
    use registry_platform_testing::{jwks_from_private_jwk, sign_compact_jwt_with_key};
    use serde_json::{json, Value};
    use std::os::unix::fs::PermissionsExt;
    use tower::ServiceExt as _;

    const RESOURCE: &str = "https://gateway.example.test/mcp";
    const ISSUER: &str = "https://issuer.example.test";
    const TRACE: &str = "0123456789abcdef0123456789abcdef";
    const TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";

    let key = generate_private_jwk(GeneratedKeyAlgorithm::Es256).unwrap();
    let gateway_key = generate_private_jwk(GeneratedKeyAlgorithm::Es256).unwrap();
    let downstream = Router::new()
        .route(
            "/token",
            post(|| async {
                Json(json!({
                    "access_token":"synthetic-downstream-token",
                    "token_type":"Bearer",
                    "issued_token_type":"urn:ietf:params:oauth:token-type:access_token",
                    "expires_in":300,
                    "scope":"citizen:self"
                }))
            }),
        )
        .route(
            "/v1/registry",
            get(|| async {
                (
                StatusCode::NOT_FOUND,
                [
                    ("Registry-Posture", "development"),
                    ("traceparent", TRACEPARENT),
                    ("cache-control", "no-store"),
                    ("content-type", "application/problem+json"),
                ],
                json!({
                    "type":"https://id.registrystack.org/problems/registry-breg/resource/not_found",
                    "title":"Not found", "status":404, "detail":"Not found.",
                    "code":"resource.not_found", "traceId":TRACE
                }).to_string(),
            )
            }),
        )
        .fallback(|| async {
            (
                [
                    ("Registry-Posture", "development"),
                    ("traceparent", TRACEPARENT),
                    ("cache-control", "no-store"),
                ],
                Json(json!({"items": [], "status": "complete"})),
            )
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    let token_endpoint = format!("{origin}token");
    let peer = tokio::spawn(async move { axum::serve(listener, downstream).await.unwrap() });
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = sign_compact_jwt_with_key(
        &key,
        "at+jwt",
        key.kid.as_deref().unwrap(),
        json!({
            "iss":ISSUER, "sub":"fixture-subject", "aud":RESOURCE, "client_id":"chat-host",
            "scope":"citizen:self", "iat":now, "exp":now + 300,
        }),
    );

    for posture in [Posture::Production, Posture::Development] {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let path = support::write_runtime(
            &root_path,
            support::free_address(),
            ISSUER,
            "https://issuer.example.test/jwks",
            &token_endpoint,
            &origin,
            &gateway_key,
        );
        let jwks = root_path.join("secrets/jwks");
        std::fs::write(
            &jwks,
            serde_json::to_vec(&jwks_from_private_jwk(&key)).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&jwks, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut runtime: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        runtime["resourceServer"]["resource"] = json!(RESOURCE);
        runtime["resourceServer"]
            .as_object_mut()
            .unwrap()
            .remove("allowInsecureHttp");
        runtime["resourceServer"]["jwksSource"] = json!({
            "type": if posture == Posture::Production { "static" } else { "test-issuer" },
            "documentRef":"secret:file/jwks"
        });
        runtime["bindings"][0]["provider"]["service"]["reviewBaseUrl"] =
            json!("https://review.example.test/");
        let casework_binding = json!({
            "name":"casework", "tools":["list_my_review_tasks"],
            "provider":{
                "type":"casework", "authority":"delegated-staff-read", "baseUrl":origin,
                "readerPolicy":"assistant-reader", "pageSize":20,
                "authorization":{
                    "exchange":{
                        "tokenEndpoint":token_endpoint, "clientId":"casework-gateway",
                        "privateKeyRef":"secret:file/exchange-key.json", "assertionAudience":ISSUER,
                    },
                    "audience":"urn:example:casework", "scopes":["citizen:self"],
                },
            },
        });
        for (name, expected) in [
            (
                "get_my_details",
                Some(if posture == Posture::Production {
                    "unexpected-response"
                } else {
                    "not-found"
                }),
            ),
            (
                "list_my_review_tasks",
                (posture == Posture::Production).then_some("casework-response-invalid"),
            ),
        ] {
            let mut runtime = runtime.clone();
            if name == "list_my_review_tasks" {
                runtime["bindings"] = json!([casework_binding]);
                runtime["audit"]["path"] = json!(root_path.join("casework-audit.jsonl"));
            }
            std::fs::write(&path, serde_json::to_vec(&runtime).unwrap()).unwrap();
            let loaded = RuntimeConfig::load_with_posture(
                &path,
                DeclaredPosture {
                    posture,
                    source: PostureSource::Flag,
                },
            )
            .unwrap();
            let app = registry_mcp::runtime::build_with_posture(&loaded)
                .await
                .unwrap();
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("host", "gateway.example.test")
                        .header("authorization", format!("Bearer {token}"))
                        .header("accept", "application/json, text/event-stream")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            json!({
                                "jsonrpc":"2.0", "id":1, "method":"tools/call",
                                "params":{"name":name, "arguments":{}}
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = to_bytes(response.into_body(), 65_536).await.unwrap();
            let body = std::str::from_utf8(&bytes).unwrap();
            let data = body
                .lines()
                .find_map(|line| line.strip_prefix("data: "))
                .unwrap_or(body);
            let reply: Value = serde_json::from_str(data).unwrap();
            let result = &reply["result"];
            assert!(result.is_object(), "{posture:?} {name}: {reply}");
            assert_eq!(
                result["isError"].as_bool().unwrap_or(false),
                expected.is_some(),
                "{posture:?} {name}: {reply}"
            );
            assert_eq!(
                result["structuredContent"]["error"]["code"].as_str(),
                expected,
                "{posture:?} {name}: {reply}"
            );
        }
    }
    peer.abort();
}
