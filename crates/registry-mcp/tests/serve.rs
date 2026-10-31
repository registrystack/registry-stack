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
                .json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
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
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 operational log");
    assert!(stdout.contains("gateway listening"), "{stdout}");
    assert!(
        stdout.contains("resourceServer.allowInsecureHttp permits plain HTTP"),
        "{stdout}"
    );
    assert!(stdout.contains("shutting down"), "{stdout}");
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
