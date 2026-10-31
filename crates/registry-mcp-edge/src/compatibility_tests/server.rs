// SPDX-License-Identifier: Apache-2.0

use std::{io, sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use registry_platform_audit::{AuditProfile, AuditWriter};
use registry_platform_httputil::{client::StaticToken, FetchUrlPolicy};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{TestAuthorizationServer, TestClient};
use rmcp::{
    model::{ProtocolVersion, Tool},
    ServerHandler,
};
use tower::ServiceExt;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    handler::GatewayHandler, router, token_verifier, AccessTokenAlgorithm, AuditOptions,
    EffectCertainty, FixedAuthorizationFactory, GatewayCore, GatewayInfo, Invocation, Provider,
    ProviderAuthorization, ProviderBinding, ProviderFailure, ProviderOutcome, RateLimitOptions,
    ResolvedTool, ResourceServer, ResourceServerOptions, ServerOptions, TokenBucketOptions,
    ToolAuditLog, VerifiedCaller,
};

struct UnusedProvider;

#[async_trait]
impl Provider for UnusedProvider {
    fn resolve_tool(&self, name: &str) -> Option<ResolvedTool> {
        (name == "unused")
            .then(|| ResolvedTool::new("unused", "test", "unused", "v1").expect("identity"))
    }

    async fn list_tools(
        &self,
        _: &VerifiedCaller,
        _: ProviderAuthorization,
    ) -> Result<Vec<Tool>, ProviderFailure> {
        Ok(Vec::new())
    }

    async fn invoke(
        &self,
        _: &VerifiedCaller,
        _: ProviderAuthorization,
        _: Invocation<'_>,
    ) -> ProviderOutcome {
        ProviderOutcome::failure(ProviderFailure::new(
            "unused",
            "Unused.",
            EffectCertainty::NoEffect,
        ))
    }
}

fn gateway_core() -> Arc<GatewayCore> {
    let token = StaticToken::new("test-only-static-token").expect("token");
    let binding = ProviderBinding::new(
        Arc::new(UnusedProvider),
        Arc::new(FixedAuthorizationFactory::new(Arc::new(token))),
        ["unused".to_owned()],
    )
    .expect("binding");
    let audit = ToolAuditLog::new(AuditWriter::from_line_sink(Box::new(io::sink())));
    Arc::new(
        GatewayCore::new(
            [binding],
            audit,
            AuditOptions::new("registry-test-mcp.tool-call/v1", "test_mcp.tool_call")
                .expect("audit"),
            GatewayInfo::new("test-mcp", "Test", "Test").expect("info"),
        )
        .expect("core"),
    )
}

async fn application(resource: &str) -> Router {
    let authorization = TestAuthorizationServer::builder()
        .client(TestClient::new("chat-host"))
        .start()
        .await;
    let options = ResourceServerOptions {
        resource: resource.to_owned(),
        issuer: authorization.issuer(),
        allow_insecure_http: false,
        algorithms: vec![AccessTokenAlgorithm::EdDSA],
        allowed_clients: vec!["chat-host".to_owned()],
        required_scopes: vec!["test:read".to_owned()],
        scope_claim: "scope".to_owned(),
        maximum_token_lifetime: Duration::from_secs(300),
        resource_name: "Test".to_owned(),
        principal_audit_namespace: "test-principal-v1".to_owned(),
        client_audit_namespace: "test-client-v1".to_owned(),
    };
    let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        authorization.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    let profile =
        AuditProfile::production_from_secret_bytes(Zeroizing::new(vec![8; 32])).expect("profile");
    let resource_server = ResourceServer::new(
        &options,
        token_verifier(&options, fetcher),
        profile.key_hasher(),
        RateLimitOptions {
            per_principal: TokenBucketOptions {
                requests_per_minute: 10,
                burst: 10,
            },
            per_client: TokenBucketOptions {
                requests_per_minute: 10,
                burst: 10,
            },
        },
    )
    .expect("resource server");
    router(
        gateway_core(),
        Arc::new(resource_server),
        &ServerOptions {
            resource: Url::parse(&options.resource).expect("resource URL"),
            maximum_request_bytes: 4096,
            hsts: false,
        },
    )
}

#[test]
fn initialization_pins_the_locked_sdk_protocol_version() {
    let initialization = GatewayHandler::new(gateway_core()).get_info();

    assert_eq!(
        initialization.protocol_version,
        ProtocolVersion::V_2026_07_28
    );
}

async fn status(app: &Router, uri: &str, host: Option<&str>) -> StatusCode {
    let mut request =
        Request::post(uri).header(header::ACCEPT, "application/json, text/event-stream");
    if let Some(host) = host {
        request = request.header(header::HOST, host);
    }
    app.clone()
        .oneshot(request.body(Body::empty()).expect("request"))
        .await
        .expect("response")
        .status()
}

#[tokio::test]
async fn the_resource_host_is_admitted_with_or_without_its_default_port() {
    let app = application("https://gateway.example.test/mcp").await;
    for host in [
        "gateway.example.test",
        "gateway.example.test:443",
        "Gateway.Example.Test",
    ] {
        assert_ne!(
            status(&app, "/mcp", Some(host)).await,
            StatusCode::FORBIDDEN,
            "{host}"
        );
    }
    for host in [
        "gateway.example.test:80",
        "gateway.example.test:8443",
        "attacker.example.test",
        "user@gateway.example.test",
        "",
    ] {
        assert_eq!(
            status(&app, "/mcp", Some(host)).await,
            StatusCode::FORBIDDEN,
            "{host}"
        );
    }
}

#[tokio::test]
async fn an_explicit_resource_port_must_be_named() {
    let app = application("http://127.0.0.1:8095/mcp").await;
    assert_ne!(
        status(&app, "/mcp", Some("127.0.0.1:8095")).await,
        StatusCode::FORBIDDEN
    );
    for host in ["127.0.0.1", "127.0.0.1:80", "localhost:8095"] {
        assert_eq!(
            status(&app, "/mcp", Some(host)).await,
            StatusCode::FORBIDDEN
        );
    }
}

#[tokio::test]
async fn an_ipv6_resource_allows_its_bracketed_host() {
    let app = application("https://[::1]:8443/mcp").await;
    assert_ne!(
        status(&app, "/mcp", Some("[::1]:8443")).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(&app, "/mcp", Some("[::1]")).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn an_http2_authority_stands_in_for_a_missing_host() {
    let app = application("https://gateway.example.test/mcp").await;
    assert_ne!(
        status(&app, "https://gateway.example.test/mcp", None).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(&app, "https://attacker.example.test/mcp", None).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(status(&app, "/mcp", None).await, StatusCode::FORBIDDEN);
}
