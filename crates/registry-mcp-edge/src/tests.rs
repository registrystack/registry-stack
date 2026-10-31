use std::{
    io::{self, Write},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use registry_platform_audit::{AuditProfile, AuditWriter};
use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
use rmcp::model::{Tool, ToolAnnotations};
use serde_json::{json, Map, Value};
use url::Url;

use crate::{
    AccessTokenAlgorithm, AuditOptions, AuthorizationError, AuthorizationFactory, CallerContext,
    CatalogError, Delegation, DelegationOptions, EffectCertainty, GatewayCore, GatewayInfo,
    Invocation, Provider, ProviderAuthorization, ProviderBinding, ProviderFailure, ProviderOutcome,
    ResolvedTool, ResourceServerError, ResourceServerOptions, ToolAuditLog, VerifiedCaller,
};

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("buffer lock").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Buffer {
    fn entries(&self) -> Vec<Value> {
        String::from_utf8(self.0.lock().expect("buffer lock").clone())
            .expect("UTF-8 audit")
            .lines()
            .map(|line| serde_json::from_str(line).expect("audit line"))
            .collect()
    }

    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("buffer lock").clone()).expect("UTF-8 log")
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for Buffer {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

struct StubProvider {
    calls: AtomicUsize,
    outcome: Mutex<Option<ProviderOutcome>>,
}

impl StubProvider {
    fn successful() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            outcome: Mutex::new(Some(ProviderOutcome::success(
                json!({"result": "bounded"}),
                EffectCertainty::NoEffect,
            ))),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

struct FailingCatalogProvider {
    failure: ProviderFailure,
}

struct EmptyCatalogProvider;

#[async_trait]
impl Provider for EmptyCatalogProvider {
    fn resolve_tool(&self, public_name: &str) -> Option<ResolvedTool> {
        (public_name == "empty_read").then(|| {
            ResolvedTool::new("empty_read", "empty", "read", "v1").expect("static tool identity")
        })
    }

    async fn list_tools(
        &self,
        _caller: &VerifiedCaller,
        _authorization: ProviderAuthorization,
    ) -> Result<Vec<Tool>, ProviderFailure> {
        Ok(Vec::new())
    }

    async fn invoke(
        &self,
        _caller: &VerifiedCaller,
        _authorization: ProviderAuthorization,
        _invocation: Invocation<'_>,
    ) -> ProviderOutcome {
        ProviderOutcome::failure(ProviderFailure::new(
            "not-visible",
            "The tool is not visible to this caller.",
            EffectCertainty::NoEffect,
        ))
    }
}

#[async_trait]
impl Provider for FailingCatalogProvider {
    fn resolve_tool(&self, public_name: &str) -> Option<ResolvedTool> {
        (public_name == "unavailable_read").then(|| {
            ResolvedTool::new("unavailable_read", "failing", "read", "v1")
                .expect("static tool identity")
        })
    }

    async fn list_tools(
        &self,
        _caller: &VerifiedCaller,
        _authorization: ProviderAuthorization,
    ) -> Result<Vec<Tool>, ProviderFailure> {
        Err(self.failure.clone())
    }

    async fn invoke(
        &self,
        _caller: &VerifiedCaller,
        _authorization: ProviderAuthorization,
        _invocation: Invocation<'_>,
    ) -> ProviderOutcome {
        ProviderOutcome::failure(self.failure.clone())
    }
}

struct RefusingAuthorization;

impl AuthorizationFactory for RefusingAuthorization {
    fn authorization(
        &self,
        _caller: &VerifiedCaller,
    ) -> Result<ProviderAuthorization, AuthorizationError> {
        Err(AuthorizationError::Unavailable)
    }
}

struct MisconfiguredAuthorization;

impl AuthorizationFactory for MisconfiguredAuthorization {
    fn authorization(
        &self,
        _caller: &VerifiedCaller,
    ) -> Result<ProviderAuthorization, AuthorizationError> {
        Err(AuthorizationError::Configuration)
    }
}

#[async_trait]
impl Provider for StubProvider {
    fn resolve_tool(&self, public_name: &str) -> Option<ResolvedTool> {
        match public_name {
            "read_bounded" => Some(
                ResolvedTool::new("read_bounded", "stub", "read", "v1")
                    .expect("static tool identity"),
            ),
            "other_read" => Some(
                ResolvedTool::new("other_read", "stub", "other", "v1")
                    .expect("static tool identity"),
            ),
            _ => None,
        }
    }

    async fn list_tools(
        &self,
        _caller: &VerifiedCaller,
        _authorization: ProviderAuthorization,
    ) -> Result<Vec<Tool>, ProviderFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let schema = || {
            Map::from_iter([
                ("type".to_owned(), json!("object")),
                ("additionalProperties".to_owned(), json!(false)),
            ])
        };
        let annotations = || {
            ToolAnnotations::new()
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(false)
        };
        Ok(vec![
            Tool::new("read_bounded", "Read one bounded value.", schema())
                .with_annotations(annotations()),
            Tool::new("other_read", "Read another bounded value.", schema())
                .with_annotations(annotations()),
        ])
    }

    async fn invoke(
        &self,
        _caller: &VerifiedCaller,
        _authorization: ProviderAuthorization,
        invocation: Invocation<'_>,
    ) -> ProviderOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(invocation.tool.public_name(), "read_bounded");
        assert!(!invocation.request_id.is_nil());
        self.outcome
            .lock()
            .expect("outcome lock")
            .take()
            .unwrap_or_else(|| {
                ProviderOutcome::failure(ProviderFailure::new(
                    "already-called",
                    "The test provider was already called.",
                    EffectCertainty::NoEffect,
                ))
            })
    }
}

fn caller() -> VerifiedCaller {
    VerifiedCaller::for_test_internal(
        "https://issuer.example.test/",
        "staff-a",
        "chat-host",
        "inbound-secret-token",
        i64::MAX,
        "principal-pseudonym",
        "client-pseudonym",
    )
}

fn delegation() -> Delegation {
    let key = generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("private key");
    Delegation::new(DelegationOptions {
        token_endpoint: Url::parse("https://issuer.example.test/token").expect("URL"),
        client_id: "gateway-client".to_owned(),
        private_key: key,
        assertion_audience: None,
        gateway_resource: "https://gateway.example.test/mcp".to_owned(),
        downstream_resource: "urn:example:downstream".to_owned(),
        downstream_scopes: vec!["bounded:read".to_owned()],
        attempt_timeout: Duration::from_secs(1),
        generation: "test-v1".to_owned(),
    })
    .expect("delegation")
}

fn audit() -> (ToolAuditLog, Buffer) {
    let buffer = Buffer::default();
    (
        ToolAuditLog::new(AuditWriter::from_line_sink(Box::new(buffer.clone()))),
        buffer,
    )
}

fn core(provider: Arc<StubProvider>, audit: ToolAuditLog) -> GatewayCore {
    let binding = ProviderBinding::new(
        provider,
        Arc::new(delegation()),
        ["read_bounded".to_owned()],
    )
    .expect("provider binding");
    gateway([binding], audit)
}

fn gateway(
    bindings: impl IntoIterator<Item = ProviderBinding>,
    audit: ToolAuditLog,
) -> GatewayCore {
    GatewayCore::new(
        bindings,
        audit,
        AuditOptions::new("registry-test-mcp.tool-call/v1", "test_mcp.tool_call")
            .expect("audit options"),
        GatewayInfo::new("test-mcp", "Test gateway", "Test instructions").expect("gateway info"),
    )
    .expect("gateway core")
}

#[tokio::test]
async fn call_is_audited_before_dispatch_and_before_release() {
    let provider = Arc::new(StubProvider::successful());
    let (audit, buffer) = audit();
    let core = core(Arc::clone(&provider), audit);

    let result = core.call(&caller(), "read_bounded", None).await;

    assert_eq!(result.is_error, Some(false));
    assert_eq!(provider.calls(), 1);
    let entries = buffer.entries();
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert_eq!(entries[0]["schema"], "registry-test-mcp.tool-call/v1");
    assert_eq!(entries[0]["phase"], "request");
    assert_eq!(entries[0]["record"]["event"], "test_mcp.tool_call");
    assert_eq!(entries[0]["record"]["tool"], "read_bounded");
    assert_eq!(
        entries[0]["record"]["principalPseudonym"],
        "principal-pseudonym"
    );
    assert_eq!(entries[0]["record"]["clientPseudonym"], "client-pseudonym");
    assert_eq!(entries[1]["phase"], "response");
    assert_eq!(entries[1]["record"]["outcome"], "ok");
}

#[tokio::test]
async fn an_unknown_tool_is_refused_before_audit_exchange_or_provider_io() {
    let provider = Arc::new(StubProvider::successful());
    let (audit, buffer) = audit();
    let core = core(Arc::clone(&provider), audit);

    let result = core.call(&caller(), "not-configured", None).await;

    assert_eq!(result.is_error, Some(true));
    assert_eq!(
        result.structured_content.unwrap()["error"]["code"],
        "unknown-tool"
    );
    assert_eq!(provider.calls(), 0);
    assert!(buffer.entries().is_empty());
}

#[tokio::test]
async fn audit_begin_failure_refuses_before_provider_io() {
    let provider = Arc::new(StubProvider::successful());
    let core = core(
        Arc::clone(&provider),
        ToolAuditLog::refusing_after_for_test(0),
    );

    let result = core.call(&caller(), "read_bounded", None).await;

    assert_eq!(result.is_error, Some(true));
    assert_eq!(
        result.structured_content.unwrap()["error"]["code"],
        "service-unavailable"
    );
    assert_eq!(provider.calls(), 0);
}

#[tokio::test]
async fn terminal_audit_failure_suppresses_the_provider_result() {
    let provider = Arc::new(StubProvider::successful());
    let core = core(
        Arc::clone(&provider),
        ToolAuditLog::refusing_after_for_test(1),
    );

    let result = core.call(&caller(), "read_bounded", None).await;

    assert_eq!(result.is_error, Some(true));
    assert_eq!(
        result.structured_content.unwrap()["error"]["code"],
        "service-unavailable"
    );
    assert_eq!(provider.calls(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn audit_outages_are_logged_without_caller_values() {
    let logs = Buffer::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(logs.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("install captured log subscriber");
    tracing::error!("capture-positive-control");

    let request_provider = Arc::new(StubProvider::successful());
    let request_core = core(
        Arc::clone(&request_provider),
        ToolAuditLog::refusing_after_for_test(0),
    );
    let request = request_core.call(&caller(), "read_bounded", None).await;
    assert_eq!(request.is_error, Some(true));

    let response_provider = Arc::new(StubProvider::successful());
    let response_core = core(
        Arc::clone(&response_provider),
        ToolAuditLog::refusing_after_for_test(1),
    );
    let response = response_core.call(&caller(), "read_bounded", None).await;
    assert_eq!(response.is_error, Some(true));

    let refusal_provider = Arc::new(StubProvider {
        calls: AtomicUsize::new(0),
        outcome: Mutex::new(Some(ProviderOutcome::failure(ProviderFailure::new(
            "downstream-refused",
            "The downstream service refused the request.",
            EffectCertainty::NoEffect,
        )))),
    });
    let (refusal_audit, _) = audit();
    let refusal_core = core(refusal_provider, refusal_audit);
    let refusal = refusal_core.call(&caller(), "read_bounded", None).await;
    assert_eq!(refusal.is_error, Some(true));

    let unavailable = Arc::new(FailingCatalogProvider {
        failure: ProviderFailure::new(
            "catalog-backend-unavailable",
            "The provider catalog is unavailable.",
            EffectCertainty::NoEffect,
        )
        .with_trace_id("catalog-trace-1"),
    });
    let binding = ProviderBinding::new(
        unavailable,
        Arc::new(delegation()),
        ["unavailable_read".to_owned()],
    )
    .expect("provider binding");
    let (audit, _) = audit();
    let catalog_core = gateway([binding], audit);
    assert!(catalog_core.list_tools(&caller()).await.is_err());

    let logs = logs.text();
    assert!(logs.contains("capture-positive-control"), "{logs}");
    assert!(logs.contains("tool audit request refused"), "{logs}");
    assert!(logs.contains("tool audit response refused"), "{logs}");
    assert!(logs.contains("request_id"), "{logs}");
    assert!(logs.contains("reason"), "{logs}");
    assert!(logs.contains("provider-refused"), "{logs}");
    assert!(!logs.contains("downstream-refused"), "{logs}");
    assert!(
        logs.contains("provider catalog binding unavailable"),
        "{logs}"
    );
    assert!(logs.contains("provider-unavailable"), "{logs}");
    assert!(!logs.contains("catalog-backend-unavailable"), "{logs}");
    assert!(!logs.contains("catalog-trace-1"), "{logs}");
    for forbidden in ["staff-a", "chat-host", "inbound-secret-token"] {
        assert!(!logs.contains(forbidden), "{forbidden}: {logs}");
    }
}

#[tokio::test]
async fn unknown_effect_is_audited_unfinished_with_a_fixed_reason() {
    let provider = Arc::new(StubProvider {
        calls: AtomicUsize::new(0),
        outcome: Mutex::new(Some(ProviderOutcome::failure(ProviderFailure::new(
            "downstream-unavailable",
            "The downstream service is unavailable.",
            EffectCertainty::Unknown,
        )))),
    });
    let (audit, buffer) = audit();
    let core = core(provider, audit);

    let result = core.call(&caller(), "read_bounded", None).await;

    assert_eq!(result.is_error, Some(true));
    let entries = buffer.entries();
    assert_eq!(entries[1]["record"]["outcome"], "unfinished");
    assert_eq!(entries[1]["record"]["reason"], "downstream-unavailable");
}

#[tokio::test]
async fn malformed_failure_with_unknown_effect_remains_unfinished() {
    let provider = Arc::new(StubProvider {
        calls: AtomicUsize::new(0),
        outcome: Mutex::new(Some(ProviderOutcome::failure(ProviderFailure::new(
            "INVALID-CODE",
            "The downstream result is not known.",
            EffectCertainty::Unknown,
        )))),
    });
    let (audit, buffer) = audit();
    let core = core(provider, audit);

    let result = core.call(&caller(), "read_bounded", None).await;

    assert_eq!(result.is_error, Some(true));
    assert_eq!(
        result.structured_content.unwrap()["error"]["code"],
        "service-unavailable"
    );
    let entries = buffer.entries();
    assert_eq!(entries[1]["record"]["outcome"], "unfinished");
    assert_eq!(entries[1]["record"]["reason"], "effect-unknown");
}

#[tokio::test]
async fn catalog_is_validated_against_the_configured_tool_ceiling() {
    let provider = Arc::new(StubProvider::successful());
    let (audit, _) = audit();
    let core = core(Arc::clone(&provider), audit);

    let tools = core.list_tools(&caller()).await.expect("catalog");

    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "read_bounded");
    assert_eq!(provider.calls(), 1);
}

#[tokio::test]
async fn unavailable_catalog_bindings_do_not_hide_healthy_tools() {
    let unavailable = Arc::new(FailingCatalogProvider {
        failure: ProviderFailure::new(
            "catalog-backend-unavailable",
            "The provider catalog is unavailable.",
            EffectCertainty::NoEffect,
        ),
    });
    let unavailable_binding = ProviderBinding::new(
        unavailable,
        Arc::new(delegation()),
        ["unavailable_read".to_owned()],
    )
    .expect("unavailable binding");

    let unauthorized = Arc::new(StubProvider::successful());
    let unauthorized_binding = ProviderBinding::new(
        unauthorized.clone(),
        Arc::new(RefusingAuthorization),
        ["other_read".to_owned()],
    )
    .expect("unauthorized binding");

    let healthy = Arc::new(StubProvider::successful());
    let healthy_binding = ProviderBinding::new(
        healthy.clone(),
        Arc::new(delegation()),
        ["read_bounded".to_owned()],
    )
    .expect("healthy binding");
    let (audit, _) = audit();
    let core = gateway(
        [unavailable_binding, unauthorized_binding, healthy_binding],
        audit,
    );

    let tools = core.list_tools(&caller()).await.expect("healthy catalog");

    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "read_bounded");
    assert_eq!(unauthorized.calls(), 0);
    assert_eq!(healthy.calls(), 1);
}

#[tokio::test]
async fn total_catalog_failure_preserves_provider_code_and_trace() {
    let unavailable = Arc::new(FailingCatalogProvider {
        failure: ProviderFailure::new(
            "catalog-backend-unavailable",
            "The provider catalog is unavailable.",
            EffectCertainty::NoEffect,
        )
        .with_trace_id("catalog-trace-1"),
    });
    let binding = ProviderBinding::new(
        unavailable,
        Arc::new(delegation()),
        ["unavailable_read".to_owned()],
    )
    .expect("provider binding");
    let authorization_binding = ProviderBinding::new(
        Arc::new(StubProvider::successful()),
        Arc::new(RefusingAuthorization),
        ["other_read".to_owned()],
    )
    .expect("authorization binding");
    let (audit, _) = audit();
    let core = gateway([binding, authorization_binding], audit);

    let error = core.list_tools(&caller()).await.expect_err("catalog fails");

    assert!(matches!(error, CatalogError::Provider(_)));
    let value = error.to_value();
    assert_eq!(value["error"]["code"], "catalog-backend-unavailable");
    assert_eq!(value["error"]["traceId"], "catalog-trace-1");
}

#[tokio::test]
async fn misconfigured_catalog_authorization_is_a_hard_contract_error() {
    let misconfigured = ProviderBinding::new(
        Arc::new(StubProvider::successful()),
        Arc::new(MisconfiguredAuthorization),
        ["read_bounded".to_owned()],
    )
    .expect("provider binding");
    let healthy = ProviderBinding::new(
        Arc::new(StubProvider::successful()),
        Arc::new(delegation()),
        ["other_read".to_owned()],
    )
    .expect("healthy binding");
    let (audit, _) = audit();
    let core = gateway([misconfigured, healthy], audit);

    assert!(matches!(
        core.list_tools(&caller()).await,
        Err(CatalogError::Contract)
    ));
}

#[tokio::test]
async fn successful_empty_provider_catalog_is_not_an_outage() {
    let binding = ProviderBinding::new(
        Arc::new(EmptyCatalogProvider),
        Arc::new(delegation()),
        ["empty_read".to_owned()],
    )
    .expect("provider binding");
    let (audit, _) = audit();
    let core = gateway([binding], audit);

    let tools = core.list_tools(&caller()).await.expect("empty catalog");

    assert!(tools.is_empty());
}

#[tokio::test]
async fn invalid_provider_catalog_failure_is_a_hard_contract_error() {
    let healthy = Arc::new(StubProvider::successful());
    let healthy_binding =
        ProviderBinding::new(healthy, Arc::new(delegation()), ["read_bounded".to_owned()])
            .expect("healthy binding");
    let invalid = Arc::new(FailingCatalogProvider {
        failure: ProviderFailure::new(
            "INVALID-CODE",
            "The provider returned an invalid failure.",
            EffectCertainty::NoEffect,
        ),
    });
    let invalid_binding = ProviderBinding::new(
        invalid,
        Arc::new(delegation()),
        ["unavailable_read".to_owned()],
    )
    .expect("invalid binding");
    let (audit, _) = audit();
    let core = gateway([healthy_binding, invalid_binding], audit);

    assert_eq!(
        core.list_tools(&caller()).await,
        Err(CatalogError::Contract)
    );
}

#[test]
fn gateway_info_accepts_composed_maximum_unicode_service_text() {
    let service_text = "\u{10ffff}".repeat(4096);
    let instructions = format!(
        "{service_text}\n\n{service_text}\n\nThe citizen is always the signed-in user. Applications are submitted only on the review page."
    );

    GatewayInfo::new("breg-mcp", service_text, instructions)
        .expect("all valid composed BReg service text fits");
}

#[test]
fn gateway_info_instructions_retain_a_size_bound() {
    assert_eq!(
        GatewayInfo::new("test-mcp", "Test", "x".repeat(64 * 1024 + 1)),
        Err(crate::GatewayBuildError::Info)
    );
}

#[test]
fn verified_caller_exposes_identity_without_leaking_it_through_debug() {
    let caller = caller();
    let context: CallerContext<'_> = caller.context();
    assert_eq!(context.principal_pseudonym(), "principal-pseudonym");
    assert_eq!(context.client_pseudonym(), "client-pseudonym");
    let identity = caller.identity();
    assert_eq!(identity.issuer(), "https://issuer.example.test/");
    assert_eq!(identity.subject(), "staff-a");
    let debug = format!("{caller:?}");
    let identity_debug = format!("{identity:?}");
    assert!(!debug.contains("staff-a"));
    assert!(!debug.contains("chat-host"));
    assert!(!debug.contains("inbound-secret-token"));
    assert!(!identity_debug.contains("staff-a"));
    assert!(!identity_debug.contains("https://issuer.example.test/"));
}

#[test]
fn resource_server_options_can_be_validated_without_runtime_dependencies() {
    let mut options = ResourceServerOptions {
        resource: "https://gateway.example.test/mcp".to_owned(),
        issuer: "https://issuer.example.test/".to_owned(),
        allow_insecure_http: false,
        algorithms: vec![AccessTokenAlgorithm::EdDSA],
        allowed_clients: vec!["chat-host".to_owned()],
        required_scopes: vec!["casework:read".to_owned()],
        scope_claim: "scope".to_owned(),
        maximum_token_lifetime: Duration::from_secs(300),
        resource_name: "Staff gateway".to_owned(),
        principal_audit_namespace: "registry-mcp-principal-v1".to_owned(),
        client_audit_namespace: "registry-mcp-client-v1".to_owned(),
    };
    assert_eq!(options.validate(), Ok(()));

    options.resource = "https://gateway.example.test/not-mcp".to_owned();
    assert_eq!(options.validate(), Err(ResourceServerError::Resource));

    options.resource = "https://gateway.example.test/mcp".to_owned();
    options.issuer = "http://issuer.example.test/".to_owned();
    assert_eq!(options.validate(), Err(ResourceServerError::Issuer));
    options.allow_insecure_http = true;
    assert_eq!(options.validate(), Ok(()));

    options.resource = "http://gateway.example.test/mcp".to_owned();
    assert_eq!(options.validate(), Err(ResourceServerError::Resource));
}

#[test]
fn audit_profile_fixture_is_usable_by_the_edge() {
    let profile = AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
        b"test-audit-key-0123456789abcdef0123456789abcdef".to_vec(),
    ))
    .expect("audit profile");
    let hash = profile
        .key_hasher()
        .audit_reference_hash(
            "test-principal-v1",
            "",
            &json!(["issuer", "subject"]).to_string(),
        )
        .expect("pseudonym");
    assert!(!hash.contains("subject"));
}
