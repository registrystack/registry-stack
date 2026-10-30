// SPDX-License-Identifier: Apache-2.0
use registry_mcp::config::RuntimeConfig;
use serde_json::{json, Value};

fn citizen() -> Value {
    json!({
        "apiVersion":"id.registrystack.org/formats/platform/mcp-runtime/v1alpha1","kind":"PlatformMcpRuntimeConfig","name":"Synthetic citizen service",
        "listener":{"bind":"127.0.0.1:8110","tlsTermination":"development-loopback","networkExposure":"private-address"},
        "secretProviders":{"environment":{}},
        "resourceServer":{"resource":"http://127.0.0.1:8110/mcp","issuer":"http://127.0.0.1:8111/","jwksSource":{"type":"static","documentRef":"secret:env/MCP_TEST_JWKS"},"algorithms":["EdDSA"],"allowedClients":["chat-host"],"requiredScopes":["citizen:self"]},
        "audit":{"hashKeyRef":"secret:env/MCP_TEST_AUDIT_KEY","destination":"stdout"},
        "rateLimits":{"perPrincipal":{"requestsPerMinute":30,"burst":10},"perClient":{"requestsPerMinute":600,"burst":100}},
        "bindings":[{"name":"citizen","tools":["get_my_details"],"provider":{"type":"breg","registry":{"baseUrl":"http://127.0.0.1:8112/","accessProfile":"citizen-agent","audience":"urn:fixture:breg","scopes":["citizen:self"]},"exchange":{"tokenEndpoint":"http://127.0.0.1:8111/token","clientId":"citizen-gateway","privateKeyRef":"secret:env/MCP_TEST_PRIVATE_KEY"},"service":{"name":"Synthetic address correction","description":"Correct a synthetic record.","disclosure":"The assistant sees the values you authorize.","details":{"recordType":"person-address"},"application":{"action":"correct-address","targetInput":"address"},"reviewBaseUrl":"http://127.0.0.1:8113/"}}}]
    })
}
fn check(value: &Value) -> registry_platform_yaml::Report {
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .canonicalize()
        .unwrap()
        .join("runtime.json");
    std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    RuntimeConfig::check(&path, false)
}
#[test]
fn offline_check_uses_no_secret_values_and_accepts_a_configured_tool_subset() {
    let report = check(&citizen());
    assert!(!report.has_errors(), "{}", report.render_human());
}
#[test]
fn audience_reuse_exchange_client_reuse_and_invalid_review_origins_are_refused() {
    for (pointer, value) in [
        (
            "/bindings/0/provider/registry/audience",
            json!("http://127.0.0.1:8110/mcp"),
        ),
        ("/bindings/0/provider/exchange/clientId", json!("chat-host")),
        (
            "/bindings/0/provider/service/reviewBaseUrl",
            json!("https://review.example.invalid/nested"),
        ),
        (
            "/bindings/0/provider/service/reviewBaseUrl",
            json!("https://review.example.invalid/?private=value"),
        ),
    ] {
        let mut config = citizen();
        *config.pointer_mut(pointer).unwrap() = value;
        assert!(
            check(&config).has_errors(),
            "accepted forbidden configuration at {pointer}"
        );
    }
}
#[test]
fn casework_staff_activation_reports_the_actual_authority_dependency() {
    let mut config = citizen();
    config["bindings"][0]["tools"] = json!(["list_my_review_tasks"]);
    config["bindings"][0]["provider"] = json!({"type":"casework","baseUrl":"http://127.0.0.1:8120/","reviewProfile":"reviewer","sourceProfile":"reviewer-source","pageSize":20,"authorization":{"exchange":{"tokenEndpoint":"http://127.0.0.1:8111/token","clientId":"staff-gateway","privateKeyRef":"secret:env/MCP_TEST_PRIVATE_KEY"},"audience":"urn:fixture:casework","scopes":["casework:staff"]}});
    let report = check(&config);
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "casework.mcp.delegation-unsupported"),
        "{}",
        report.render_human()
    );
}
#[test]
fn duplicate_public_tool_names_and_unconfigured_native_operations_are_refused() {
    let mut config = citizen();
    let duplicate = config["bindings"][0].clone();
    config["bindings"].as_array_mut().unwrap().push(duplicate);
    assert!(check(&config).has_errors());
    let mut config = citizen();
    config["bindings"][0]["tools"] = json!(["submit_application"]);
    assert!(check(&config).has_errors());
}
