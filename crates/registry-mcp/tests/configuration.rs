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

fn assert_code_and_path(config: &Value, code: &str, path: &str) {
    let report = check(config);
    assert!(
        report
            .to_json_value()
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["code"] == code && finding["path"] == path),
        "expected {code} at {path}: {}",
        report.render_human()
    );
}

fn assert_diagnostic(config: &Value, code: &str, path: &str) {
    assert_code_and_path(config, &format!("platform.mcp-runtime.{code}"), path);
}
#[test]
fn offline_check_uses_no_secret_values_and_accepts_a_configured_tool_subset() {
    let report = check(&citizen());
    assert!(!report.has_errors(), "{}", report.render_human());
}
#[test]
fn audience_reuse_exchange_client_reuse_and_invalid_review_origins_are_refused() {
    for (pointer, value, code, path) in [
        (
            "/bindings/0/provider/registry/audience",
            json!("http://127.0.0.1:8110/mcp"),
            "downstream-audience-reused",
            "/bindings/0/provider/registry/audience",
        ),
        (
            "/bindings/0/provider/exchange/clientId",
            json!("chat-host"),
            "exchange-client-reused",
            "/bindings/0/provider/exchange/clientId",
        ),
        (
            "/bindings/0/provider/service/reviewBaseUrl",
            json!("https://review.example.invalid/nested"),
            "breg-review-origin-invalid",
            "/bindings/0/provider/service/reviewBaseUrl",
        ),
        (
            "/bindings/0/provider/service/reviewBaseUrl",
            json!("https://review.example.invalid/?private=value"),
            "breg-review-origin-invalid",
            "/bindings/0/provider/service/reviewBaseUrl",
        ),
    ] {
        let mut config = citizen();
        *config.pointer_mut(pointer).unwrap() = value;
        assert_diagnostic(&config, code, path);
    }
}

#[test]
fn breg_binding_refusals_name_the_exact_member() {
    for (pointer, value, code, path) in [
        (
            "/bindings/0/provider/exchange/tokenEndpoint",
            json!("http://exchange.example.test/token"),
            "exchange-url-invalid",
            "/bindings/0/provider/exchange/tokenEndpoint",
        ),
        (
            "/bindings/0/provider/exchange/privateKeyRef",
            json!("secret:file/mcp-key"),
            "exchange-secret-provider-undeclared",
            "/bindings/0/provider/exchange/privateKeyRef",
        ),
        (
            "/bindings/0/provider/registry/baseUrl",
            json!("http://registry.example.test/"),
            "provider-url-invalid",
            "/bindings/0/provider/registry/baseUrl",
        ),
        (
            "/bindings/0/tools",
            json!(["submit_application"]),
            "provider-tool-unsupported",
            "/bindings/0/tools/0",
        ),
    ] {
        let mut config = citizen();
        *config.pointer_mut(pointer).unwrap() = value;
        assert_diagnostic(&config, code, path);
    }

    let mut empty_scopes = citizen();
    empty_scopes["bindings"][0]["provider"]["registry"]["scopes"] = json!([]);
    assert_code_and_path(
        &empty_scopes,
        "config.invalid-length",
        "/bindings/0/provider/registry/scopes",
    );
}
fn staff() -> Value {
    let mut config = citizen();
    config["bindings"][0]["tools"] = json!(["list_my_review_tasks", "get_review_task_context"]);
    config["bindings"][0]["provider"] = json!({"type":"casework","authority":"delegated-staff-read","baseUrl":"http://127.0.0.1:8120/","readerPolicy":"assistant-reader","sourceProfile":"assistant-source","pageSize":20,"authorization":{"exchange":{"tokenEndpoint":"http://127.0.0.1:8111/token","clientId":"staff-gateway","privateKeyRef":"secret:env/MCP_TEST_PRIVATE_KEY"},"audience":"urn:fixture:casework","scopes":["casework:staff","casework:assistant-read"]}});
    config
}
#[test]
fn explicit_casework_delegated_read_configuration_passes_offline_without_credentials() {
    let report = check(&staff());
    assert!(!report.has_errors(), "{}", report.render_human());
}

#[test]
fn casework_binding_refusals_name_the_exact_member() {
    for (pointer, value, code, path) in [
        (
            "/bindings/0/provider/authorization/audience",
            json!("http://127.0.0.1:8110/mcp"),
            "downstream-audience-reused",
            "/bindings/0/provider/authorization/audience",
        ),
        (
            "/bindings/0/provider/authorization/exchange/clientId",
            json!("chat-host"),
            "exchange-client-reused",
            "/bindings/0/provider/authorization/exchange/clientId",
        ),
        (
            "/bindings/0/provider/authorization/exchange/tokenEndpoint",
            json!("http://exchange.example.test/token"),
            "exchange-url-invalid",
            "/bindings/0/provider/authorization/exchange/tokenEndpoint",
        ),
        (
            "/bindings/0/provider/authorization/exchange/privateKeyRef",
            json!("secret:file/mcp-key"),
            "exchange-secret-provider-undeclared",
            "/bindings/0/provider/authorization/exchange/privateKeyRef",
        ),
        (
            "/bindings/0/provider/baseUrl",
            json!("http://casework.example.test/"),
            "provider-url-invalid",
            "/bindings/0/provider/baseUrl",
        ),
        (
            "/bindings/0/provider/pageSize",
            json!(0),
            "casework-page-size-invalid",
            "/bindings/0/provider/pageSize",
        ),
        (
            "/bindings/0/provider/authorization/scopes",
            json!([]),
            "downstream-scopes-empty",
            "/bindings/0/provider/authorization/scopes",
        ),
        (
            "/bindings/0/tools",
            json!(["decide_review_task"]),
            "provider-tool-unsupported",
            "/bindings/0/tools/0",
        ),
    ] {
        let mut config = staff();
        *config.pointer_mut(pointer).unwrap() = value;
        assert_diagnostic(&config, code, path);
    }
}
#[test]
fn casework_requires_an_explicit_delegated_read_contract_and_refuses_human_modes() {
    let mut absent = staff();
    absent["bindings"][0]["provider"]
        .as_object_mut()
        .unwrap()
        .remove("authority");
    assert!(check(&absent).has_errors());
    for mode in ["human", "service", "delegated-staff-write"] {
        let mut config = staff();
        config["bindings"][0]["provider"]["authority"] = json!(mode);
        assert!(check(&config).has_errors(), "accepted {mode}");
    }
    for tool in [
        "decide_review_task",
        "claim_review_task",
        "assign_review_task",
    ] {
        let mut config = staff();
        config["bindings"][0]["tools"] = json!([tool]);
        assert!(check(&config).has_errors(), "accepted {tool}");
    }
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

#[test]
fn citizen_and_staff_bindings_cannot_share_one_inbound_resource() {
    let mut config = citizen();
    let mut binding = staff()["bindings"][0].clone();
    binding["name"] = json!("staff");
    config["bindings"].as_array_mut().unwrap().push(binding);
    let report = check(&config);
    assert!(
        report
            .to_json_value()
            .as_array()
            .unwrap()
            .iter()
            .any(
                |finding| finding["code"] == "platform.mcp-runtime.mixed-personas"
                    && finding["path"] == "/bindings"
            ),
        "{}",
        report.render_human()
    );
}

#[test]
fn submitted_staff_reads_can_omit_source_profile_and_use_the_default_page_size() {
    let mut config = staff();
    let provider = config["bindings"][0]["provider"].as_object_mut().unwrap();
    provider.remove("sourceProfile");
    provider.remove("pageSize");
    let report = check(&config);
    assert!(!report.has_errors(), "{}", report.render_human());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("runtime.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let parsed = RuntimeConfig::load(&path).unwrap();
    assert!(matches!(
        &parsed.bindings[0].provider,
        registry_mcp::config::ProviderConfig::Casework {
            page_size: 25,
            source_profile: None,
            ..
        }
    ));
}

#[test]
fn old_citizen_rate_bucket_names_the_replacement() {
    let mut config = citizen();
    let rates = config["rateLimits"].as_object_mut().unwrap();
    let bucket = rates.remove("perPrincipal").unwrap();
    rates.insert("perCitizen".into(), bucket);
    let report = check(&config);
    assert!(
        report
            .to_json_value()
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["code"] == "config.removed-key"
                && finding["path"] == "/rateLimits/perCitizen"),
        "{}",
        report.render_human()
    );
    assert!(report.render_human().contains("perPrincipal"));
}
