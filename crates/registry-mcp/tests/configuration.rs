// SPDX-License-Identifier: Apache-2.0
use registry_mcp::config::RuntimeConfig;
use registry_platform_config::Posture;
use serde_json::{json, Value};

fn citizen() -> Value {
    json!({
        "apiVersion":"id.registrystack.org/formats/platform/mcp-runtime/v1alpha1","kind":"PlatformMcpRuntimeConfig","name":"Synthetic citizen service",
        "listener":{"bind":"127.0.0.1:8110","tlsTermination":"loopback-plaintext","networkExposure":"private-address"},
        "secretProviders":{"environment":{}},
        "resourceServer":{"resource":"https://citizen-assistant.example.invalid/mcp","issuer":"https://login.example.invalid/","jwksSource":{"type":"static","documentRef":"secret:env/MCP_TEST_JWKS"},"algorithms":["EdDSA"],"allowedClients":["chat-host"],"requiredScopes":["citizen:self"]},
        "audit":{"hashKeyRef":"secret:env/MCP_TEST_AUDIT_KEY","destination":"stdout"},
        "rateLimits":{"perPrincipal":{"requestsPerMinute":30,"burst":10},"perClient":{"requestsPerMinute":600,"burst":100}},
        "bindings":[{"name":"citizen","tools":["get_my_details"],"provider":{"type":"breg","registry":{"baseUrl":"http://127.0.0.1:8112/","accessProfile":"citizen-agent","audience":"urn:fixture:breg","scopes":["citizen:self"]},"exchange":{"tokenEndpoint":"https://login.example.invalid/token","clientId":"citizen-gateway","privateKeyRef":"secret:env/MCP_TEST_PRIVATE_KEY","assertionAudience":"https://login.example.invalid/"},"service":{"name":"Synthetic address correction","description":"Correct a synthetic record.","disclosure":"The assistant sees the values you authorize.","details":{"recordType":"person-address"},"application":{"action":"correct-address","targetInput":"address"},"reviewBaseUrl":"https://review.example.invalid/"}}}]
    })
}
fn check(value: &Value) -> registry_platform_yaml::Report {
    check_with_posture(value, Posture::Production)
}

fn check_with_posture(value: &Value, posture: Posture) -> registry_platform_yaml::Report {
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .canonicalize()
        .unwrap()
        .join("runtime.json");
    std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    RuntimeConfig::check_status_with_posture(
        &path,
        false,
        registry_platform_config::DeclaredPosture {
            posture,
            source: registry_platform_config::PostureSource::Flag,
        },
    )
    .0
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
            json!("https://citizen-assistant.example.invalid/mcp"),
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
    config["bindings"][0]["provider"] = json!({"type":"casework","authority":"delegated-staff-read","baseUrl":"http://127.0.0.1:8120/","readerPolicy":"assistant-reader","sourceProfile":"assistant-source","pageSize":20,"authorization":{"exchange":{"tokenEndpoint":"https://login.example.invalid/token","clientId":"staff-gateway","privateKeyRef":"secret:env/MCP_TEST_PRIVATE_KEY","assertionAudience":"https://login.example.invalid/"},"audience":"urn:fixture:casework","scopes":["casework:staff","casework:assistant-read"]}});
    config
}
#[test]
fn explicit_casework_delegated_read_configuration_passes_offline_without_credentials() {
    let report = check(&staff());
    assert!(!report.has_errors(), "{}", report.render_human());
}

#[test]
fn an_exchange_without_an_assertion_audience_is_refused_naming_the_member() {
    for (mut config, exchange) in [
        (citizen(), "/bindings/0/provider/exchange"),
        (staff(), "/bindings/0/provider/authorization/exchange"),
    ] {
        config
            .pointer_mut(exchange)
            .and_then(Value::as_object_mut)
            .unwrap()
            .remove("assertionAudience")
            .expect("the fixture states an assertion audience");
        let report = check(&config);
        assert!(
            report
                .to_json_value()
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| finding["code"] == "config.missing-key"
                    && finding["path"].as_str().unwrap_or("").starts_with(exchange)
                    && finding["message"]
                        .as_str()
                        .unwrap_or("")
                        .contains("assertionAudience")),
            "expected a missing assertionAudience at {exchange}: {}",
            report.render_human()
        );
    }
}

#[test]
fn casework_binding_refusals_name_the_exact_member() {
    for (pointer, value, code, path) in [
        (
            "/bindings/0/provider/authorization/audience",
            json!("https://citizen-assistant.example.invalid/mcp"),
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

#[test]
fn production_refuses_http_published_endpoints() {
    let mut config = citizen();
    config["bindings"][0]["provider"]["service"]["reviewBaseUrl"] = json!("http://127.0.0.1:8113/");
    config["resourceServer"]["issuer"] = json!("http://127.0.0.1:8111/");
    assert_code_and_path(
        &config,
        "breg.posture.review-http-public-origin",
        "/bindings/0/provider/service/reviewBaseUrl",
    );
    assert_code_and_path(
        &config,
        "platform.posture.mcp-http-published-issuer",
        "/resourceServer/issuer",
    );
}

#[test]
fn malformed_configuration_still_reports_http_resource() {
    let mut config = citizen();
    config["unknown"] = json!(true);
    config["resourceServer"]["resource"] = json!("http://127.0.0.1:8110/mcp");
    assert_code_and_path(
        &config,
        "platform.posture.mcp-http-resource",
        "/resourceServer/resource",
    );
}

#[test]
fn development_lists_http_published_endpoints() {
    let mut config = citizen();
    config["bindings"][0]["provider"]["service"]["reviewBaseUrl"] =
        json!("http://review.example.test/");
    config["resourceServer"]["issuer"] = json!("http://127.0.0.1:8111/");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("runtime.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let loaded = RuntimeConfig::load_with_posture(
        &path,
        registry_platform_config::DeclaredPosture {
            posture: registry_platform_config::Posture::Development,
            source: registry_platform_config::PostureSource::Flag,
        },
    )
    .unwrap();
    let ready = loaded.posture.ready_member();
    let settings = ready["developmentSettings"].as_array().unwrap();
    for (code, pointer) in [
        (
            "breg.posture.review-http-public-origin",
            "/bindings/0/provider/service/reviewBaseUrl",
        ),
        (
            "platform.posture.mcp-http-published-issuer",
            "/resourceServer/issuer",
        ),
    ] {
        assert!(settings
            .iter()
            .any(|setting| setting["code"] == code && setting["pointer"] == pointer));
    }
}

#[tokio::test]
async fn production_report_cannot_be_paired_with_a_development_witness() {
    use registry_platform_config::{DeclaredPosture, Posture, PostureReport, PostureSource};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("runtime.json");
    std::fs::write(&path, serde_json::to_vec(&citizen()).unwrap()).unwrap();
    let mut loaded = RuntimeConfig::load_with_posture(
        &path,
        DeclaredPosture {
            posture: Posture::Development,
            source: PostureSource::Flag,
        },
    )
    .unwrap();
    loaded.posture = PostureReport::new(DeclaredPosture {
        posture: Posture::Production,
        source: PostureSource::Flag,
    });
    let error = registry_mcp::runtime::build_with_posture(&loaded)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("the development witness does not match the declared posture"));
}

#[test]
fn published_endpoint_refusals_name_both_migrations() {
    let mut config = citizen();
    config["resourceServer"]["resource"] = json!("http://127.0.0.1:8110/mcp");
    config["resourceServer"]["issuer"] = json!("http://issuer.example.test");
    config["bindings"][0]["provider"]["service"]["reviewBaseUrl"] =
        json!("http://review.example.test/");
    let report = check(&config).to_json_value();
    for (code, subject, replacement) in [
        (
            "platform.posture.mcp-http-resource",
            "The protected resource identifier is plain http",
            "Use an https resource identifier.",
        ),
        (
            "platform.posture.mcp-http-published-issuer",
            "The published resource server issuer is plain http",
            "Use an https issuer.",
        ),
        (
            "breg.posture.review-http-public-origin",
            "The review base URL is plain http",
            "Use an https review base URL.",
        ),
    ] {
        let diagnostic = report
            .as_array()
            .unwrap()
            .iter()
            .find(|diagnostic| diagnostic["code"] == code)
            .unwrap();
        assert_eq!(
            diagnostic["message"],
            format!("{subject}; it is accepted only when the process declares development")
        );
        assert_eq!(diagnostic["suggestedAction"], format!("{replacement} For a laptop or test run, start it with `rstack dev`, or declare development with REGISTRY_STACK_POSTURE=development or --posture development."));
    }
    // Production refuses the http issuer by its posture code alone.
    assert!(!report
        .as_array()
        .unwrap()
        .iter()
        .any(|diagnostic| diagnostic["code"] == "platform.mcp-runtime.insecure-resource-server"));
}

#[test]
fn an_http_issuer_beyond_loopback_names_its_one_remedy() {
    let mut config = citizen();
    config["resourceServer"]["issuer"] = json!("http://issuer.example.test");
    let report = check_with_posture(&config, Posture::Development).to_json_value();
    let diagnostic = report
        .as_array()
        .unwrap()
        .iter()
        .find(|diagnostic| diagnostic["code"] == "platform.mcp-runtime.insecure-resource-server")
        .unwrap_or_else(|| panic!("{report}"));
    assert_eq!(diagnostic["path"], "/resourceServer/issuer");
    assert_eq!(
        diagnostic["message"],
        "The issuer uses plain http beyond loopback without allowInsecureHttp."
    );
    assert_eq!(diagnostic["suggestedAction"], "Write an https issuer URL. For plain http, start with `rstack dev` or declare development with REGISTRY_STACK_POSTURE=development or --posture development; beyond loopback, also set resourceServer.allowInsecureHttp: true.");
}

#[test]
fn malformed_configuration_still_reports_http_issuer_and_review_origin() {
    let mut config = citizen();
    config["unknown"] = json!(true);
    config["resourceServer"]["issuer"] = json!("http://127.0.0.1:8111/");
    config["bindings"][0]["provider"]["service"]["reviewBaseUrl"] = json!("http://127.0.0.1:8113/");
    assert_code_and_path(
        &config,
        "platform.posture.mcp-http-published-issuer",
        "/resourceServer/issuer",
    );
    assert_code_and_path(
        &config,
        "breg.posture.review-http-public-origin",
        "/bindings/0/provider/service/reviewBaseUrl",
    );
}

/// `citizen()` with file secrets a build can resolve: the static key set, the
/// audit hash key and the exchange key.
fn citizen_with_file_secrets(root: &std::path::Path) -> Value {
    use std::os::unix::fs::PermissionsExt;
    let secrets = root.join("secrets");
    std::fs::create_dir(&secrets).unwrap();
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = registry_platform_crypto::generate_private_jwk(
        registry_platform_crypto::GeneratedKeyAlgorithm::Es256,
    )
    .unwrap();
    let private_key = json!({
        "kty": key.kty, "kid": key.kid, "alg": key.alg, "crv": key.crv,
        "x": key.x, "y": key.y, "d": key.d,
    });
    for (name, bytes) in [
        (
            "jwks",
            serde_json::to_vec(&registry_platform_testing::jwks_from_private_jwk(&key)).unwrap(),
        ),
        ("audit-key", vec![7; 32]),
        ("private-key", serde_json::to_vec(&private_key).unwrap()),
    ] {
        let path = secrets.join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut config = citizen();
    config["secretProviders"] = json!({"file":{"root":secrets}});
    config["resourceServer"]["jwksSource"]["documentRef"] = json!("secret:file/jwks");
    config["resourceServer"]["algorithms"] = json!(["ES256"]);
    config["audit"]["hashKeyRef"] = json!("secret:file/audit-key");
    config["bindings"][0]["provider"]["exchange"]["privateKeyRef"] =
        json!("secret:file/private-key");
    config
}

fn declared(posture: Posture) -> registry_platform_config::DeclaredPosture {
    registry_platform_config::DeclaredPosture {
        posture,
        source: registry_platform_config::PostureSource::Flag,
    }
}

/// Every gated member is recorded while the file decodes, at the pointer
/// `development_settings` names, so the runtime's own list and the loader's
/// report cannot drift apart.
#[test]
fn development_settings_list_what_the_decoder_records() {
    let mut config = citizen();
    config["resourceServer"]["resource"] = json!("http://127.0.0.1:8110/mcp");
    config["resourceServer"]["issuer"] = json!("http://login.example.invalid/");
    config["resourceServer"]["allowInsecureHttp"] = json!(true);
    config["resourceServer"]["jwksSource"] =
        json!({"type":"test-issuer","documentRef":"secret:env/MCP_TEST_JWKS"});
    config["audit"]["hashKeyCustody"] = json!("development-generated");
    config["bindings"][0]["provider"]["service"]["reviewBaseUrl"] =
        json!("http://review.example.invalid/");
    let loaded = RuntimeConfig::loader(declared(Posture::Development))
        .parse_str::<RuntimeConfig>(&config.to_string(), |_| None)
        .unwrap();
    let pairs = |settings: &[registry_platform_config::FoundSetting]| {
        let mut pairs: Vec<(&str, Option<String>)> = settings
            .iter()
            .map(|found| (found.setting.code, found.pointer.clone()))
            .collect();
        pairs.sort();
        pairs
    };
    let listed = loaded.config.development_settings();
    assert_eq!(listed.len(), 6, "{:?}", pairs(&listed));
    assert_eq!(pairs(&listed), pairs(loaded.posture.settings()));
}

#[tokio::test]
async fn production_refuses_a_development_loaded_audit_key_custody() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let mut config = citizen_with_file_secrets(&root);
    config["audit"]["hashKeyCustody"] = json!("development-generated");
    let path = root.join("runtime.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let mut loaded =
        RuntimeConfig::load_with_posture(&path, declared(Posture::Development)).unwrap();
    loaded.posture = registry_platform_config::PostureReport::new(declared(Posture::Production));
    loaded.development = None;
    let error = registry_mcp::runtime::build_with_posture(&loaded)
        .await
        .expect_err("production refuses a development-generated audit key");
    let text = error.to_string();
    assert!(
        text.contains("production refuses development settings")
            && text.contains("platform.posture.generated-audit-key at /audit/hashKeyCustody")
            && text.contains("rstack dev"),
        "{text}"
    );
}
