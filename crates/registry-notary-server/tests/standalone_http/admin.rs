// SPDX-License-Identifier: Apache-2.0

use super::support::*;
#[allow(unused_imports)]
use super::{
    audit::*, auth::*, credentials::*, federation::*, http_contracts::*, oid4vci::*, preauth::*,
    sources::*,
};

#[tokio::test]
pub(super) async fn admin_reload_401_unauth_403_wrong_scope_501_admin() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var(
        "TEST_EVIDENCE_WRONG_SCOPE_KEY_HASH",
        "sha256:ac3dced2bcf7d2cb4166747790d67437b5cc5314ed33e01d06b274a7fe0c3b3c",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "wrong-scope".to_string(),
        fingerprint: env_fingerprint_ref("TEST_EVIDENCE_WRONG_SCOPE_KEY_HASH"),
        scopes: vec!["farmer_registry:evidence_verification".to_string()],
        authorization_details: None,
    });
    add_admin_api_key(&mut config);
    enable_shared_admin_listener(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let unauthenticated = server.post("/admin/v1/reload").await;
    unauthenticated.assert_status(StatusCode::UNAUTHORIZED);

    let wrong_scope = server
        .post("/admin/v1/reload")
        .add_header("x-api-key", "wrong-scope-token")
        .await;
    wrong_scope.assert_status(StatusCode::FORBIDDEN);

    let admin = server
        .post("/admin/v1/reload")
        .add_header("x-api-key", "admin-token")
        .await;
    admin.assert_status(StatusCode::NOT_IMPLEMENTED);
    let admin_body: Value = admin.json();
    assert_eq!(admin_body["schema"], json!("registry.admin.error.v1"));
    assert_eq!(
        admin_body["code"],
        json!("registry.admin.capability.not_supported")
    );
    assert_eq!(admin_body["capability"], json!("reload.config_reload"));
}

#[test]
pub(super) fn admin_reload_openapi_says_runtime_config_reload_is_not_supported() {
    let document = serde_json::to_value(openapi_document()).expect("OpenAPI serializes");
    let operation = &document["paths"]["/admin/v1/reload"]["post"];
    let rendered = serde_json::to_string(operation).expect("operation serializes");

    assert!(rendered.contains("unsupported"));
    assert!(rendered.contains("does not support runtime configuration reload"));
    assert!(operation["responses"].get("501").is_some());
    assert!(operation["responses"].get("200").is_none());
    assert!(!rendered.contains("Request a standalone config reload"));

    let capabilities = &document["paths"]["/admin/v1/capabilities"]["get"];
    assert_eq!(
        capabilities["responses"]["403"]["description"],
        "Caller lacks registry_notary:ops_read scope"
    );

    assert!(
        document["paths"].get("/admin/v1/config/verify").is_none(),
        "admin config verify route is removed"
    );
    assert!(
        document["paths"].get("/admin/v1/config/dry-run").is_none(),
        "admin config dry-run route is removed"
    );
    assert!(
        document["paths"].get("/admin/v1/config/apply").is_none(),
        "admin config apply route is removed"
    );
}

#[tokio::test]
pub(super) async fn admin_posture_requires_ops_read_not_admin_and_ops_cannot_reload() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut config);
    add_admin_api_key(&mut config);
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    server
        .get("/admin/v1/posture")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "admin-token")
        .await
        .assert_status(StatusCode::FORBIDDEN);
    server
        .post("/admin/v1/reload")
        .add_header("x-api-key", "ops-token")
        .await
        .assert_status(StatusCode::FORBIDDEN);
    let unsupported_reload = server
        .post("/admin/v1/reload")
        .add_header("x-api-key", "admin-token")
        .await;
    unsupported_reload.assert_status(StatusCode::NOT_IMPLEMENTED);
    let unsupported_reload_body: Value = unsupported_reload.json();
    assert_eq!(
        unsupported_reload_body["code"],
        json!("registry.admin.capability.not_supported")
    );
    server
        .post("/admin/v1/credentials/urn:ulid:01HX0000000000000000000000/status")
        .add_header("x-api-key", "ops-token")
        .json(&json!({ "status": "revoked" }))
        .await
        .assert_status(StatusCode::FORBIDDEN);

    let posture = server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    posture.assert_status_ok();
    let body: Value = posture.json();
    assert_matches_posture_schema(&body);
    assert_eq!(body["schema"], json!("registry.ops.posture.v1"));
    assert_eq!(body["component"], json!("registry-notary"));
    assert_eq!(body["instance"]["id"], json!("registry-notary-standalone"));
    assert_eq!(body["instance"]["environment"], json!("development"));
    assert_eq!(body["build"]["package"], json!("registry-notary"));
    assert_eq!(body["build"]["version"], json!(env!("CARGO_PKG_VERSION")));
    assert!(body["build"].get("git_sha").is_none());
    assert!(body["build"].get("features").is_none());
}

#[tokio::test]
pub(super) async fn admin_capabilities_requires_ops_read_and_reports_notary_surface() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::SharedWithPublic;
    add_admin_api_key(&mut config);
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    server
        .get("/admin/v1/capabilities")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    server
        .get("/admin/v1/capabilities")
        .add_header("x-api-key", "admin-token")
        .await
        .assert_status(StatusCode::FORBIDDEN);

    let response = server
        .get("/admin/v1/capabilities")
        .add_header("x-api-key", "ops-token")
        .await;
    response.assert_status_ok();
    assert_eq!(
        response
            .header("cache-control")
            .to_str()
            .expect("cache-control is ASCII"),
        "no-store"
    );
    let body: Value = response.json();
    assert_matches_admin_capabilities_schema(&body);
    assert_eq!(body["schema"], json!("registry.admin.capabilities.v1"));
    assert_eq!(body["product"], json!("registry-notary"));
    assert_eq!(
        body["supported_posture_tiers"],
        json!(["default", "restricted"])
    );
    assert_eq!(body.get("scopes"), None);
    assert_eq!(
        body["config"]["verify"],
        json!({
            "supported": false,
            "currently_available": false
        })
    );
    assert_eq!(
        body["config"]["dry_run"],
        json!({
            "supported": false,
            "currently_available": false
        })
    );
    assert_eq!(
        body["config"]["apply"],
        json!({
            "supported": false,
            "currently_available": false,
            "requires_signed_input": true,
            "supported_sources": []
        })
    );
    assert_eq!(
        body["break_glass"],
        json!({
            "supported": false,
            "currently_available": false,
            "rate_limit_scope": "none"
        })
    );
    assert_eq!(
        body["listeners"],
        json!({
            "admin": {
                "mode": "shared_with_public",
                "public_admin_routes": true
            },
            "metrics": {
                "mode": "shared_with_public",
                "requires_admin_scope": false,
                "required_scope": "registry_notary:metrics_read"
            }
        })
    );
    assert!(!serde_json::to_string(&body["listeners"])
        .expect("listeners serialize")
        .contains("127.0.0.1"));
    assert_eq!(body["root_transition"]["supported"], json!(false));
    assert_eq!(
        body["hot_swap"],
        json!({
            "supported": false,
            "currently_available": false,
            "components": []
        })
    );
    assert_eq!(body["reload"]["resource_reload"]["supported"], json!(false));
    assert_eq!(body["reload"]["table_reload"]["supported"], json!(false));
    assert_eq!(body["reload"]["config_reload"]["supported"], json!(false));
}

#[tokio::test]
pub(super) async fn dedicated_topology_splits_admin_routes_and_reports_capabilities() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::Dedicated;
    add_ops_read_api_key(&mut config);

    let routers = notary_routers_from_runtime(
        compile_notary_runtime(config).expect("runtime compiles for dedicated topology"),
    )
    .expect("direct-source runtime is serve-ready");
    let public = TestServer::builder().http_transport().build(routers.public);
    let admin = TestServer::builder().http_transport().build(routers.admin);

    public.get("/healthz").await.assert_status_ok();
    public
        .get("/admin/v1/capabilities")
        .add_header("x-api-key", "ops-token")
        .await
        .assert_status(StatusCode::NOT_FOUND);
    public
        .get("/metrics")
        .add_header("x-api-key", "ops-token")
        .await
        .assert_status(StatusCode::NOT_FOUND);

    let response = admin
        .get("/admin/v1/capabilities")
        .add_header("x-api-key", "ops-token")
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_matches_admin_capabilities_schema(&body);
    assert_eq!(
        body["listeners"],
        json!({
            "admin": {
                "mode": "dedicated",
                "public_admin_routes": false
            },
            "metrics": {
                "mode": "admin",
                "requires_admin_scope": false,
                "required_scope": "registry_notary:metrics_read"
            }
        })
    );
    assert!(!serde_json::to_string(&body["listeners"])
        .expect("listeners serialize")
        .contains("127.0.0.1"));
}

#[tokio::test]
pub(super) async fn governed_config_rejects_shared_admin_listener_topology() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.config_trust = Some(ConfigTrustConfig {
        trust_anchor_path: tmp.path().join("config-anchor.json"),
        bundle_path: tmp.path().join("config-bundle"),
        antirollback_state_path: tmp.path().join("config-antirollback.json"),
        break_glass_override_path: None,
    });

    let error = match compile_notary_runtime(config) {
        Ok(_) => panic!("shared governed topology is rejected"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("server.admin_listener.mode = dedicated"),
        "unexpected error: {message}"
    );
}

#[test]
pub(super) fn governed_config_docs_do_not_ship_unresolved_config_trust_placeholders() {
    let doc = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/notary/docs/operator-config-reference.md"),
    )
    .expect("operator config reference reads");

    assert!(
        doc.contains("syntactically valid but illustrative"),
        "governed config example must be explicitly labeled as illustrative"
    );
    assert!(
        !doc.contains("REPLACE_WITH_FINAL"),
        "governed config example must not contain replacement placeholders"
    );
    assert!(
        !doc.contains("TUF_TARGETS_ROLE_KEY_ID"),
        "governed config example must not mention retired TUF key placeholders"
    );
}

#[tokio::test]
pub(super) async fn admin_posture_rejects_unknown_tier_with_shared_error_code() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut config);
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .get("/admin/v1/posture?tier=complete")
        .add_header("x-api-key", "ops-token")
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["schema"], json!("registry.admin.error.v1"));
    assert_eq!(body["code"], json!("registry.admin.posture.invalid_tier"));
    assert_eq!(
        body["detail"],
        json!("posture tier must be default or restricted")
    );
}

#[tokio::test]
pub(super) async fn admin_posture_reports_configured_instance_override() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut config);
    config.instance.id = "notary-prod-a".to_string();
    config.instance.environment = "production".to_string();
    config.instance.owner = Some("trust-ops".to_string());
    config.instance.jurisdiction = Some("TH".to_string());
    config.instance.public_base_url = Some("https://notary.example.test".to_string());
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let posture = server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    posture.assert_status_ok();
    let body: Value = posture.json();
    assert_matches_posture_schema(&body);
    assert_eq!(body["instance"]["id"], json!("notary-prod-a"));
    assert_eq!(body["instance"]["environment"], json!("production"));
    assert_eq!(body["instance"]["owner"], json!("trust-ops"));
    assert_eq!(body["instance"]["jurisdiction"], json!("TH"));
    assert!(body["instance"].get("public_base_url").is_none());
}

#[tokio::test]
pub(super) async fn admin_posture_top_level_keys_match_documented_example() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut config);
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let default_posture = server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    default_posture.assert_status_ok();
    let default_body: Value = default_posture.json();
    assert_matches_posture_schema(&default_body);

    let default_live_keys = default_body
        .as_object()
        .expect("posture is object")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let default_example: Value =
        serde_json::from_str(registry_platform_ops::NOTARY_POSTURE_EXAMPLE_V1)
            .expect("notary posture example parses");
    assert_standards_artifacts_omit_sha256(&default_body, "live default posture");
    assert_standards_artifacts_omit_sha256(&default_example, "NOTARY_POSTURE_EXAMPLE_V1");
    let default_example_keys = default_example
        .as_object()
        .expect("example posture is object")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        default_example_keys, default_live_keys,
        "NOTARY_POSTURE_EXAMPLE_V1 top-level keys drifted from the live default-tier posture document \
         (missing from example: {:?}, extra in example: {:?})",
        default_live_keys.difference(&default_example_keys).collect::<Vec<_>>(),
        default_example_keys.difference(&default_live_keys).collect::<Vec<_>>(),
    );

    let restricted_posture = server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("x-api-key", "ops-token")
        .await;
    restricted_posture.assert_status_ok();
    let restricted_body: Value = restricted_posture.json();
    assert_matches_posture_schema(&restricted_body);

    let restricted_live_keys = restricted_body
        .as_object()
        .expect("posture is object")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let restricted_fixture: Value =
        serde_json::from_str(registry_platform_ops::RESTRICTED_POSTURE_FIXTURE_V1)
            .expect("restricted posture fixture parses");
    let restricted_fixture_keys = restricted_fixture
        .as_object()
        .expect("restricted fixture posture is object")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        restricted_fixture_keys, restricted_live_keys,
        "RESTRICTED_POSTURE_FIXTURE_V1 top-level keys drifted from the live restricted-tier posture document \
         (missing from fixture: {:?}, extra in fixture: {:?})",
        restricted_live_keys.difference(&restricted_fixture_keys).collect::<Vec<_>>(),
        restricted_fixture_keys.difference(&restricted_live_keys).collect::<Vec<_>>(),
    );
}

#[tokio::test]
pub(super) async fn admin_posture_reports_self_attestation_summary_and_redacts_signing_key_ids() {
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let issuer = MockIdp::start().await;
    let issuer_url = issuer.issuer();
    let jwks_uri = issuer.jwks_uri();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &issuer_url,
        &jwks_uri,
    );
    enable_shared_admin_listener(&mut config);
    config
        .auth
        .oidc
        .as_mut()
        .expect("oidc config exists")
        .scope_map
        .insert(
            "ops_read".to_string(),
            vec!["registry_notary:ops_read".to_string()],
        );
    let ops_token = issuer.mint_token(json!({
        "sub": "trust-ops",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "ops_read",
    }));

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let posture = server
        .get("/admin/v1/posture")
        .add_header("authorization", format!("Bearer {ops_token}"))
        .await;
    posture.assert_status_ok();
    let body: Value = posture.json();
    assert_matches_posture_schema(&body);
    assert_eq!(body["notary"]["self_attestation"]["enabled"], json!(true));
    assert_eq!(
        body["notary"]["self_attestation"]["allowed_claim_count"],
        json!(1)
    );
    assert_eq!(
        body["notary"]["self_attestation"]["allowed_purpose_count"],
        json!(1)
    );
    assert_eq!(
        body["notary"]["self_attestation"]["credential_profile_count"],
        json!(1)
    );
    assert_eq!(
        body["notary"]["self_attestation"]["wallet_origin_count"],
        json!(1)
    );
    assert_eq!(
        body["notary"]["self_attestation"]["rate_limit_mode"],
        json!("in_process")
    );
    assert!(body["notary"].get("signing_keys").is_none());

    let rendered = serde_json::to_string(&body).expect("posture serializes");
    assert!(!rendered.contains("issuer-key"));
    assert!(!rendered.contains("did:web:issuer.example#key-1"));
}

#[tokio::test]
pub(super) async fn admin_posture_reports_oid4vci_bearer_offer_mode() {
    set_preauth_env();
    let issuer = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &issuer.issuer(),
        &issuer.jwks_uri(),
        &format!("{}/authorize", issuer.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    enable_shared_admin_listener(&mut config);
    config.oid4vci.pre_authorized_code.tx_code.required = false;
    config
        .oid4vci
        .pre_authorized_code
        .pre_authorized_code_ttl_seconds = 120;
    config
        .auth
        .oidc
        .as_mut()
        .expect("oidc config exists")
        .scope_map
        .insert(
            "ops_read".to_string(),
            vec!["registry_notary:ops_read".to_string()],
        );
    let ops_token = issuer.mint_token(json!({
        "sub": "trust-ops",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "ops_read",
    }));

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let posture = server
        .get("/admin/v1/posture")
        .add_header("authorization", format!("Bearer {ops_token}"))
        .await;
    posture.assert_status_ok();
    let body: Value = posture.json();
    assert_matches_posture_schema(&body);
    assert!(body["posture"]["warnings"]
        .as_array()
        .expect("warnings is an array")
        .iter()
        .any(|warning| warning == "notary.oid4vci.bearer_offer"));
    let finding = body["posture"]["findings"]
        .as_array()
        .expect("findings is an array")
        .iter()
        .find(|finding| finding["id"] == "notary.oid4vci.bearer_offer")
        .expect("bearer-offer finding is reported");
    assert!(finding["evidence"]
        .as_array()
        .expect("finding evidence is an array")
        .iter()
        .any(|entry| entry["value"] == json!("bearer_offer")));

    issuer.stop().await;
}

#[tokio::test]
pub(super) async fn admin_posture_redacts_runtime_config_secrets_and_private_topology() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "very-secret-source-token");
    std::env::set_var("TEST_UNUSED_SOURCE_TOKEN", "unused-secret-source-token");
    std::env::set_var("TEST_POSTURE_PRIVATE_JWK", TEST_ISSUER_JWK);

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1/private-source?token=source-url-secret",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut config);
    let mut unused_connection = config.evidence.source_connections["farmer_registry"].clone();
    unused_connection.base_url =
        "http://10.24.0.9/internal/source-adapter?token=unused-url-secret".to_string();
    unused_connection.token_env = "TEST_UNUSED_SOURCE_TOKEN".to_string();
    unused_connection.bulk_mode = BulkMode::SourceAdapterSidecarBatch;
    config.evidence.source_connections.insert(
        "private_unused_source_adapter".to_string(),
        unused_connection,
    );
    config.evidence.signing_keys.insert(
        "issuer".to_string(),
        SigningKeyConfig {
            provider: SigningKeyProviderConfig::LocalJwkEnv,
            alg: SD_JWT_VC_SIGNING_ALG.to_string(),
            kid: "did:web:evidence.example.test#issuer".to_string(),
            status: SigningKeyStatus::Active,
            publish_until_unix_seconds: None,
            private_jwk_env: "TEST_POSTURE_PRIVATE_JWK".to_string(),
            public_jwk_env: String::new(),
            module_path: String::new(),
            token_label: String::new(),
            pin_env: String::new(),
            key_label: String::new(),
            key_id_hex: String::new(),
            path: String::new(),
            password_env: String::new(),
        },
    );
    let claim = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "farmed-land-size")
        .expect("farmed-land-size claim exists");
    claim
        .source_bindings
        .get_mut("farmer")
        .expect("farmer source binding exists")
        .matching
        .policy_id = Some("civil-id-policy-1234567890123".to_string());
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let posture = server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    posture.assert_status_ok();
    let text = posture.text();

    assert!(!text.contains("very-secret-source-token"));
    assert!(!text.contains("unused-secret-source-token"));
    assert!(!text.contains("source-url-secret"));
    assert!(!text.contains("unused-url-secret"));
    assert!(!text.contains("http://127.0.0.1:1/private-source"));
    assert!(!text.contains("http://10.24.0.9/internal/source-adapter"));
    assert!(!text.contains("TEST_EVIDENCE_SOURCE_TOKEN"));
    assert!(!text.contains("TEST_UNUSED_SOURCE_TOKEN"));
    assert!(!text.contains("TEST_EVIDENCE_API_KEY_HASH"));
    assert!(!text.contains("TEST_POSTURE_PRIVATE_JWK"));
    assert!(
        !text.contains("sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51")
    );
    assert!(!text.contains("2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"));
    assert!(!text.contains("private_jwk"));
    assert!(!text.contains("\"d\""));
    assert!(!text.contains("token_env"));
    assert!(!text.contains("civil-id-policy-1234567890123"));
    assert!(!text.contains("disclosure"));
    assert!(!text.contains("predicate"));
    // The disclosure config must not leak. `audit.redaction_mode: "redacted"` is
    // a legitimate posture vocabulary value, so guard against the disclosure
    // list shape rather than the bare word.
    assert!(!text.contains("[value, redacted]"));
    assert!(!text.contains("\"value\",\"redacted\""));
}

#[tokio::test]
pub(super) async fn admin_posture_hash_ignores_secret_only_config_changes() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_ROTATED_SOURCE_TOKEN", "rotated-source-token");

    let tmp = TempDir::new().expect("tempdir");
    let first_audit_path = tmp.path().join("first-audit.jsonl");
    let second_audit_path = tmp.path().join("second-audit.jsonl");
    let mut first = registry_data_api_config(
        "http://127.0.0.1:1",
        first_audit_path.to_str().expect("audit path is UTF-8"),
    );
    let mut second = registry_data_api_config(
        "http://127.0.0.1:1",
        second_audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut first);
    enable_shared_admin_listener(&mut second);
    first
        .evidence
        .source_connections
        .get_mut("farmer_registry")
        .expect("farmer source connection exists")
        .token_env = "TEST_EVIDENCE_SOURCE_TOKEN".to_string();
    second
        .evidence
        .source_connections
        .get_mut("farmer_registry")
        .expect("farmer source connection exists")
        .token_env = "TEST_ROTATED_SOURCE_TOKEN".to_string();
    second
        .evidence
        .source_connections
        .get_mut("farmer_registry")
        .expect("farmer source connection exists")
        .base_url = "http://127.0.0.1:2/private-source".to_string();
    add_ops_read_api_key(&mut first);
    add_ops_read_api_key(&mut second);
    let first_internal_hash = internal_config_hash(
        serde_json::to_string(&first)
            .expect("config serializes")
            .as_bytes(),
    );

    let first_server = TestServer::builder()
        .http_transport()
        .build(standalone_router(first).expect("first router builds"));
    let second_server = TestServer::builder()
        .http_transport()
        .build(standalone_router(second).expect("second router builds"));

    let first_posture = first_server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    first_posture.assert_status_ok();
    let second_posture = second_server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    second_posture.assert_status_ok();
    let first_body: Value = first_posture.json();
    let second_body: Value = second_posture.json();
    assert_matches_posture_schema(&first_body);
    assert_matches_posture_schema(&second_body);

    assert_eq!(
        first_body["configuration"]["last_config_hash"],
        second_body["configuration"]["last_config_hash"]
    );
    assert_ne!(
        first_body["configuration"]["last_config_hash"],
        json!(first_internal_hash)
    );
}

#[tokio::test]
pub(super) async fn admin_posture_hash_tracks_public_instance_config_changes() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let first_audit_path = tmp.path().join("first-audit.jsonl");
    let second_audit_path = tmp.path().join("second-audit.jsonl");
    let mut first = registry_data_api_config(
        "http://127.0.0.1:1",
        first_audit_path.to_str().expect("audit path is UTF-8"),
    );
    let mut second = registry_data_api_config(
        "http://127.0.0.1:1",
        second_audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut first);
    enable_shared_admin_listener(&mut second);
    first.instance.owner = Some("operations".to_string());
    second.instance.owner = Some("data-office".to_string());
    first
        .evidence
        .source_connections
        .get_mut("farmer_registry")
        .expect("farmer source connection exists")
        .token_env = "TEST_EVIDENCE_SOURCE_TOKEN".to_string();
    second
        .evidence
        .source_connections
        .get_mut("farmer_registry")
        .expect("farmer source connection exists")
        .token_env = "TEST_EVIDENCE_SOURCE_TOKEN".to_string();
    add_ops_read_api_key(&mut first);
    add_ops_read_api_key(&mut second);

    let first_server = TestServer::builder()
        .http_transport()
        .build(standalone_router(first).expect("first router builds"));
    let second_server = TestServer::builder()
        .http_transport()
        .build(standalone_router(second).expect("second router builds"));

    let first_posture = first_server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    first_posture.assert_status_ok();
    let second_posture = second_server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    second_posture.assert_status_ok();
    let first_body: Value = first_posture.json();
    let second_body: Value = second_posture.json();

    assert_ne!(
        first_body["configuration"]["last_config_hash"],
        second_body["configuration"]["last_config_hash"]
    );
}

#[tokio::test]
pub(super) async fn admin_posture_counts_configured_but_unused_source_connections_by_safe_kind() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_UNUSED_DCI_SOURCE_TOKEN", "unused-dci-source-token");
    std::env::set_var(
        "TEST_UNUSED_GENERIC_SOURCE_TOKEN",
        "unused-generic-source-token",
    );

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut config);
    let mut unused_dci = config.evidence.source_connections["farmer_registry"].clone();
    unused_dci.base_url = "http://127.0.0.1:2/private-dci".to_string();
    unused_dci.token_env = "TEST_UNUSED_DCI_SOURCE_TOKEN".to_string();
    unused_dci.bulk_mode = BulkMode::DciBatchedSearch;
    config
        .evidence
        .source_connections
        .insert("unused_dci".to_string(), unused_dci);
    let mut unused_generic = config.evidence.source_connections["farmer_registry"].clone();
    unused_generic.base_url = "http://127.0.0.1:3/private-generic".to_string();
    unused_generic.token_env = "TEST_UNUSED_GENERIC_SOURCE_TOKEN".to_string();
    config
        .evidence
        .source_connections
        .insert("unused_generic".to_string(), unused_generic);
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let posture = server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    posture.assert_status_ok();
    let body: Value = posture.json();
    assert_matches_posture_schema(&body);
    assert_eq!(
        body["notary"]["source_connection_counts"]["registry_data_api"],
        json!(1)
    );
    assert_eq!(body["notary"]["source_connection_counts"]["dci"], json!(1));
    assert_eq!(
        body["notary"]["source_connection_counts"]["unknown"],
        json!(1)
    );
}

#[tokio::test]
pub(super) async fn admin_posture_classifies_replay_storage() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_REPLAY_REDIS_URL", "redis://127.0.0.1:6379/0");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut config);
    config.replay.storage = "redis".to_string();
    config.replay.redis.url_env = "TEST_REPLAY_REDIS_URL".to_string();
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let posture = server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    posture.assert_status_ok();
    let body: Value = posture.json();
    assert_matches_posture_schema(&body);
    assert_eq!(body["notary"]["replay"]["storage"], json!("redis"));
}

#[tokio::test]
pub(super) async fn admin_posture_warns_for_production_like_in_memory_replay() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut config);
    config.instance.environment = "production".to_string();
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let posture = server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    posture.assert_status_ok();
    let body: Value = posture.json();
    assert_matches_posture_schema(&body);
    assert_eq!(
        body["posture"]["warnings"][0],
        json!("notary.replay.in_memory.production")
    );
    assert_eq!(
        body["posture"]["findings"][0]["id"],
        json!("notary.replay.in_memory.production")
    );
    assert_eq!(body["runtime"]["readiness"], json!("degraded"));
}

#[tokio::test]
pub(super) async fn admin_posture_federation_summary_omits_peer_private_data() {
    set_federation_env();
    let peer_jwks = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = federation_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &format!("{}/jwks/private", peer_jwks.url()),
    );
    enable_shared_admin_listener(&mut config);
    add_ops_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let posture = server
        .get("/admin/v1/posture")
        .add_header("x-api-key", "ops-token")
        .await;
    posture.assert_status_ok();
    let body: Value = posture.json();
    assert_matches_posture_schema(&body);
    assert_eq!(body["notary"]["federation"]["enabled"], json!(true));
    assert!(body["notary"]["federation"].get("node_id").is_none());
    assert_eq!(body["notary"]["federation"]["peer_count"], json!(1));
    assert!(body["notary"]["federation"].get("peers").is_none());

    let text = serde_json::to_string(&body).expect("posture serializes");
    assert!(!text.contains("agency-b.example.gov"));
    assert!(!text.contains("/jwks/private"));
}

#[tokio::test]
pub(super) async fn metrics_requires_metrics_scope_and_keeps_health_public() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var(
        "TEST_EVIDENCE_ADMIN_KEY_HASH",
        "sha256:10a4c7c9fc5206d6f36dc6944a81bb6f4a3cb0e25014ae3b12e6c3e52712292a",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::SharedWithPublic;
    add_admin_api_key(&mut config);
    add_metrics_read_api_key(&mut config);

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let health = server.get("/healthz").await;
    health.assert_status_ok();

    let unauthenticated = server.get("/metrics").await;
    unauthenticated.assert_status(StatusCode::UNAUTHORIZED);
    assert!(!unauthenticated
        .text()
        .contains("registry_notary_http_requests_total"));

    let non_metrics = server
        .get("/metrics")
        .add_header("x-api-key", "api-token")
        .await;
    non_metrics.assert_status(StatusCode::FORBIDDEN);
    assert!(!non_metrics
        .text()
        .contains("registry_notary_http_requests_total"));

    let admin = server
        .get("/metrics")
        .add_header("x-api-key", "admin-token")
        .await;
    admin.assert_status(StatusCode::FORBIDDEN);
    assert!(!admin.text().contains("registry_notary_http_requests_total"));

    let metrics = server
        .get("/metrics")
        .add_header("x-api-key", "metrics-token")
        .await;
    metrics.assert_status_ok();
    let content_type = metrics
        .headers()
        .get("content-type")
        .expect("content-type header")
        .to_str()
        .expect("content-type is valid");
    assert!(content_type.starts_with("text/plain; version=0.0.4"));
    assert!(metrics
        .text()
        .contains("registry_notary_http_requests_total"));
}
