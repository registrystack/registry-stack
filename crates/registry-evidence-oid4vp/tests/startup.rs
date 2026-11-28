//! What the service refuses to start on, and what the offline file check
//! refuses, each with the shared diagnostic.

mod common;

use common::{Harness, Options};
use registry_evidence_oid4vp::config::{check_file, Oid4vpConfig};
use registry_platform_config::{DeclaredPosture, Posture, PostureSource};
use registry_platform_yaml::Severity;
const PRODUCTION: DeclaredPosture = DeclaredPosture {
    posture: Posture::Production,
    source: PostureSource::Default,
};

async fn startup_code(options: Options) -> String {
    let harness = Harness::new(&options).await;
    let error = harness
        .try_service()
        .await
        .expect_err("the service must refuse to start");
    let diagnostic = error.diagnostic();
    assert_eq!(diagnostic.severity, Severity::Error);
    assert!(!diagnostic.message.is_empty());
    assert!(!diagnostic.suggested_action.is_empty());
    assert!(diagnostic.path.starts_with("/clientIdentifier"));
    diagnostic.code.clone()
}

#[test]
fn openapi_write_failure_uses_the_operational_log() {
    let directory = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_evidence-oid4vp"))
        .args(["openapi", "--output"])
        .arg(directory.path())
        .env_remove("RUST_LOG")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let event: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(event["level"], "ERROR");
    assert_eq!(event["target"], "registry_evidence_oid4vp");
    assert!(output.stderr.is_empty());
}

#[tokio::test]
async fn a_certificate_that_does_not_name_the_public_host_is_refused() {
    let code = startup_code(Options {
        sans: vec!["other.example.net".to_owned()],
        ..Options::default()
    })
    .await;
    assert_eq!(code, "evidence.oid4vp.certificate-san-host");
}

#[tokio::test]
async fn the_hash_identifier_does_not_need_the_host_in_the_certificate() {
    let harness = Harness::new(&Options {
        client_identifier: "x509-hash",
        sans: vec!["other.example.net".to_owned()],
        ..Options::default()
    })
    .await;
    harness.try_service().await.expect("x509_hash starts");
}

#[tokio::test]
async fn a_signing_key_that_is_not_the_leaf_key_is_refused() {
    let code = startup_code(Options {
        mismatched_key: true,
        ..Options::default()
    })
    .await;
    assert_eq!(code, "evidence.oid4vp.signing-key-mismatch");
}

#[tokio::test]
async fn an_expired_request_signing_certificate_is_refused() {
    let code = startup_code(Options {
        not_before_year: 2019,
        not_after_year: 2021,
        ..Options::default()
    })
    .await;
    assert_eq!(code, "evidence.oid4vp.certificate-expired");
}

#[tokio::test]
async fn a_certificate_that_is_not_yet_valid_is_refused() {
    let code = startup_code(Options {
        not_before_year: 2080,
        not_after_year: 2090,
        ..Options::default()
    })
    .await;
    assert_eq!(code, "evidence.oid4vp.certificate-not-yet-valid");
}

#[tokio::test]
async fn a_missing_secret_is_refused_without_naming_its_contents() {
    let harness = Harness::new(&Options::default()).await;
    std::fs::remove_file(harness.dir.path().join("secrets/signing.jwk.json")).unwrap();
    let error = harness.try_service().await.expect_err("no signing key");
    assert_eq!(
        error.diagnostic().code,
        "evidence.oid4vp.secret-unavailable"
    );
    assert_eq!(
        error.diagnostic().path,
        "/clientIdentifiers/0/signingKeyRef"
    );
}

fn codes(harness: &Harness) -> Vec<String> {
    check_file(&harness.config_path, false, PRODUCTION)
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.clone())
        .collect()
}

fn edit(harness: &Harness, from: &str, to: &str) {
    let text = std::fs::read_to_string(&harness.config_path).unwrap();
    assert!(text.contains(from), "{from} is in the file");
    std::fs::write(&harness.config_path, text.replacen(from, to, 1)).unwrap();
}

#[tokio::test]
async fn posture_loopback_issuers_need_no_opt_in() {
    let harness = Harness::new(&Options::default()).await;
    assert_eq!(codes(&harness), Vec::<String>::new());
    let service = harness.service().await;
    let server = axum_test::TestServer::new(registry_evidence_oid4vp::service::build_app(service));
    let ready = server.get("/ready").await;
    ready.assert_status_ok();
    assert_eq!(
        ready.json::<serde_json::Value>(),
        serde_json::json!({
            "status": "ready", "posture": "production", "developmentSettings": []
        })
    );
    assert!(ready.maybe_header("registry-posture").is_none());
    let token = harness.applicant_token("portal", "user-1");
    server
        .post("/v1/sessions")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({"policy": "national-id"}))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    edit(
        &harness,
        "issuer: http://127.0.0.1:",
        "issuer: http://local.example.invalid:",
    );
    assert!(!codes(&harness).is_empty());
    assert!(Oid4vpConfig::load(&harness.config_path, PRODUCTION).is_err());
}

#[tokio::test]
async fn development_audit_records_the_declared_posture() {
    let harness = Harness::new(&Options::default()).await;
    edit(
        &harness,
        "applicantTokens:\n",
        "applicantTokens:\n  allowInsecureHttp: true\n",
    );
    let declared = DeclaredPosture {
        posture: Posture::Development,
        source: PostureSource::Flag,
    };
    let config = Oid4vpConfig::load(&harness.config_path, declared).unwrap();
    let service = registry_evidence_oid4vp::service::VerifierService::load_with_clock(
        config,
        harness.clock(),
    )
    .await
    .unwrap();
    let server = axum_test::TestServer::new(registry_evidence_oid4vp::service::build_app(
        std::sync::Arc::new(service),
    ));
    let token = harness.applicant_token("portal", "user-1");
    server
        .post("/v1/sessions")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({"policy": "national-id"}))
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    let audit = harness.audit_journal();
    let entry: serde_json::Value = serde_json::from_str(audit.lines().next().unwrap()).unwrap();
    assert_eq!(entry["posture"], "development");
}

#[tokio::test]
async fn posture_insecure_issuers_are_development_only() {
    let harness = Harness::new(&Options::default()).await;
    let text = std::fs::read_to_string(&harness.config_path).unwrap();
    let text = text
        .replacen("issuer: http://127.0.0.1", "issuer: http://10.0.0.5", 1)
        .replacen(
            "applicantTokens:\n",
            "applicantTokens:\n  allowInsecureHttp: true\n",
            1,
        );
    std::fs::write(&harness.config_path, text).unwrap();
    assert!(codes(&harness)
        .iter()
        .any(|code| code == "platform.posture.insecure-issuer-http"));
    assert!(Oid4vpConfig::load(&harness.config_path, PRODUCTION).is_err());
    let binary = env!("CARGO_BIN_EXE_evidence-oid4vp");
    let checked = std::process::Command::new(binary)
        .args([
            "check",
            "--posture",
            "development",
            "--deny-warnings",
            "--runtime-config",
        ])
        .arg(&harness.config_path)
        .env_remove("REGISTRY_STACK_POSTURE")
        .output()
        .unwrap();
    let warnings = String::from_utf8_lossy(&checked.stderr);
    assert!(checked.status.success(), "{warnings}");
    assert!(
        warnings.contains("platform.posture.insecure-issuer-http"),
        "{warnings}"
    );
    let development = DeclaredPosture {
        posture: Posture::Development,
        source: PostureSource::Flag,
    };
    let config = Oid4vpConfig::load(&harness.config_path, development)
        .expect("development accepts the setting");
    assert_eq!(
        config.posture.settings()[0].pointer.as_deref(),
        Some("/applicantTokens/allowInsecureHttp")
    );
    let service = registry_evidence_oid4vp::service::VerifierService::load_with_clock(
        config,
        harness.clock(),
    )
    .await
    .unwrap();
    let server = axum_test::TestServer::new(registry_evidence_oid4vp::service::build_app(
        std::sync::Arc::new(service),
    ));
    let ready = server.get("/ready").await;
    ready.assert_status_ok();
    ready.assert_header("registry-posture", "development");
    let ready = ready.json::<serde_json::Value>();
    assert_eq!(
        ready,
        serde_json::json!({
            "status": "ready",
            "posture": "development",
            "developmentSettings": [{
                "code": "platform.posture.insecure-issuer-http",
                "pointer": "/applicantTokens/allowInsecureHttp"
            }]
        })
    );
    // The service above holds the writer lock, so the second process logs
    // its posture and then exits without binding a listener.
    let startup = std::process::Command::new(binary)
        .args(["serve", "--posture", "development", "--runtime-config"])
        .arg(&harness.config_path)
        .env("RUST_LOG", "info")
        .env_remove("REGISTRY_STACK_POSTURE")
        .output()
        .unwrap();
    assert!(!startup.status.success());
    let listing = String::from_utf8_lossy(&startup.stdout);
    let logs: Vec<serde_json::Value> = listing
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    for setting in ready["developmentSettings"].as_array().unwrap() {
        assert!(
            logs.iter()
                .any(|entry| entry["fields"]["error_code"] == setting["code"]
                    && entry["fields"]["pointer"] == setting["pointer"]),
            "{listing}"
        );
    }
}

#[tokio::test]
async fn the_unedited_deployment_passes_the_offline_check() {
    let harness = Harness::new(&Options::default()).await;
    assert_eq!(codes(&harness), Vec::<String>::new());
    assert!(Oid4vpConfig::load(&harness.config_path, PRODUCTION).is_ok());
}

#[tokio::test]
async fn an_empty_policy_identifier_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(&harness, "- id: national-id", "- id: \"\"");
    let codes = codes(&harness);
    assert!(!codes.is_empty());
    assert!(Oid4vpConfig::load(&harness.config_path, PRODUCTION).is_err());
}

#[tokio::test]
async fn a_duplicate_policy_identifier_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(&harness, "- id: age-check", "- id: national-id");
    assert_eq!(codes(&harness), vec!["config.duplicate-id".to_owned()]);
}

#[tokio::test]
async fn a_file_without_policies_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    let text = std::fs::read_to_string(&harness.config_path).unwrap();
    let start = text.find("policies:").unwrap();
    let end = text.find("sessions:").unwrap();
    std::fs::write(
        &harness.config_path,
        format!("{}policies: []\n{}", &text[..start], &text[end..]),
    )
    .unwrap();
    assert_eq!(
        codes(&harness),
        vec!["evidence.oid4vp.no-policies".to_owned()]
    );
}

#[tokio::test]
async fn a_camel_case_client_identifier_tag_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(&harness, "type: x509-san-dns", "type: x509SanDns");
    assert!(!codes(&harness).is_empty());
}

#[tokio::test]
async fn a_public_base_url_with_a_path_or_plain_http_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(
        &harness,
        &format!("publicBaseUrl: https://{}", common::HOST),
        &format!("publicBaseUrl: https://{}/wallet", common::HOST),
    );
    assert_eq!(
        codes(&harness),
        vec!["evidence.oid4vp.public-base-path".to_owned()]
    );

    edit(
        &harness,
        "publicBaseUrl: https://",
        "publicBaseUrl: http://",
    );
    assert!(codes(&harness).contains(&"evidence.oid4vp.https-required".to_owned()));
}

fn with_metrics(harness: &Harness, metrics: &str, exposure: Option<&str>) {
    let exposure =
        exposure.map_or_else(String::new, |value| format!("  networkExposure: {value}\n"));
    edit(
        harness,
        "listener:\n  bind: 127.0.0.1:8095\n",
        &format!(
            "listener:\n  bind: 127.0.0.1:8095\nmetricsListener:\n  bind: \"{metrics}\"\n{exposure}"
        ),
    );
}

#[tokio::test]
async fn metrics_accept_loopback_and_private_addresses_and_refuse_link_local_and_mapped_forms() {
    for accepted in [
        "127.0.0.1:9095",
        "10.0.0.1:9095",
        "[::1]:9095",
        "[fd00::1]:9095",
    ] {
        let harness = Harness::new(&Options::default()).await;
        with_metrics(&harness, accepted, None);
        assert_eq!(codes(&harness), Vec::<String>::new(), "refused {accepted}");
    }
    for refused in [
        "169.254.1.1:9095",
        "[fe80::1]:9095",
        "[::ffff:127.0.0.1]:9095",
        "[::ffff:10.0.0.1]:9095",
        "8.8.8.8:9095",
        "0.0.0.0:9095",
        "[::]:9095",
    ] {
        let harness = Harness::new(&Options::default()).await;
        with_metrics(&harness, refused, None);
        assert_eq!(
            codes(&harness),
            vec!["evidence.oid4vp.metrics-address".to_owned()],
            "accepted {refused}"
        );
        assert!(Oid4vpConfig::load(&harness.config_path, PRODUCTION).is_err());
    }
}

/// Each metrics refusal carries its own remedy, and only the wildcard
/// refusal points at `container-private`.
#[tokio::test]
async fn a_metrics_refusal_names_its_cause_and_remedy() {
    for (bind, remedy, names_container_private) in [
        ("0.0.0.0:9095", "container-private", true),
        ("[::]:9095", "container-private", true),
        ("8.8.8.8:9095", "keep metrics off public addresses", false),
        ("169.254.1.1:9095", "link-local", false),
        ("127.0.0.1:8095", "its own port", false),
    ] {
        let harness = Harness::new(&Options::default()).await;
        with_metrics(&harness, bind, None);
        let diagnostics = check_file(&harness.config_path, false, PRODUCTION).diagnostics;
        let action = &diagnostics
            .first()
            .unwrap_or_else(|| panic!("{bind} should be refused"))
            .suggested_action;
        assert!(action.contains(remedy), "{bind}: {action}");
        assert_eq!(
            action.contains("container-private"),
            names_container_private,
            "{bind}: {action}"
        );
    }
}

#[tokio::test]
async fn the_metrics_wildcard_needs_container_private_exposure() {
    for wildcard in ["0.0.0.0:9095", "[::]:9095"] {
        let harness = Harness::new(&Options::default()).await;
        with_metrics(&harness, wildcard, Some("container-private"));
        assert_eq!(codes(&harness), Vec::<String>::new(), "refused {wildcard}");
        assert!(Oid4vpConfig::load(&harness.config_path, PRODUCTION).is_ok());
    }
    for (bind, code) in [
        ("169.254.1.1:9095", "evidence.oid4vp.metrics-address"),
        ("8.8.8.8:9095", "evidence.oid4vp.metrics-address"),
        ("[::ffff:10.0.0.1]:9095", "evidence.oid4vp.metrics-address"),
        ("0.0.0.0:0", "evidence.oid4vp.metrics-port"),
        ("0.0.0.0:8095", "evidence.oid4vp.metrics-shared-binding"),
    ] {
        let harness = Harness::new(&Options::default()).await;
        with_metrics(&harness, bind, Some("container-private"));
        assert_eq!(codes(&harness), vec![code.to_owned()], "accepted {bind}");
    }
}

#[tokio::test]
async fn serve_revalidates_the_metrics_listener_before_any_socket_is_bound() {
    use registry_evidence_oid4vp::config::MetricsListenerConfig;
    use registry_evidence_oid4vp::service::{serve, VerifierService};
    use registry_platform_config::ListenerNetworkExposure;

    for bind in ["0.0.0.0:9090", "127.0.0.1:8095"] {
        let harness = Harness::new(&Options::default()).await;
        let mut config = harness.config();
        config.listener.bind = "127.0.0.1:8095".parse().expect("a socket address");
        config.metrics_listener = Some(MetricsListenerConfig {
            bind: bind.parse().expect("a socket address"),
            network_exposure: ListenerNetworkExposure::PrivateAddress,
        });
        let service = std::sync::Arc::new(
            VerifierService::load_with_clock(config, harness.clock())
                .await
                .expect("the service starts"),
        );
        // A service that does not refuse binds and serves until shutdown, so
        // the wait is bounded.
        let served = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            serve(service, std::future::pending()),
        )
        .await
        .unwrap_or_else(|_| panic!("{bind}: serve bound its sockets instead of refusing"));
        let error = served.expect_err("a mutated unsafe metrics listener is refused");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{bind}");
    }
}

#[tokio::test]
async fn a_secret_reference_to_a_disabled_provider_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(
        &harness,
        "certificateChainRef: secret:file/chain.pem",
        "certificateChainRef: secret:env/CHAIN",
    );
    assert_eq!(
        codes(&harness),
        vec!["evidence.oid4vp.secret-provider-disabled".to_owned()]
    );
}

#[tokio::test]
async fn an_authority_key_identifier_that_is_not_base64url_is_refused() {
    let harness = Harness::new(&Options {
        trusted_authorities: true,
        ..Options::default()
    })
    .await;
    edit(
        &harness,
        "values: [c2lnbmluZy1rZXktaWRlbnRpZmllcg]",
        "values: [\"not base64!\"]",
    );
    assert!(
        codes(&harness).contains(&"evidence.oid4vp.invalid-authority-key-identifier".to_owned())
    );
}

#[tokio::test]
async fn session_lifetimes_and_limits_have_bounds() {
    let harness = Harness::new(&Options::default()).await;
    edit(&harness, "sessionTtlSeconds: 300", "sessionTtlSeconds: 5");
    assert!(!codes(&harness).is_empty());
    edit(&harness, "sessionTtlSeconds: 5", "sessionTtlSeconds: 300");
    edit(
        &harness,
        "maximumLiveSessions: 64",
        "maximumLiveSessions: 0",
    );
    assert!(!codes(&harness).is_empty());
}

#[tokio::test]
async fn an_empty_claim_path_segment_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(&harness, "- path: [given_name]", "- path: [\"\"]");
    assert!(!codes(&harness).is_empty());
    assert!(Oid4vpConfig::load(&harness.config_path, PRODUCTION).is_err());
}

#[tokio::test]
async fn a_claim_path_may_repeat_a_name() {
    let harness = Harness::new(&Options::default()).await;
    edit(
        &harness,
        "- path: [given_name]",
        "- path: [address, address]",
    );
    assert_eq!(codes(&harness), Vec::<String>::new());
}

#[tokio::test]
async fn response_and_read_rate_limits_have_bounds() {
    for member in [
        "walletResponsesPerMinute",
        "walletResponseBurst",
        "responsesPerRequestPerMinute",
        "responseBurstPerRequest",
        "evidenceReadsPerMinute",
        "evidenceReadBurst",
    ] {
        for bad in ["0", "99999999999", "-1", "\"fast\""] {
            let harness = Harness::new(&Options::default()).await;
            let text = std::fs::read_to_string(&harness.config_path).unwrap();
            let line = text
                .lines()
                .find(|line| line.trim_start().starts_with(&format!("{member}:")))
                .unwrap_or_else(|| panic!("{member} is in the deployment"))
                .to_owned();
            edit(&harness, &line, &format!("  {member}: {bad}"));
            assert!(!codes(&harness).is_empty(), "{member}: {bad}");
            assert!(
                Oid4vpConfig::load(&harness.config_path, PRODUCTION).is_err(),
                "{member}: {bad}"
            );
        }
    }
}

#[tokio::test]
async fn the_response_and_read_limits_default_when_omitted() {
    let harness = Harness::new(&Options::default()).await;
    let text = std::fs::read_to_string(&harness.config_path).unwrap();
    let kept: Vec<&str> = text
        .lines()
        .filter(|line| {
            ![
                "walletResponsesPerMinute",
                "walletResponseBurst",
                "responsesPerRequestPerMinute",
                "responseBurstPerRequest",
                "evidenceReadsPerMinute",
                "evidenceReadBurst",
            ]
            .iter()
            .any(|member| line.trim_start().starts_with(&format!("{member}:")))
        })
        .collect();
    std::fs::write(&harness.config_path, kept.join("\n")).unwrap();
    let config = Oid4vpConfig::load(&harness.config_path, PRODUCTION).expect("defaults apply");
    assert_eq!(config.rate_limits.wallet_responses_per_minute, 600);
    assert_eq!(config.rate_limits.responses_per_request_per_minute, 12);
    assert_eq!(config.rate_limits.evidence_read_burst, 100);
}

#[tokio::test]
async fn a_policy_naming_an_unknown_client_identifier_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(
        &harness,
        "clientIdentifier: haip",
        "clientIdentifier: missing",
    );
    assert_eq!(
        codes(&harness),
        vec!["evidence.oid4vp.unknown-client-identifier".to_owned()]
    );
    assert!(Oid4vpConfig::load(&harness.config_path, PRODUCTION).is_err());
}

#[tokio::test]
async fn a_client_identifier_no_policy_uses_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(
        &harness,
        "clientIdentifier: inji-registered",
        "clientIdentifier: inji-did",
    );
    assert_eq!(
        codes(&harness),
        vec!["evidence.oid4vp.unused-client-identifier".to_owned()]
    );
}

#[tokio::test]
async fn a_duplicate_client_identifier_id_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(&harness, "- id: inji-registered\n", "- id: inji-did\n");
    assert!(codes(&harness).contains(&"config.duplicate-id".to_owned()));
}

#[tokio::test]
async fn a_policy_must_name_its_client_identifier() {
    let harness = Harness::new(&Options::default()).await;
    edit(&harness, "    clientIdentifier: haip\n", "");
    assert!(!codes(&harness).is_empty());
    assert!(Oid4vpConfig::load(&harness.config_path, PRODUCTION).is_err());
}

#[tokio::test]
async fn a_did_web_identifier_must_name_the_public_host_alone() {
    for (did, code) in [
        ("did:web:other.example.net", "evidence.oid4vp.did-web-host"),
        (
            "did:web:verifier.example.org%3A8443",
            "evidence.oid4vp.did-web-port-or-path",
        ),
        (
            "did:web:verifier.example.org:users:verifier",
            "evidence.oid4vp.did-web-port-or-path",
        ),
        ("did:key:z6MkExample", "evidence.oid4vp.did-web-invalid"),
        ("did:web:", "evidence.oid4vp.did-web-invalid"),
    ] {
        let harness = Harness::new(&Options::default()).await;
        edit(
            &harness,
            "did: did:web:verifier.example.org",
            &format!("did: \"{did}\""),
        );
        assert_eq!(codes(&harness), vec![code.to_owned()], "{did}");
    }
}

#[tokio::test]
async fn a_did_web_identifier_is_refused_when_the_public_url_has_a_port() {
    let harness = Harness::new(&Options::default()).await;
    edit(
        &harness,
        "publicBaseUrl: https://verifier.example.org",
        "publicBaseUrl: https://verifier.example.org:8443",
    );
    assert_eq!(
        codes(&harness),
        vec!["evidence.oid4vp.did-web-public-port".to_owned()]
    );
}

#[tokio::test]
async fn a_pre_registered_client_id_with_a_colon_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(
        &harness,
        "clientId: evidence-verifier",
        "clientId: x509_san_dns:verifier.example.org",
    );
    assert_eq!(
        codes(&harness),
        vec!["evidence.oid4vp.pre-registered-client-id".to_owned()]
    );
}

#[tokio::test]
async fn a_signing_key_that_is_not_ed25519_is_refused_for_the_inji_identifiers() {
    for (secret, index) in [
        ("did-signing.jwk.json", 1),
        ("registered-signing.jwk.json", 2),
    ] {
        let harness = Harness::new(&Options::default()).await;
        std::fs::write(
            harness.dir.path().join("secrets").join(secret),
            &harness.keys.private_jwk,
        )
        .unwrap();
        let error = harness
            .try_service()
            .await
            .expect_err("a P-256 key cannot sign for Inji");
        assert_eq!(
            error.diagnostic().code,
            "evidence.oid4vp.signing-key-not-ed25519"
        );
        assert_eq!(
            error.diagnostic().path,
            format!("/clientIdentifiers/{index}/signingKeyRef")
        );
    }
}

#[tokio::test]
async fn two_identifiers_with_one_client_id_are_refused_at_startup() {
    let harness = Harness::new(&Options::default()).await;
    edit(
        &harness,
        "type: pre-registered\n    clientId: evidence-verifier",
        "type: decentralized-identifier\n    did: did:web:verifier.example.org",
    );
    assert_eq!(codes(&harness), Vec::<String>::new());
    let code = startup_code_for(&harness).await;
    assert_eq!(code, "evidence.oid4vp.duplicate-client-identifier");
}

async fn startup_code_for(harness: &Harness) -> String {
    harness
        .try_service()
        .await
        .expect_err("the service must refuse to start")
        .diagnostic()
        .code
        .clone()
}

const PUBLIC_KEY_WITH_EXT: &str = r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"issuer-key","ext":true,"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}"#;
const KEY_WITH_PRIVATE_MEMBER: &str = r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"issuer-key","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}"#;

#[tokio::test]
async fn a_static_key_set_with_an_ext_member_loads() {
    let harness = Harness::new(&Options {
        applicant_static_jwks: Some(PUBLIC_KEY_WITH_EXT),
        ..Options::default()
    })
    .await;
    harness
        .try_service()
        .await
        .expect("a public key with an ext member is a valid static key set");
}

#[tokio::test]
async fn a_static_key_set_with_a_private_member_is_refused_with_the_validator_text() {
    let harness = Harness::new(&Options {
        applicant_static_jwks: Some(KEY_WITH_PRIVATE_MEMBER),
        ..Options::default()
    })
    .await;
    let error = harness
        .try_service()
        .await
        .expect_err("a key set holding a private member is refused at startup");
    let diagnostic = error.diagnostic();
    assert_eq!(diagnostic.code, "evidence.oid4vp.issuer-unavailable");
    assert_eq!(diagnostic.path, "/applicantTokens");
    assert!(
        diagnostic.message.contains("private-key member \"d\""),
        "the startup message names the broken rule: {}",
        diagnostic.message
    );
    assert!(
        !diagnostic.message.contains("jpsQnnGQmL"),
        "the key material is never repeated"
    );
}
