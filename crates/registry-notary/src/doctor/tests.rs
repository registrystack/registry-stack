// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_support::*;

#[test]
fn doctor_cli_defaults_to_text_format() {
    let args = Args::try_parse_from(["registry-notary", "doctor"]).expect("args parse");
    let Some(Command::Doctor { format, .. }) = args.command else {
        panic!("expected doctor command");
    };

    assert_eq!(format, DoctorOutputFormat::Text);
}

#[test]
fn doctor_cli_accepts_json_format() {
    let args = Args::try_parse_from(["registry-notary", "doctor", "--format", "json"])
        .expect("args parse");
    let Some(Command::Doctor { format, .. }) = args.command else {
        panic!("expected doctor command");
    };

    assert_eq!(format, DoctorOutputFormat::Json);
}

#[test]
fn doctor_cli_accepts_profile_override() {
    let args = Args::try_parse_from(["registry-notary", "doctor", "--profile", "production"])
        .expect("args parse");
    let Some(Command::Doctor { profile, .. }) = args.command else {
        panic!("expected doctor command");
    };

    assert_eq!(profile.as_deref(), Some("production"));
}

#[test]
fn doctor_cli_rejects_unknown_format() {
    let err = Args::try_parse_from(["registry-notary", "doctor", "--format", "pretty"])
        .expect_err("unknown doctor format is rejected");

    assert!(err.to_string().contains("text"));
    assert!(err.to_string().contains("json"));
}

#[test]
fn redaction_covers_pin_key_and_credential_names() {
    let mut value = json!({
        "pin": "1234",
        "password_env": "PKCS12_PASSWORD_ENV_NAME",
        "key": "plain-key",
        "credential": "raw-credential",
        "credential_env": "SOURCE_CREDENTIAL",
        "api_keys": [{
            "id": "api-key-id",
            "scopes": ["claims:read"]
        }],
        "signing_keys": {
            "active": {
                "status": "active",
                "public_key_id": "public-key-id"
            }
        },
        "nested": {
            "public_key": "public-material",
            "source_credential": "source-secret",
            "safe": "visible"
        }
    });

    redact_value(&mut value);

    assert_eq!(value["pin"], json!("[redacted]"));
    assert_eq!(value["password_env"], json!("[redacted]"));
    assert_eq!(value["key"], json!("[redacted]"));
    assert_eq!(value["credential"], json!("[redacted]"));
    assert_eq!(value["credential_env"], json!("[redacted]"));
    assert_eq!(value["nested"]["public_key"], json!("[redacted]"));
    assert_eq!(value["nested"]["source_credential"], json!("[redacted]"));
    assert_eq!(value["nested"]["safe"], json!("visible"));
    assert_eq!(value["api_keys"][0]["id"], json!("api-key-id"));
    assert_eq!(value["api_keys"][0]["scopes"][0], json!("claims:read"));
    assert_eq!(value["signing_keys"]["active"]["status"], json!("active"));
    assert_eq!(
        value["signing_keys"]["active"]["public_key_id"],
        json!("[redacted]")
    );
}

#[test]
fn local_file_audit_sink_emits_beta_tamper_evidence_warning() {
    let mut config = doctor_live_test_config("http://127.0.0.1:1");
    config.audit.sink = "jsonl".to_string();

    let diagnostics = local_env_diagnostics(&config, &EnvFileReport::default());

    let warning = diagnostics
        .iter()
        .find(|diagnostic| diagnostic.label.contains("local-chain-only"))
        .expect("audit file warning exists");
    assert!(warning.ok);
    assert!(warning.warning);
    assert!(warning
        .action
        .as_deref()
        .expect("warning has next action")
        .contains("off-host"));
}

#[test]
fn attested_local_file_audit_sink_suppresses_beta_tamper_evidence_warning() {
    let mut config = doctor_live_test_config("http://127.0.0.1:1");
    config.audit.sink = "jsonl".to_string();
    config.deployment.evidence.audit_offhost_shipping = true;

    let diagnostics = local_env_diagnostics(&config, &EnvFileReport::default());

    assert!(
        !diagnostics
            .iter()
            .any(|diagnostic| diagnostic.label.contains("local-chain-only")),
        "declaring off-host shipping must silence the local-chain-only warning"
    );
}

fn doctor_relay_config(token_file: PathBuf) -> StandaloneRegistryNotaryConfig {
    let mut config = doctor_live_test_config("http://127.0.0.1:1");
    config.evidence.claims[0].evidence_mode =
        registry_notary_core::ClaimEvidenceMode::RegistryBacked {
            consultations: std::collections::BTreeMap::new(),
        };
    config.evidence.relay = Some(registry_notary_core::RelayConnectionConfig {
        base_url: "http://127.0.0.1:1".to_string(),
        token_file,
        allowed_private_cidrs: Vec::new(),
        allow_insecure_localhost: true,
    });
    config
}

#[test]
fn relay_token_file_diagnostic_is_safe_and_requires_non_empty_regular_file() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let token_file = tmp.path().join("do-not-report-this-token-path.jwt");
    let config = doctor_relay_config(token_file.clone());

    let missing = relay_token_file_diagnostic(&config);
    assert!(!missing.ok);
    assert_eq!(
        missing.report_code.as_deref(),
        Some("notary.relay.credential_unavailable")
    );
    let missing_text = format!(
        "{} {}",
        missing.label,
        missing.action.as_deref().unwrap_or_default()
    );
    assert!(!missing_text.contains("do-not-report-this-token-path"));

    std::fs::write(&token_file, "").expect("empty token file writes");
    assert!(!relay_token_file_diagnostic(&config).ok);

    std::fs::write(&token_file, "header.payload.signature").expect("token file writes");
    let permissive = relay_token_file_diagnostic(&config);
    assert!(permissive.ok);
    #[cfg(unix)]
    {
        assert!(permissive.warning);
        assert_eq!(
            permissive.report_code.as_deref(),
            Some("notary.relay.credential_permissions")
        );
        std::fs::set_permissions(
            &token_file,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .expect("token permissions are restricted");
        let private = relay_token_file_diagnostic(&config);
        assert!(private.ok);
        assert!(!private.warning);
    }
}

#[test]
fn relay_live_failures_have_stable_safe_categories() {
    let cases = [
        (
            StandaloneServerError::RelayCredentialUnavailable,
            "notary.relay.credential_unavailable",
        ),
        (
            StandaloneServerError::RelayCredentialsRejected,
            "notary.relay.credentials_rejected",
        ),
        (
            StandaloneServerError::RelayProfileNotFound,
            "notary.relay.profile_not_found",
        ),
        (
            StandaloneServerError::RelayProfileMismatch,
            "notary.relay.profile_mismatch",
        ),
        (
            StandaloneServerError::RelayUnavailable,
            "notary.relay.unavailable",
        ),
        (
            StandaloneServerError::InvalidRelayActivationPlan,
            "notary.relay.configuration_invalid",
        ),
    ];

    for (error, expected_code) in cases {
        let diagnostic = relay_live_failure_diagnostic(&error);
        assert!(!diagnostic.ok);
        assert_eq!(diagnostic.report_code.as_deref(), Some(expected_code));
        assert_eq!(diagnostic.report_severity, Some("error"));
    }
}

#[test]
fn notary_audit_shipping_reports_stdout_sink_as_shipped() {
    let mut config = doctor_live_test_config("http://127.0.0.1:1");
    config.audit.sink = "stdout".to_string();

    let shipping = notary_audit_shipping(&config);

    assert_eq!(shipping["sink_type"], "stdout");
    assert_eq!(shipping["shipping_target_configured"], true);
    assert_eq!(shipping["shipping_target"], "stdout");
    // A shipping target is declared but no ack cursor is configured.
    assert_eq!(shipping["shipping_health"], "unverified");
    assert_eq!(shipping["shipping_observed_at"], Value::Null);
}

#[test]
fn notary_audit_shipping_reports_local_file_sink_without_attestation_as_unshipped() {
    let mut config = doctor_live_test_config("http://127.0.0.1:1");
    config.audit.sink = "jsonl".to_string();
    config.deployment.evidence.audit_offhost_shipping = false;

    let shipping = notary_audit_shipping(&config);

    assert_eq!(shipping["sink_type"], "file");
    assert_eq!(shipping["shipping_target_configured"], false);
    assert_eq!(shipping["shipping_target"], "none");
    // No shipping target is configured, so health is null.
    assert_eq!(shipping["shipping_health"], Value::Null);
    assert_eq!(shipping["shipping_observed_at"], Value::Null);
}

#[test]
fn notary_audit_shipping_reports_attested_local_file_sink_as_declared_external() {
    let mut config = doctor_live_test_config("http://127.0.0.1:1");
    config.audit.sink = "file".to_string();
    config.deployment.evidence.audit_offhost_shipping = true;

    let shipping = notary_audit_shipping(&config);

    assert_eq!(shipping["sink_type"], "file");
    assert_eq!(shipping["shipping_target_configured"], true);
    assert_eq!(shipping["shipping_target"], "declared_external");
    // declared_external with no ack cursor: shipping is declared but unobserved.
    assert_eq!(shipping["shipping_health"], "unverified");
    assert_eq!(shipping["shipping_observed_at"], Value::Null);
}

#[test]
fn notary_audit_shipping_maps_unrecognized_sink_to_unknown() {
    let mut config = doctor_live_test_config("http://127.0.0.1:1");
    config.audit.sink = "s3".to_string();

    let shipping = notary_audit_shipping(&config);

    assert_eq!(shipping["sink_type"], "unknown");
    assert_eq!(shipping["shipping_target_configured"], false);
    assert_eq!(shipping["shipping_target"], "unknown");
    assert_eq!(shipping["shipping_health"], Value::Null);
    assert_eq!(shipping["shipping_observed_at"], Value::Null);
}

/// Write a `registry.audit.ack_cursor.v1` cursor with `acked_at` and return
/// its path, so doctor shipping-health tests can drive each observation.
fn write_doctor_ack_cursor(tmp: &tempfile::TempDir, acked_at: &str) -> std::path::PathBuf {
    let path = tmp.path().join("ack-cursor.json");
    let body = format!(
        r#"{{"schema":"registry.audit.ack_cursor.v1","acked_at":"{acked_at}","last_acked_hash":"sha256:4444444444444444444444444444444444444444444444444444444444444444","writer":"test-shipper"}}"#
    );
    std::fs::write(&path, body).expect("ack cursor writes");
    path
}

#[test]
fn notary_audit_shipping_reports_unverified_for_fresh_offline_cursor() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let acked_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("now formats");
    let cursor = write_doctor_ack_cursor(&tmp, &acked_at);
    let mut config = doctor_live_test_config("http://127.0.0.1:1");
    config.audit.sink = "stdout".to_string();
    config.deployment.evidence.audit_ack_cursor_path = Some(cursor);

    let shipping = notary_audit_shipping(&config);

    assert_eq!(shipping["shipping_health"], "unverified");
    assert_eq!(shipping["shipping_observed_at"], acked_at);
}

#[test]
fn notary_audit_shipping_reports_stale_for_old_cursor() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    // Far past the default 900s window relative to any plausible test clock.
    let cursor = write_doctor_ack_cursor(&tmp, "2026-06-04T09:59:00Z");
    let mut config = doctor_live_test_config("http://127.0.0.1:1");
    config.audit.sink = "stdout".to_string();
    config.deployment.evidence.audit_ack_cursor_path = Some(cursor);

    let shipping = notary_audit_shipping(&config);

    assert_eq!(shipping["shipping_health"], "stale");
    assert_eq!(shipping["shipping_observed_at"], "2026-06-04T09:59:00Z");
}

#[test]
fn notary_audit_shipping_reports_missing_for_absent_cursor_file() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cursor = tmp.path().join("does-not-exist.json");
    let mut config = doctor_live_test_config("http://127.0.0.1:1");
    config.audit.sink = "stdout".to_string();
    config.deployment.evidence.audit_ack_cursor_path = Some(cursor);

    let shipping = notary_audit_shipping(&config);

    assert_eq!(shipping["shipping_health"], "missing");
    assert_eq!(shipping["shipping_observed_at"], Value::Null);
}

#[test]
fn notary_audit_shipping_reports_invalid_for_malformed_cursor_file() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cursor = tmp.path().join("ack-cursor.json");
    std::fs::write(&cursor, "{ not valid json").expect("cursor writes");
    let mut config = doctor_live_test_config("http://127.0.0.1:1");
    config.audit.sink = "stdout".to_string();
    config.deployment.evidence.audit_ack_cursor_path = Some(cursor);

    let shipping = notary_audit_shipping(&config);

    assert_eq!(shipping["shipping_health"], "invalid");
    assert_eq!(shipping["shipping_observed_at"], Value::Null);
}

#[test]
fn doctor_pkcs11_preflight_attempts_module_loading() {
    let _guard = ENV_LOCK.lock().expect("env lock is not poisoned");
    std::env::set_var(
        "TEST_DOCTOR_PKCS11_PUBLIC_JWK",
        r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.example#hsm"}"#,
    );
    std::env::set_var("TEST_DOCTOR_PKCS11_PIN", "1234");
    let mut config = doctor_live_test_config("http://127.0.0.1:1");
    config.evidence.signing_keys.insert(
        "hsm-key".to_string(),
        registry_notary_core::SigningKeyConfig {
            provider: SigningKeyProviderConfig::Pkcs11,
            alg: "EdDSA".to_string(),
            kid: "did:web:issuer.example#hsm".to_string(),
            status: registry_notary_core::SigningKeyStatus::Active,
            publish_until_unix_seconds: None,
            private_jwk_env: String::new(),
            public_jwk_env: "TEST_DOCTOR_PKCS11_PUBLIC_JWK".to_string(),
            module_path: "/definitely/missing/pkcs11.so".to_string(),
            token_label: "registry-notary".to_string(),
            pin_env: "TEST_DOCTOR_PKCS11_PIN".to_string(),
            key_label: "issuer-signing-key".to_string(),
            key_id_hex: "01ab23cd".to_string(),
            path: String::new(),
            password_env: String::new(),
        },
    );

    let diagnostic =
        pkcs11_preflight_diagnostic(&config).expect("active PKCS#11 key triggers preflight");

    assert!(!diagnostic.ok);
    assert!(diagnostic
        .label
        .contains("PKCS#11 signing preflight failed"));
    assert!(
        diagnostic.label.contains("could not load PKCS#11 module")
            || diagnostic
                .label
                .contains("provider 'pkcs11' is not enabled"),
        "unexpected diagnostic: {}",
        diagnostic.label
    );
    std::env::remove_var("TEST_DOCTOR_PKCS11_PUBLIC_JWK");
    std::env::remove_var("TEST_DOCTOR_PKCS11_PIN");
}

#[test]
fn dci_diagnostics_skip_registry_data_api_bindings() {
    let mut config = doctor_live_test_config("http://127.0.0.1:1");
    let binding = config.evidence.claims[0]
        .source_bindings
        .get_mut("record")
        .expect("source binding exists");
    binding.connector = registry_notary_core::SourceConnectorKind::RegistryDataApi;

    let diagnostics = dci_diagnostics(&config, None);

    assert!(diagnostics.is_empty());
}

#[test]
fn dci_probe_body_uses_binding_lookup_field_for_idtype_value_queries_by_default() {
    let config: StandaloneRegistryNotaryConfig =
        serde_norway::from_str(&dci_config_yaml(&test_dci_options(false)))
            .expect("generated config parses");
    let connection = config
        .evidence
        .source_connections
        .get("dci_registry")
        .expect("connection exists");
    let binding =
        first_dci_binding_for_connection(&config, "dci_registry").expect("dci binding exists");
    let body = dci_probe_body(
        &connection.effective_dci().expect("effective dci"),
        binding,
        "secret-subject-123",
        None,
    )
    .expect("body builds");
    assert_eq!(
        body["message"]["search_request"][0]["search_criteria"]["query"],
        json!({
            "type": "SUBJECT_ID",
            "value": "secret-subject-123"
        })
    );
}

#[test]
fn dci_probe_body_allows_subject_id_type_override_for_idtype_value_queries() {
    let config: StandaloneRegistryNotaryConfig =
        serde_norway::from_str(&dci_config_yaml(&test_dci_options(false)))
            .expect("generated config parses");
    let connection = config
        .evidence
        .source_connections
        .get("dci_registry")
        .expect("connection exists");
    let binding =
        first_dci_binding_for_connection(&config, "dci_registry").expect("dci binding exists");
    let body = dci_probe_body(
        &connection.effective_dci().expect("effective dci"),
        binding,
        "secret-subject-123",
        Some("NATIONAL_ID"),
    )
    .expect("body builds");
    assert_eq!(
        body["message"]["search_request"][0]["search_criteria"]["query"],
        json!({
            "type": "NATIONAL_ID",
            "value": "secret-subject-123"
        })
    );
}

#[test]
fn doctor_source_url_preserves_base_path_prefix() {
    let url = source_url_for_cli("https://dci.example.test/api/v1", "/registry/sync/search")
        .expect("relative DCI path builds");

    assert_eq!(
        url.as_str(),
        "https://dci.example.test/api/v1/registry/sync/search"
    );
}

#[test]
fn doctor_source_url_ignores_empty_relative_path_segments() {
    let url = source_url_for_cli("https://dci.example.test/api/v1/", "registry//sync/search")
        .expect("relative DCI path builds");

    assert_eq!(
        url.as_str(),
        "https://dci.example.test/api/v1/registry/sync/search"
    );
}

#[test]
fn public_jwk_diagnostic_rejects_mismatched_kid() {
    let env = format!("TEST_REGISTRY_NOTARY_PUBLIC_JWK_{}", Ulid::new());
    unsafe {
        std::env::set_var(
            &env,
            json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11qYAYdkdABYXknkTDYUs_NflZt9-QJxBWpukhfQq8Q",
                "alg": "EdDSA",
                "kid": "did:web:issuer.example#wrong"
            })
            .to_string(),
        );
    }

    let diagnostic = check_public_jwk_env(
        &env,
        "hsm-key",
        "did:web:issuer.example#expected",
        "EdDSA",
        &EnvFileReport::default(),
    );
    unsafe {
        std::env::remove_var(&env);
    }

    assert!(!diagnostic.ok);
    assert!(diagnostic.label.contains("kid mismatch"));
}

#[test]
fn public_jwk_diagnostic_rejects_missing_alg() {
    let env = format!("TEST_REGISTRY_NOTARY_PUBLIC_JWK_{}", Ulid::new());
    unsafe {
        std::env::set_var(
            &env,
            json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11qYAYdkdABYXknkTDYUs_NflZt9-QJxBWpukhfQq8Q",
                "kid": "did:web:issuer.example#key-1"
            })
            .to_string(),
        );
    }

    let diagnostic = check_public_jwk_env(
        &env,
        "hsm-key",
        "did:web:issuer.example#key-1",
        "EdDSA",
        &EnvFileReport::default(),
    );
    unsafe {
        std::env::remove_var(&env);
    }

    assert!(!diagnostic.ok);
    assert!(diagnostic.label.contains("alg mismatch"));
}

#[test]
fn local_jwk_diagnostic_rejects_mismatched_alg() {
    let env = format!("TEST_REGISTRY_NOTARY_PRIVATE_JWK_{}", Ulid::new());
    unsafe {
        std::env::set_var(
            &env,
            json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "d": "2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw",
                "x": "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
                "alg": "RS256",
                "kid": "did:web:issuer.example#key-1"
            })
            .to_string(),
        );
    }

    let diagnostic = check_local_jwk_env(
        &env,
        "issuer-key",
        "did:web:issuer.example#key-1",
        "EdDSA",
        &EnvFileReport::default(),
    );
    unsafe {
        std::env::remove_var(&env);
    }

    assert!(!diagnostic.ok);
    assert!(
        diagnostic.label.contains("alg mismatch") || diagnostic.label.contains("usable local JWK")
    );
}

#[cfg(unix)]
#[test]
fn generated_secret_file_overwrite_forces_private_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let path = std::env::temp_dir().join(format!(
        "registry-notary-secret-permissions-{}",
        Ulid::new()
    ));
    std::fs::write(&path, "old").expect("test file is written");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .expect("test file permissions are set");

    write_generated_file(&path, "secret", true, true).expect("secret file is overwritten");

    let mode = std::fs::metadata(&path)
        .expect("test file metadata")
        .permissions()
        .mode()
        & 0o777;
    std::fs::remove_file(&path).expect("test file is removed");
    assert_eq!(mode, 0o600);
}

#[tokio::test]
async fn doctor_live_fetches_oauth_runs_dci_probe_and_redacts_subject_and_token() {
    std::env::set_var("TEST_DOCTOR_OAUTH_CLIENT_ID", "doctor-client");
    std::env::set_var("TEST_DOCTOR_OAUTH_CLIENT_SECRET", "doctor-secret");
    let state = DoctorLiveState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .fallback(post(doctor_live_upstream))
            .with_state(state.clone()),
    );
    let base_url = upstream
        .server_address()
        .expect("upstream address")
        .to_string();
    let config = doctor_live_test_config(base_url.trim_end_matches('/'));
    let diagnostics = live_diagnostics(&config, Some("secret-subject-123"), None).await;

    assert!(
        state.token_called.load(Ordering::SeqCst),
        "doctor should call OAuth token endpoint"
    );
    assert!(
        state.dci_called.load(Ordering::SeqCst),
        "doctor should run DCI record probe"
    );
    assert!(
        diagnostics.iter().all(|diagnostic| diagnostic.ok),
        "expected all diagnostics ok: {diagnostics:?}"
    );
    let output = diagnostics
        .iter()
        .map(|diagnostic| {
            format!(
                "{} {}",
                diagnostic.label,
                diagnostic.action.as_deref().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!output.contains("secret-subject-123"));
    assert!(!output.contains("doctor-live-token"));

    std::env::remove_var("TEST_DOCTOR_OAUTH_CLIENT_ID");
    std::env::remove_var("TEST_DOCTOR_OAUTH_CLIENT_SECRET");
}

#[test]
fn doctor_parse_expanded_config_surfaces_disclosure_default_violation() {
    // GH#170 / RS-DM-CLAIM Section 10: `registry-notary doctor` calls
    // parse_expanded_config (see the `doctor` function above), which now
    // rejects a disclosure default that isn't a member of the claim's
    // allowed set (REQ-DM-CLAIM-008) at load instead of loading cleanly
    // and surfacing the inconsistency only when a result is rendered.
    let raw = r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_DOCTOR_API_HASH
      scopes: [dci:evidence_verification]
audit:
  sink: stdout
evidence:
  enabled: true
  service_id: doctor-disclosure-test
  source_connections:
    dci_registry:
      base_url: "https://dci.example.test"
      source_auth:
        type: oauth2_client_credentials
        token_url: "https://dci.example.test/oauth/token"
        client_id_env: TEST_DOCTOR_OAUTH_CLIENT_ID
        client_secret_env: TEST_DOCTOR_OAUTH_CLIENT_SECRET
        request_format: json
      dci:
        search_path: /registry/sync/search
        sender_id: registry-notary
        query_type: idtype-value
        records_path: /message/search_response/0/data/reg_records
  claims:
    - id: dci-record-exists
      title: DCI record exists
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: transitional_direct
      value:
        type: boolean
      source_bindings:
        record:
          connector: dci
          connection: dci_registry
          required_scope: dci:evidence_verification
          dataset: registry_records
          entity: record
          lookup:
            input: target.id
            field: SUBJECT_ID
            op: eq
            cardinality: one
          fields:
            id:
              field: id
              type: string
              required: false
      rule:
        type: exists
        source: record
      disclosure:
        default: value
        allowed: [redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#;

    let err = parse_expanded_config(raw)
        .expect_err("disclosure default outside allowed must fail at the doctor entrypoint");
    let message = err.to_string();
    assert!(
        message.contains("dci-record-exists") && message.contains("disclosure"),
        "doctor-facing error must name the offending claim id and field: {message}"
    );
}
