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
    let mut config = notary_test_config();
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
    let mut config = notary_test_config();
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
    let mut config = notary_test_config();
    config.evidence.claims[0].evidence_mode =
        registry_notary_core::ClaimEvidenceMode::RegistryBacked {
            consultations: std::collections::BTreeMap::new(),
        };
    config.evidence.relay = Some(registry_notary_core::RelayConnectionConfig {
        base_url: "http://127.0.0.1:1".to_string(),
        workload_client_id: "registry-notary".to_string(),
        token_file,
        allowed_private_cidrs: Vec::new(),
        allow_insecure_localhost: true,
        max_in_flight: 8,
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
    let mut config = notary_test_config();
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
    let mut config = notary_test_config();
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
    let mut config = notary_test_config();
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
    let mut config = notary_test_config();
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
    let mut config = notary_test_config();
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
    let mut config = notary_test_config();
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
    let mut config = notary_test_config();
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
    let mut config = notary_test_config();
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
    let mut config = notary_test_config();
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

#[test]
fn doctor_parse_expanded_config_surfaces_disclosure_default_violation() {
    // GH#170 / RS-DM-CLAIM Section 10: `registry-notary doctor` calls
    // parse_expanded_config (see the `doctor` function above), which rejects
    // a disclosure default that is not a member of the claim's allowed set.
    let raw = r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
auth:
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_DOCTOR_API_HASH
      scopes: [registry_notary:credential_issue]
audit:
  sink: stdout
evidence:
  enabled: true
  service_id: doctor-disclosure-test
  claims:
    - id: self-attested-test
      title: Self-attested test
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: self_attested
      rule:
        type: cel
        expression: "true"
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
        message.contains("self-attested-test") && message.contains("disclosure"),
        "doctor-facing error must name the offending claim id and field: {message}"
    );
}
