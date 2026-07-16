// SPDX-License-Identifier: Apache-2.0
// Crate-internal tests for the operator-declared deployment profile gates.
//
// These exercise the gate framework end to end: startup failures, readiness
// failures, posture rendering of the `deployment` and `audit` objects, and
// waiver behaviour. They build their own minimal config so they stay
// independent of the broader standalone HTTP test fixtures.

use super::super::{
    compile_notary_runtime_for_gate_test as compile_notary_runtime,
    compile_notary_runtime_with_provenance_for_gate_test as compile_notary_runtime_with_provenance,
    notary_routers_from_runtime, notary_shared_router_from_runtime,
    standalone_router_for_gate_test as standalone_router, StandaloneServerError,
};
use axum::http::StatusCode;
use axum_test::TestServer;
use registry_notary_core::{
    EvidenceCredentialConfig, RegistryNotaryAdminListenerMode, StandaloneRegistryNotaryConfig,
};
use registry_platform_audit::{AuditProfile, JsonlFileSink};
use registry_platform_authcommon::{CredentialFingerprintProvider, CredentialFingerprintRef};
use registry_platform_ops::ConfigSource;
use registry_platform_testing::fixtures::ED25519_PRIVATE_JWK;
use serde_json::{json, Value};
use std::path::Path;

const AUDIT_SECRET: &str = "0123456789abcdef0123456789abcdef";
static SHIPPING_CURSOR_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
// The raw caseworker API-key fingerprint env value. The tests here never
// present the credential; they exercise startup, readiness, and posture only.
const CASEWORKER_KEY_HASH: &str =
    "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51";

fn set_env() {
    // SAFETY: the integration test binary is single-threaded at setup time.
    unsafe {
        std::env::set_var("REGISTRY_NOTARY_GATES_AUDIT_HASH_SECRET", AUDIT_SECRET);
        std::env::set_var("REGISTRY_NOTARY_GATES_ISSUER_JWK", ED25519_PRIVATE_JWK);
        std::env::set_var(
            "REGISTRY_NOTARY_GATES_FEDERATION_SECRET",
            "gates-federation-pairwise-secret",
        );
    }
}

#[derive(Clone, Copy)]
enum TestSignerProvider {
    LocalJwkEnv,
    FileWatch,
}

/// A minimal but complete config skeleton, parameterised by the knobs the gates
/// read: whether the audit sink is durable and a YAML `deployment:` block.
/// Serving-state dependencies use the crate-internal in-memory harness. The
/// operator config itself retains the clean PostgreSQL default so gate and
/// posture projections exercise deployable configuration.
struct ConfigBuilder {
    durable_audit: bool,
    /// Overrides `durable_audit` with a specific sink kind ("jsonl" or
    /// "syslog") for the retention-local-only gate tests, which need sink
    /// kinds beyond the plain durable/stdout split.
    audit_sink_kind: Option<&'static str>,
    audit_path: String,
    deployment_block: String,
    /// Disable OpenAPI auth (triggers openapi_public gate).
    openapi_public: bool,
    /// Provider for the active test signing key.
    signer_provider: Option<TestSignerProvider>,
    /// Bind the test signing key to a credential profile.
    credential_signer: bool,
    /// Bind the test signing key to federation response signing.
    federation_signer: bool,
    signer_path: String,
}

impl ConfigBuilder {
    fn new(audit_path: &str) -> Self {
        Self {
            durable_audit: true,
            audit_sink_kind: None,
            audit_path: audit_path.to_string(),
            deployment_block: String::new(),
            openapi_public: false,
            signer_provider: None,
            credential_signer: false,
            federation_signer: false,
            signer_path: Path::new(audit_path)
                .with_file_name("gates-signer.jwk")
                .display()
                .to_string(),
        }
    }

    fn durable_audit(mut self, durable: bool) -> Self {
        self.durable_audit = durable;
        self
    }

    fn audit_sink_kind(mut self, kind: &'static str) -> Self {
        self.audit_sink_kind = Some(kind);
        self
    }

    fn deployment(mut self, block: &str) -> Self {
        self.deployment_block = block.to_string();
        self
    }

    fn openapi_public(mut self, enable: bool) -> Self {
        self.openapi_public = enable;
        self
    }

    fn local_software_signer(mut self, enable: bool) -> Self {
        self.signer_provider = enable.then_some(TestSignerProvider::LocalJwkEnv);
        self.credential_signer = enable;
        self
    }

    fn file_watch_signer(mut self) -> Self {
        self.signer_provider = Some(TestSignerProvider::FileWatch);
        self.credential_signer = true;
        self
    }

    fn federation_local_software_signer(mut self) -> Self {
        self.signer_provider = Some(TestSignerProvider::LocalJwkEnv);
        self.federation_signer = true;
        self
    }

    fn audit_section(&self) -> String {
        match self.audit_sink_kind {
            Some("jsonl") => format!(
                "audit:\n  sink: jsonl\n  path: \"{}\"\n  hash_secret_env: REGISTRY_NOTARY_GATES_AUDIT_HASH_SECRET\n",
                self.audit_path
            ),
            Some("syslog") => format!(
                "audit:\n  sink: syslog\n  syslog_socket_path: \"{}\"\n  hash_secret_env: REGISTRY_NOTARY_GATES_AUDIT_HASH_SECRET\n",
                self.audit_path
            ),
            Some(other) => panic!("unsupported audit_sink_kind in test builder: {other}"),
            None if self.durable_audit => format!(
                "audit:\n  sink: file\n  path: \"{}\"\n  hash_secret_env: REGISTRY_NOTARY_GATES_AUDIT_HASH_SECRET\n",
                self.audit_path
            ),
            None => {
                "audit:\n  sink: stdout\n  hash_secret_env: REGISTRY_NOTARY_GATES_AUDIT_HASH_SECRET\n"
                    .to_string()
            }
        }
    }

    fn server_section(&self) -> String {
        if self.openapi_public {
            "server:\n  bind: 127.0.0.1:0\n  openapi_requires_auth: false\n".to_string()
        } else {
            "server:\n  bind: 127.0.0.1:0\n".to_string()
        }
    }

    fn signing_section(&self) -> String {
        let provider = match self.signer_provider {
            Some(TestSignerProvider::LocalJwkEnv) => concat!(
                "  signing_keys:\n",
                "    issuer-key:\n",
                "      provider: local_jwk_env\n",
                "      private_jwk_env: REGISTRY_NOTARY_GATES_ISSUER_JWK\n",
                "      alg: EdDSA\n",
                "      kid: registry-platform-testing-ed25519-1\n",
                "      status: active\n",
            )
            .to_string(),
            Some(TestSignerProvider::FileWatch) => format!(
                concat!(
                    "  signing_keys:\n",
                    "    issuer-key:\n",
                    "      provider: file_watch\n",
                    "      path: \"{}\"\n",
                    "      alg: EdDSA\n",
                    "      kid: registry-platform-testing-ed25519-1\n",
                    "      status: active\n",
                ),
                self.signer_path,
            ),
            None => return String::new(),
        };
        if self.credential_signer {
            format!(
                "{provider}{}",
                concat!(
                    "  credential_profiles:\n",
                    "    gates_sd_jwt:\n",
                    "      format: application/dc+sd-jwt\n",
                    "      issuer: did:web:evidence.example.test\n",
                    "      signing_key: issuer-key\n",
                    "      vct: https://evidence.example.test/credentials/gates\n",
                    "      holder_binding:\n",
                    "        mode: none\n",
                    "      allowed_claims:\n",
                    "        - farmed-land-size\n",
                    "      disclosure:\n",
                    "        allowed: [value, redacted]\n",
                )
            )
        } else {
            provider
        }
    }

    fn claim_credential_profiles(&self) -> &'static str {
        if self.credential_signer {
            "      credential_profiles:\n        - gates_sd_jwt\n"
        } else {
            ""
        }
    }

    fn federation_section(&self) -> &'static str {
        if !self.federation_signer {
            return "";
        }
        concat!(
            "federation:\n",
            "  enabled: true\n",
            "  node_id: did:web:evidence.example.test\n",
            "  issuer: https://evidence.example.test\n",
            "  jwks_uri: https://evidence.example.test/federation/jwks.json\n",
            "  federation_api: https://evidence.example.test/federation/v1\n",
            "  supported_protocol_versions: [registry-notary-federation/v0.1]\n",
            "  signing:\n",
            "    signing_key: issuer-key\n",
            "  pairwise_subject_hash:\n",
            "    secret_env: REGISTRY_NOTARY_GATES_FEDERATION_SECRET\n",
            "  peers:\n",
            "    - node_id: did:web:peer.example.test\n",
            "      issuer: https://peer.example.test\n",
            "      jwks_uri: https://peer.example.test/federation/jwks.json\n",
            "      allowed_protocol_versions: [registry-notary-federation/v0.1]\n",
            "      allowed_purposes: [https://purpose.example.test/eligibility]\n",
            "      allowed_profiles: [gates]\n",
            "      evaluation_scopes: [farmer_registry:evidence_verification]\n",
            "  evaluation_profiles:\n",
            "    - id: gates\n",
            "      ruleset: gates-v1\n",
            "      claim_id: farmed-land-size\n",
            "      subject_id_type: national_id\n",
        )
    }

    fn build(&self) -> StandaloneRegistryNotaryConfig {
        set_env();
        if matches!(self.signer_provider, Some(TestSignerProvider::FileWatch)) {
            std::fs::write(&self.signer_path, ED25519_PRIVATE_JWK)
                .expect("file-watch signer fixture writes");
        }
        let state = if self.deployment_block.contains("profile: local")
            && !self.deployment_block.contains("multi_instance: true")
        {
            "state:\n  storage: in_memory\n"
        } else {
            ""
        };
        let raw = format!(
            r#"
{server}{state}auth:
  api_keys:
    - id: caseworker
      fingerprint:
        provider: env
        name: TEST_GATES_API_KEY_HASH
      scopes: [farmer_registry:evidence_verification]
{audit}evidence:
  enabled: true
  service_id: evidence.test
  api_base_url: https://evidence.example.test
{signing}
  claims:
    - id: farmed-land-size
      title: Farmed land size
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: self_attested
      value:
        type: boolean
      rule:
        type: cel
        expression: "true"
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
{claim_credential_profiles}
{deployment}{federation}"#,
            server = self.server_section(),
            state = state,
            audit = self.audit_section(),
            signing = self.signing_section(),
            claim_credential_profiles = self.claim_credential_profiles(),
            deployment = self.deployment_block,
            federation = self.federation_section(),
        );
        // The caseworker fingerprint env var must resolve at runtime.
        // SAFETY: see set_env.
        unsafe {
            std::env::set_var("TEST_GATES_API_KEY_HASH", CASEWORKER_KEY_HASH);
        }
        serde_norway::from_str(&raw).expect("gates config deserializes")
    }
}

fn env_fingerprint_ref(_id: &str, env_name: &str, _fingerprint: &str) -> CredentialFingerprintRef {
    CredentialFingerprintRef {
        provider: CredentialFingerprintProvider::Env,
        name: Some(env_name.to_string()),
        path: None,
    }
}

fn add_ops_read_api_key(config: &mut StandaloneRegistryNotaryConfig) {
    let fingerprint = "sha256:d9310c002af91822beb0b3487d8b04f85bf6bf1f8a5496bff7d35fc7c5a29def";
    // SAFETY: see set_env.
    unsafe {
        std::env::set_var("TEST_GATES_OPS_KEY_HASH", fingerprint);
    }
    config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "ops".to_string(),
        fingerprint: env_fingerprint_ref("ops", "TEST_GATES_OPS_KEY_HASH", fingerprint),
        scopes: vec!["registry_notary:ops_read".to_string()],
        authorization_details: None,
    });
}

fn assert_matches_posture_schema(body: &Value) {
    let schema: Value = serde_json::from_str(registry_platform_ops::POSTURE_SCHEMA_V1)
        .expect("posture schema parses");
    let compiled = jsonschema::JSONSchema::compile(&schema).expect("posture schema compiles");
    let errors = compiled
        .validate(body)
        .err()
        .map(|errors| errors.map(|error| error.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();
    assert!(
        errors.is_empty(),
        "posture did not match registry.ops.posture.v1: {errors:?}\n{body:#}"
    );
}

async fn fetch_posture(config: StandaloneRegistryNotaryConfig) -> Value {
    let mut config = config;
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::SharedWithPublic;
    add_ops_read_api_key(&mut config);
    let runtime = compile_notary_runtime(config).expect("runtime compiles for posture");
    let app =
        notary_shared_router_from_runtime(runtime).expect("source-free runtime is serve-ready");
    let server = TestServer::builder().http_transport().build(app);
    let response = server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("x-api-key", "ops-token")
        .await;
    response.assert_status_ok();
    response.json()
}

fn audit_path(tmp: &tempfile::TempDir) -> String {
    tmp.path()
        .join("audit.jsonl")
        .to_string_lossy()
        .into_owned()
}

fn registry_backed_config(tmp: &tempfile::TempDir) -> StandaloneRegistryNotaryConfig {
    let mut config = ConfigBuilder::new(&audit_path(tmp))
        .deployment("deployment:\n  profile: local\n")
        .build();
    config.evidence.relay = Some(registry_notary_core::RelayConnectionConfig {
        base_url: "http://127.0.0.1:1".to_string(),
        workload_client_id: "registry-notary".to_string(),
        token_file: tmp.path().join("relay-workload.jwt"),
        allowed_private_cidrs: Vec::new(),
        allow_insecure_localhost: true,
        max_in_flight: 8,
    });
    config.evidence.claims[0] = serde_norway::from_str(
        r#"
id: farmed-land-size
title: Farmed land size
version: "1"
subject_type: person
evidence_mode:
  type: registry_backed
  consultations:
    farmer:
      profile:
        id: example.farmed-land-size.exact
        contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      inputs:
        subject_id: target.id
      outputs:
        total_farmed_area: { type: string, nullable: true, max_bytes: 64 }
value:
  type: string
  nullable: true
purpose: benefit-verification
required_scopes: [farmer_registry:evidence_verification]
rule:
  type: consultation_output
  consultation: farmer
  output: total_farmed_area
disclosure:
  default: value
  allowed: [value, redacted]
formats:
  - application/vnd.registry-notary.claim-result+json
"#,
    )
    .expect("Registry-backed claim parses");
    config
}

/// Compile a config expecting it to be rejected, returning the error.
///
/// `NotaryRuntimeSnapshot` does not implement `Debug`, so `expect_err` cannot be
/// used directly on the compile result.
fn expect_compile_rejected(
    config: StandaloneRegistryNotaryConfig,
    context: &str,
) -> StandaloneServerError {
    match compile_notary_runtime(config) {
        Ok(_) => panic!("expected compile to be rejected: {context}"),
        Err(error) => error,
    }
}

#[test]
fn source_free_standalone_router_builds_without_relay_activation() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment("deployment:\n  profile: local\n")
        .build();

    let _router = standalone_router(config).expect("source-free router builds synchronously");
}

#[test]
fn synchronous_router_requires_async_activation_for_postgresql() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment("deployment:\n  profile: production\n  multi_instance: true\n")
        .build();

    let error = match super::super::standalone_router(config) {
        Ok(_) => panic!("the synchronous helper must reject PostgreSQL state"),
        Err(error) => error,
    };
    assert!(matches!(
        &error,
        StandaloneServerError::PostgresqlStateActivationRequired
    ));
    assert!(error.to_string().contains("activate().await"));
}

#[test]
fn registry_backed_standalone_router_refuses_to_serve_before_activation() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = registry_backed_config(&tmp);

    let error = match standalone_router(config) {
        Ok(_) => panic!("Registry-backed standalone router must require Relay activation"),
        Err(error) => error,
    };
    assert!(matches!(error, StandaloneServerError::RelayNotActivated));
}

#[test]
fn registry_backed_compiled_runtime_cannot_be_routed_before_activation() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let runtime = compile_notary_runtime(registry_backed_config(&tmp))
        .expect("Registry-backed runtime compiles before activation");

    let error = match notary_shared_router_from_runtime(runtime) {
        Ok(_) => panic!("compiled Registry-backed runtime must not be served before activation"),
        Err(error) => error,
    };
    assert!(matches!(error, StandaloneServerError::RelayNotActivated));
}

#[test]
fn evidence_grade_postgresql_default_does_not_trigger_in_memory_gate() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment("deployment:\n  profile: evidence_grade\n  multi_instance: true\n")
        .build();

    let error = expect_compile_rejected(config, "evidence_grade unsigned config must refuse");
    match error {
        StandaloneServerError::DeploymentGateStartupFailure { profile, findings } => {
            assert_eq!(profile, "evidence_grade");
            assert!(!findings.contains("notary.state.in_memory_high_risk"));
        }
        other => panic!("expected a deployment gate startup failure, got: {other:?}"),
    }
}

#[test]
fn production_without_audit_sink_refuses_startup() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .durable_audit(false)
        .deployment("deployment:\n  profile: production\n")
        .build();

    let error = expect_compile_rejected(config, "production without durable sink must refuse");
    match error {
        StandaloneServerError::DeploymentGateStartupFailure { profile, findings } => {
            assert_eq!(profile, "production");
            assert!(
                findings.contains("notary.audit.sink_missing"),
                "expected the audit sink gate in: {findings}"
            );
        }
        other => panic!("expected a deployment gate startup failure, got: {other:?}"),
    }
}

#[test]
fn local_profile_binds_no_gates_with_postgresql_default() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .durable_audit(false)
        .deployment("deployment:\n  profile: local\n  multi_instance: true\n")
        .build();

    // Local binds no deployment gates. Multi-instance uses the PostgreSQL
    // default rather than an impossible in-memory fixture.
    compile_notary_runtime(config).expect("local profile binds no gates");
}

#[test]
fn undeclared_profile_refuses_startup_with_actionable_error() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .durable_audit(false)
        .build();

    let error = expect_compile_rejected(config, "undeclared profile must refuse startup");
    let rendered = error.to_string();
    match error {
        StandaloneServerError::DeploymentGateStartupFailure { profile, findings } => {
            assert_eq!(profile, "undeclared");
            assert!(
                findings.contains("deployment.profile_undeclared"),
                "expected the undeclared-profile gate in: {findings}"
            );
        }
        other => panic!("expected a deployment gate startup failure, got: {other:?}"),
    }
    assert!(
        rendered.contains("set deployment.profile: local for development"),
        "startup error must be actionable: {rendered}"
    );
}

#[test]
fn invalid_profile_value_fails_config_load() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let result = std::panic::catch_unwind(|| {
        ConfigBuilder::new(&audit_path(&tmp))
            .deployment("deployment:\n  profile: prod\n")
            .build()
    });
    assert!(
        result.is_err(),
        "an unknown profile value must fail deserialization"
    );
}

#[test]
fn waiver_for_startup_fail_gate_is_rejected_at_load() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .durable_audit(false)
        .deployment(
            "deployment:\n  profile: production\n  waivers:\n    - finding: notary.audit.sink_missing\n      reason: \"synthetic test waiver\"\n      expires: 2999-01-01\n",
        )
        .build();

    let error = expect_compile_rejected(config, "a startup_fail gate must never be waivable");
    assert!(
        matches!(error, StandaloneServerError::Config(_)),
        "expected a config validation error, got: {error:?}"
    );
}

#[tokio::test]
async fn production_multi_instance_postgresql_default_is_state_ready() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment("deployment:\n  profile: production\n  multi_instance: true\n")
        .build();
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::Dedicated;

    let app = standalone_router(config).expect("production PostgreSQL config starts in harness");
    let server = TestServer::builder().http_transport().build(app);
    let ready = server.get("/ready").await;
    ready.assert_status_ok();
    let body: Value = ready.json();
    assert_eq!(body["status"], "ready");
}

#[tokio::test]
async fn production_declared_external_without_cursor_reports_shipping_unverified() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    // A file sink with attested off-host shipping is declared_external; with no
    // ack cursor the completeness is unobserved, so shipping_unverified binds.
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment(
            "deployment:\n  profile: production\n  evidence:\n    audit_offhost_shipping: true\n",
        )
        .build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    let findings = posture["deployment"]["findings"]
        .as_array()
        .expect("deployment findings is an array");
    let finding = findings
        .iter()
        .find(|f| f["id"] == "notary.audit.shipping_unverified")
        .expect("shipping_unverified finding present under production");
    assert_eq!(finding["severity"], "finding_warn");
    assert_eq!(finding["status"], "active");

    let posture_audit = &posture["posture"]["audit"];
    assert_eq!(posture_audit["shipping_target"], "declared_external");
    assert_eq!(posture_audit["shipping_health"], "unverified");
}

#[tokio::test]
async fn production_stale_cursor_reports_shipping_stale_finding() {
    let _guard = SHIPPING_CURSOR_TEST_LOCK.lock().await;
    let tmp = tempfile::TempDir::new().expect("tempdir");
    // A cursor stale against the default 900s window, on an attested file sink.
    let cursor = write_ack_cursor(&tmp, "2026-06-04T09:59:00Z");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment(&format!(
            "deployment:\n  profile: production\n  evidence:\n    audit_offhost_shipping: true\n    audit_ack_cursor_path: \"{cursor}\"\n"
        ))
        .build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    let findings = posture["deployment"]["findings"]
        .as_array()
        .expect("deployment findings is an array");
    let finding = findings
        .iter()
        .find(|f| f["id"] == "notary.audit.shipping_stale")
        .expect("shipping_stale finding present under production");
    assert_eq!(finding["severity"], "finding_error");
    assert_eq!(finding["status"], "active");

    let posture_audit = &posture["posture"]["audit"];
    assert_eq!(posture_audit["shipping_health"], "stale");
    assert_eq!(
        posture_audit["shipping_observed_at"],
        "2026-06-04T09:59:00Z"
    );
}

#[tokio::test]
async fn production_unapproved_local_signer_reports_readiness_failure() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .local_software_signer(true)
        .deployment("deployment:\n  profile: production\n")
        .build();

    let app = standalone_router(config).expect("production local signer config still starts");
    let server = TestServer::builder().http_transport().build(app);
    let ready = server.get("/ready").await;
    ready.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = ready.json();
    assert_eq!(body["readiness_status"], "not_ready");
    let header_request_id = ready
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .expect("readiness failure carries x-request-id");
    assert_eq!(body["request_id"], header_request_id);
    assert_eq!(body["checks"]["failed"], 1);
    assert!(body["checks"].get("deployment").is_none());
    let custody = &body["checks"]["signing_providers"]["custody"];
    assert_eq!(custody["custody_approval_required"], true);
    assert_eq!(custody["custody_approved"], false);
    assert_eq!(custody["signing_provider_count"], 1);
    assert_eq!(custody["local_software_signing_provider_count"], 1);
    assert_eq!(custody["unapproved_signing_provider_count"], 1);
    assert_eq!(custody["active_provider_counts"]["local_jwk_env"], 1);
    assert_eq!(
        custody["surfaces"]["credential_issuance"]["signing_provider_count"],
        1
    );
    assert_eq!(
        custody["surfaces"]["credential_issuance"]["unapproved_signing_provider_count"],
        1
    );
}

#[tokio::test]
async fn production_file_watch_signer_requires_custody_approval() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .file_watch_signer()
        .deployment("deployment:\n  profile: production\n")
        .build();

    let app = standalone_router(config).expect("production file-watch signer config starts");
    let server = TestServer::builder().http_transport().build(app);
    let ready = server.get("/ready").await;
    ready.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = ready.json();
    let custody = &body["checks"]["signing_providers"]["custody"];
    assert_eq!(custody["active_provider_counts"]["file_watch"], 1);
    assert_eq!(custody["local_software_signing_provider_count"], 1);
    assert_eq!(custody["unapproved_signing_provider_count"], 1);
}

#[tokio::test]
async fn production_federation_signer_is_reported_by_surface() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .federation_local_software_signer()
        .deployment("deployment:\n  profile: production\n")
        .build();

    let app = standalone_router(config).expect("production federation signer config starts");
    let server = TestServer::builder().http_transport().build(app);
    let ready = server.get("/ready").await;
    ready.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = ready.json();
    let custody = &body["checks"]["signing_providers"]["custody"];
    assert_eq!(
        custody["surfaces"]["credential_issuance"]["signing_provider_count"],
        0
    );
    assert_eq!(custody["surfaces"]["federation"]["enabled"], true);
    assert_eq!(
        custody["surfaces"]["federation"]["signing_provider_count"],
        1
    );
    assert_eq!(
        custody["surfaces"]["federation"]["local_software_signing_provider_count"],
        1
    );
    assert_eq!(
        custody["surfaces"]["federation"]["unapproved_signing_provider_count"],
        1
    );
}

#[tokio::test]
async fn production_signer_custody_approval_is_visible_in_readiness() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .local_software_signer(true)
        .deployment(
            "deployment:\n  profile: production\n  evidence:\n    signer_custody_approved: true\n",
        )
        .build();

    let app = standalone_router(config).expect("approved local signer config starts");
    let server = TestServer::builder().http_transport().build(app);
    let ready = server.get("/ready").await;
    ready.assert_status_ok();
    let body: Value = ready.json();
    assert_eq!(body["status"], "ready");
    assert_eq!(body["checks"]["failed"], 0);
    let custody = &body["checks"]["signing_providers"]["custody"];
    assert_eq!(custody["custody_approval_required"], true);
    assert_eq!(custody["custody_approved"], true);
    assert_eq!(custody["signing_provider_count"], 1);
    assert_eq!(custody["local_software_signing_provider_count"], 1);
    assert_eq!(custody["unapproved_signing_provider_count"], 0);
}

#[test]
fn evidence_grade_unapproved_signer_fails_startup() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .local_software_signer(true)
        .deployment("deployment:\n  profile: evidence_grade\n")
        .build();

    match compile_notary_runtime_with_provenance(config, ConfigSource::SignedBundleFile, None) {
        Err(StandaloneServerError::DeploymentGateStartupFailure { findings, .. }) => {
            assert!(
                findings.contains("notary.signer_custody.unapproved"),
                "signer-custody gate should be the startup blocker: {findings}"
            );
        }
        Ok(_) => panic!("expected signer-custody deployment gate startup failure, got success"),
        Err(other) => {
            panic!("expected signer-custody deployment gate startup failure, got {other}")
        }
    }
}

#[tokio::test]
async fn posture_renders_deployment_and_audit_assurance() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment("deployment:\n  profile: production\n")
        .build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    assert_eq!(posture["deployment"]["profile"], "production");

    let audit = &posture["audit"];
    assert_eq!(audit["keyed_integrity"], "hmac");
    assert_eq!(audit["write_policy"], "fail_closed_route_families");
    assert_eq!(audit["redaction_mode"], "redacted");
    assert_eq!(audit["sink_class"], "file");
    assert_eq!(audit["retention_owner"], "operator");
    // All eight assurance fields are present.
    for field in [
        "write_policy",
        "redaction_mode",
        "hash_chain",
        "keyed_integrity",
        "sink_class",
        "retention_owner",
        "checkpoints",
        "anchoring",
    ] {
        assert!(
            audit.get(field).is_some(),
            "audit assurance is missing {field}"
        );
    }

    let posture_audit = &posture["posture"]["audit"];
    assert_eq!(posture_audit["shipping_target_configured"], false);
    assert_eq!(posture_audit["shipping_target"], "none");
    // No shipping target is configured, so health and observed_at are null.
    assert_eq!(posture_audit["shipping_health"], Value::Null);
    assert_eq!(posture_audit["shipping_observed_at"], Value::Null);
}

/// Write a `registry.audit.ack_cursor.v1` file with the given `acked_at` and
/// return its path as a string for embedding in a `deployment` block.
fn write_ack_cursor(tmp: &tempfile::TempDir, acked_at: &str) -> String {
    write_ack_cursor_with_hash(tmp, acked_at, &"4".repeat(64))
}

fn write_ack_cursor_with_hash(
    tmp: &tempfile::TempDir,
    acked_at: &str,
    last_acked_hash: &str,
) -> String {
    let path = tmp.path().join("ack-cursor.json");
    let body = format!(
        r#"{{"schema":"registry.audit.ack_cursor.v1","acked_at":"{acked_at}","last_acked_hash":"sha256:{last_acked_hash}","writer":"test-shipper"}}"#
    );
    std::fs::write(&path, body).expect("ack cursor writes");
    path.display().to_string()
}

async fn seed_audit_tail(audit_path: &str) -> String {
    set_env();
    let sink = JsonlFileSink::new(audit_path);
    let profile = AuditProfile::registry_notary_from_env("REGISTRY_NOTARY_GATES_AUDIT_HASH_SECRET")
        .expect("test audit profile builds");
    let chain = profile
        .bootstrap_or_start_empty(&sink)
        .await
        .expect("test audit chain starts");
    let envelope = chain
        .append(&sink, json!({"event": "shipping-readiness-test"}))
        .await
        .expect("test audit record appends");
    envelope
        .record_hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn read_audit_tail(audit_path: &str) -> String {
    let contents = std::fs::read_to_string(audit_path).expect("audit file reads");
    let envelope: Value = serde_json::from_str(
        contents
            .lines()
            .last()
            .expect("audit file contains an envelope"),
    )
    .expect("audit envelope parses");
    envelope["record_hash"]
        .as_str()
        .expect("audit envelope has a record hash")
        .to_string()
}

fn rfc3339_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("now formats as RFC3339")
}

#[tokio::test]
async fn posture_reports_shipping_health_ok_for_fresh_cursor() {
    let _guard = SHIPPING_CURSOR_TEST_LOCK.lock().await;
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let audit_path = audit_path(&tmp);
    let tail_hash = seed_audit_tail(&audit_path).await;
    let acked_at = rfc3339_now();
    let cursor = write_ack_cursor_with_hash(&tmp, &acked_at, &tail_hash);
    // A durable file sink with attested off-host shipping is declared_external,
    // so shipping_target_configured is true and audit stays off stdout. local
    // binds no gates, so the posture emission is isolated.
    let config = ConfigBuilder::new(&audit_path)
        .deployment(&format!(
            "deployment:\n  profile: local\n  evidence:\n    audit_offhost_shipping: true\n    audit_ack_cursor_path: \"{cursor}\"\n"
        ))
        .build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    let posture_audit = &posture["posture"]["audit"];
    assert_eq!(posture_audit["shipping_target_configured"], true);
    assert_eq!(posture_audit["shipping_target"], "declared_external");
    assert_eq!(posture_audit["shipping_health"], "ok");
    assert_eq!(posture_audit["shipping_observed_at"], acked_at);
}

#[tokio::test]
async fn evidence_grade_readiness_rechecks_cursor_binding_and_recovers() {
    let _guard = SHIPPING_CURSOR_TEST_LOCK.lock().await;
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let audit_path = audit_path(&tmp);
    let tail_hash = seed_audit_tail(&audit_path).await;
    let acked_at = rfc3339_now();
    let cursor = write_ack_cursor_with_hash(&tmp, &acked_at, &tail_hash);
    let mut config = ConfigBuilder::new(&audit_path)
        .deployment(&format!(
            "deployment:\n  profile: evidence_grade\n  evidence:\n    audit_offhost_shipping: true\n    audit_ack_cursor_path: \"{cursor}\"\n"
        ))
        .build();
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::Dedicated;
    add_ops_read_api_key(&mut config);
    let runtime =
        compile_notary_runtime_with_provenance(config, ConfigSource::SignedBundleFile, None)
            .expect("signed evidence-grade runtime compiles");
    let routers = notary_routers_from_runtime(runtime).expect("source-free runtime is serve-ready");
    let server = TestServer::builder().http_transport().build(routers.public);
    let admin_server = TestServer::builder().http_transport().build(routers.admin);

    let ready = server.get("/ready").await;
    ready.assert_status_ok();
    let body: Value = ready.json();
    assert_eq!(body["status"], "ready");

    let healthy_posture: Value = admin_server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("x-api-key", "ops-token")
        .await
        .json();
    assert_eq!(healthy_posture["posture"]["audit"]["shipping_health"], "ok");
    assert!(!healthy_posture["deployment"]["findings"]
        .as_array()
        .expect("deployment findings")
        .iter()
        .any(|finding| finding["id"] == "notary.audit.shipping_stale"));
    // The protected posture request is itself audited after its response, so
    // let the shipper catch up before testing a different audited request.
    let posture_tail = read_audit_tail(&audit_path);
    write_ack_cursor_with_hash(&tmp, &rfc3339_now(), &posture_tail);

    server
        .get("/v1/claims")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    let lagging: Value = server.get("/ready").await.json();
    assert_eq!(lagging["checks"]["failed"], 1);

    let lagging_posture: Value = admin_server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("x-api-key", "ops-token")
        .await
        .json();
    assert_eq!(
        lagging_posture["posture"]["audit"]["shipping_health"],
        "invalid"
    );
    assert!(lagging_posture["deployment"]["findings"]
        .as_array()
        .expect("deployment findings")
        .iter()
        .any(|finding| finding["id"] == "notary.audit.shipping_stale"));
    let advanced_tail = read_audit_tail(&audit_path);

    write_ack_cursor_with_hash(&tmp, &rfc3339_now(), &advanced_tail);
    let caught_up: Value = server.get("/ready").await.json();
    assert_eq!(caught_up["checks"]["failed"], 0);

    write_ack_cursor_with_hash(&tmp, "2026-06-04T09:59:00Z", &advanced_tail);
    let stale: Value = server.get("/ready").await.json();
    assert_eq!(stale["checks"]["failed"], 1);

    write_ack_cursor_with_hash(&tmp, &rfc3339_now(), &"5".repeat(64));
    let mismatched: Value = server.get("/ready").await.json();
    assert_eq!(mismatched["checks"]["failed"], 1);

    write_ack_cursor_with_hash(&tmp, &rfc3339_now(), &advanced_tail);
    let recovered: Value = server.get("/ready").await.json();
    assert_eq!(recovered["checks"]["failed"], 0);

    std::fs::remove_file(tmp.path().join("ack-cursor.json")).expect("cursor removed");
    let missing: Value = server.get("/ready").await.json();
    assert_eq!(missing["checks"]["failed"], 1);

    write_ack_cursor_with_hash(&tmp, &rfc3339_now(), &advanced_tail);
    let restored: Value = server.get("/ready").await.json();
    assert_eq!(restored["checks"]["failed"], 0);
}

#[tokio::test]
async fn posture_reports_shipping_health_stale_for_old_cursor() {
    let _guard = SHIPPING_CURSOR_TEST_LOCK.lock().await;
    let tmp = tempfile::TempDir::new().expect("tempdir");
    // Far in the past relative to the default 900s window.
    let cursor = write_ack_cursor(&tmp, "2026-06-04T09:59:00Z");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment(&format!(
            "deployment:\n  profile: local\n  evidence:\n    audit_offhost_shipping: true\n    audit_ack_cursor_path: \"{cursor}\"\n"
        ))
        .build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    let posture_audit = &posture["posture"]["audit"];
    assert_eq!(posture_audit["shipping_health"], "stale");
    assert_eq!(
        posture_audit["shipping_observed_at"],
        "2026-06-04T09:59:00Z"
    );
}

#[tokio::test]
async fn posture_reports_shipping_health_unverified_without_cursor() {
    let _guard = SHIPPING_CURSOR_TEST_LOCK.lock().await;
    let tmp = tempfile::TempDir::new().expect("tempdir");
    // A declared_external sink (file + attested shipping) with no ack cursor.
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment(
            "deployment:\n  profile: local\n  evidence:\n    audit_offhost_shipping: true\n",
        )
        .build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    let posture_audit = &posture["posture"]["audit"];
    assert_eq!(posture_audit["shipping_target_configured"], true);
    assert_eq!(posture_audit["shipping_target"], "declared_external");
    assert_eq!(posture_audit["shipping_health"], "unverified");
    assert_eq!(posture_audit["shipping_observed_at"], Value::Null);
}

#[tokio::test]
async fn posture_reports_local_profile_without_findings() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment("deployment:\n  profile: local\n")
        .build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    assert_eq!(posture["deployment"]["profile"], "local");
    let findings = posture["deployment"]["findings"]
        .as_array()
        .expect("deployment findings is an array");
    assert!(
        findings.is_empty(),
        "local profile should not bind findings"
    );
}

#[tokio::test]
async fn posture_reports_waived_finding_with_active_waiver() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .openapi_public(true)
        .deployment(
            "deployment:\n  profile: hosted_lab\n  waivers:\n    - finding: notary.openapi.public\n      reason: \"synthetic single-node lab, ticket TEST-1\"\n      expires: 2999-01-01\n",
        )
        .build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    let findings = posture["deployment"]["findings"]
        .as_array()
        .expect("deployment findings is an array");
    let waived = findings
        .iter()
        .find(|finding| finding["id"] == "notary.openapi.public")
        .expect("public OpenAPI finding is present");
    assert_eq!(waived["status"], "waived");
    assert_eq!(waived["waiver"]["expires"], "2999-01-01");

    let waivers = posture["deployment"]["waivers"]
        .as_array()
        .expect("deployment waivers is an array");
    assert!(
        waivers
            .iter()
            .any(|waiver| waiver["finding"] == "notary.openapi.public"),
        "active waiver must be echoed in: {waivers:#?}"
    );
}

#[tokio::test]
async fn posture_re_triggers_expired_waiver() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .openapi_public(true)
        .deployment(
            "deployment:\n  profile: hosted_lab\n  waivers:\n    - finding: notary.openapi.public\n      reason: \"synthetic expired waiver\"\n      expires: 2000-01-01\n",
        )
        .build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    let findings = posture["deployment"]["findings"]
        .as_array()
        .expect("deployment findings is an array");
    let openapi = findings
        .iter()
        .find(|finding| finding["id"] == "notary.openapi.public")
        .expect("public OpenAPI finding is present");
    // An expired waiver stops suppressing the finding: it is active again.
    assert_eq!(openapi["status"], "active");
    assert!(
        findings
            .iter()
            .any(|finding| finding["id"] == "deployment.waiver_expired"),
        "expected deployment.waiver_expired in: {findings:#?}"
    );
}

#[tokio::test]
async fn hosted_lab_openapi_public_reports_finding_warn() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .openapi_public(true)
        .deployment("deployment:\n  profile: hosted_lab\n")
        .build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    let findings = posture["deployment"]["findings"]
        .as_array()
        .expect("deployment findings is an array");
    let found = findings
        .iter()
        .find(|f| f["id"] == "notary.openapi.public")
        .expect("notary.openapi.public present under hosted_lab");
    assert_eq!(
        found["severity"], "finding_warn",
        "hosted_lab openapi_public must be finding_warn"
    );
}

#[tokio::test]
async fn production_openapi_public_reports_finding_error() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .openapi_public(true)
        .deployment("deployment:\n  profile: production\n")
        .build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    let findings = posture["deployment"]["findings"]
        .as_array()
        .expect("deployment findings is an array");
    let found = findings
        .iter()
        .find(|f| f["id"] == "notary.openapi.public")
        .expect("notary.openapi.public present under production");
    assert_eq!(
        found["severity"], "finding_error",
        "production openapi_public must be finding_error"
    );
}

#[tokio::test]
async fn openapi_with_auth_required_clears_the_gate() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment("deployment:\n  profile: production\n")
        .build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    let findings = posture["deployment"]["findings"]
        .as_array()
        .expect("deployment findings is an array");
    assert!(
        !findings.iter().any(|f| f["id"] == "notary.openapi.public"),
        "notary.openapi.public must be absent when openapi_requires_auth = true"
    );
}

#[tokio::test]
async fn config_unsigned_reports_finding_under_hosted_lab() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    // A minimal config has no config_trust block and therefore config_unsigned = true.
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment("deployment:\n  profile: hosted_lab\n")
        .build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    let findings = posture["deployment"]["findings"]
        .as_array()
        .expect("deployment findings is an array");
    let found = findings
        .iter()
        .find(|f| f["id"] == "notary.config.unsigned")
        .expect("notary.config.unsigned present under hosted_lab (no config_trust)");
    assert_eq!(
        found["severity"], "finding_warn",
        "hosted_lab config_unsigned must be finding_warn"
    );
}

#[tokio::test]
async fn config_unsigned_reports_finding_error_under_production() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment("deployment:\n  profile: production\n")
        .build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    let findings = posture["deployment"]["findings"]
        .as_array()
        .expect("deployment findings is an array");
    let found = findings
        .iter()
        .find(|f| f["id"] == "notary.config.unsigned")
        .expect("notary.config.unsigned present under production (no config_trust)");
    assert_eq!(
        found["severity"], "finding_error",
        "production config_unsigned must be finding_error"
    );
}

#[test]
fn evidence_grade_config_unsigned_refuses_startup() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    // evidence_grade + config_unsigned = startup_fail.
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment("deployment:\n  profile: evidence_grade\n")
        .build();

    let error =
        expect_compile_rejected(config, "evidence_grade config_unsigned must refuse startup");
    match error {
        StandaloneServerError::DeploymentGateStartupFailure { profile, findings } => {
            assert_eq!(profile, "evidence_grade");
            assert!(
                findings.contains("notary.config.unsigned"),
                "expected notary.config.unsigned in startup failures: {findings}"
            );
        }
        other => panic!("expected a deployment gate startup failure, got: {other:?}"),
    }
}

#[test]
fn admin_shared_exposure_refuses_startup_under_evidence_grade() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    // fetch_posture sets SharedWithPublic on the compiled config, but here we
    // set it before compile to test the startup gate.
    let mut config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment("deployment:\n  profile: evidence_grade\n")
        .build();
    config.server.admin_listener.mode =
        registry_notary_core::RegistryNotaryAdminListenerMode::SharedWithPublic;

    let error = expect_compile_rejected(
        config,
        "evidence_grade admin_shared_exposure must refuse startup",
    );
    match error {
        StandaloneServerError::DeploymentGateStartupFailure { profile, findings } => {
            assert_eq!(profile, "evidence_grade");
            assert!(
                findings.contains("notary.admin.shared_exposure"),
                "expected notary.admin.shared_exposure in startup failures: {findings}"
            );
        }
        other => panic!("expected a deployment gate startup failure, got: {other:?}"),
    }
}

#[test]
fn admin_dedicated_or_disabled_clears_shared_exposure_gate() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    // Default admin listener mode is Disabled; no admin_shared_exposure.
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment("deployment:\n  profile: evidence_grade\n")
        .build();

    // Evidence grade with config_unsigned is a startup_fail, but we're only
    // checking that admin_shared_exposure is not among the reasons. So we
    // can check via compile that the admin exposure gate is not the trigger.
    // (The test ensures the gate logic for the non-triggering path is exercised
    // end-to-end; config_unsigned startup_fail is a separate gate.)
    let error = expect_compile_rejected(
        config,
        "evidence_grade still refuses due to config_unsigned, not admin_shared_exposure",
    );
    match error {
        StandaloneServerError::DeploymentGateStartupFailure { findings, .. } => {
            assert!(
                !findings.contains("notary.admin.shared_exposure"),
                "notary.admin.shared_exposure must not appear when listener is disabled: {findings}"
            );
        }
        other => panic!("expected a deployment gate startup failure, got: {other:?}"),
    }
}

// Integration tests for notary.audit.retention_local_only: a local file sink
// caps retention and an attacker with host access can destroy it, unless the
// operator attests logs are shipped off-host. stdout and syslog are exempt.

#[tokio::test]
async fn production_file_sink_without_attestation_reports_finding_warn() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment("deployment:\n  profile: production\n")
        .build();

    // Startup is unaffected: finding_warn is not a hard gate.
    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    let findings = posture["deployment"]["findings"]
        .as_array()
        .expect("deployment findings is an array");
    let found = findings
        .iter()
        .find(|f| f["id"] == "notary.audit.retention_local_only")
        .expect("notary.audit.retention_local_only finding present under production");
    assert_eq!(found["severity"], "finding_warn");
    assert_eq!(found["status"], "active");
}

#[tokio::test]
async fn production_file_sink_with_offhost_attestation_is_clean() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment(
            "deployment:\n  profile: production\n  evidence:\n    audit_offhost_shipping: true\n",
        )
        .build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    let findings = posture["deployment"]["findings"]
        .as_array()
        .expect("deployment findings is an array");
    assert!(
        !findings
            .iter()
            .any(|f| f["id"] == "notary.audit.retention_local_only"),
        "attested off-host shipping must clear the gate: {findings:#?}"
    );
}

#[tokio::test]
async fn production_stdout_sink_is_exempt_from_retention_local_only() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .durable_audit(false)
        .deployment("deployment:\n  profile: production\n")
        .build();

    // A stdout sink also triggers notary.audit.sink_missing (not durable),
    // so this exercises compile directly rather than the posture route.
    let error = expect_compile_rejected(config, "stdout sink is not durable under production");
    match error {
        StandaloneServerError::DeploymentGateStartupFailure { findings, .. } => {
            assert!(
                !findings.contains("notary.audit.retention_local_only"),
                "stdout sink must be exempt from retention_local_only: {findings}"
            );
        }
        other => panic!("expected a deployment gate startup failure, got: {other:?}"),
    }
}

#[tokio::test]
async fn production_syslog_sink_is_exempt_from_retention_local_only() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let socket_path = tmp.path().join("audit.sock");
    // Fetching posture emits an audit event through the syslog sink, so a
    // real datagram socket must be listening or the write fails closed.
    let _socket = tokio::net::UnixDatagram::bind(&socket_path).expect("bind syslog socket");
    let config = ConfigBuilder::new(&socket_path.to_string_lossy())
        .audit_sink_kind("syslog")
        .deployment("deployment:\n  profile: production\n")
        .build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    let findings = posture["deployment"]["findings"]
        .as_array()
        .expect("deployment findings is an array");
    assert!(
        !findings
            .iter()
            .any(|f| f["id"] == "notary.audit.retention_local_only"),
        "syslog sink must be exempt from retention_local_only: {findings:#?}"
    );
}

#[test]
fn jsonl_sink_without_attestation_is_startup_gate_binding_under_evidence_grade() {
    // evidence_grade + jsonl sink without attestation is a startup gate. The
    // minimal config also triggers notary.config.unsigned under evidence_grade,
    // so verify the audit gate binding directly.
    use registry_notary_core::deployment::{
        evaluate_gates, DeploymentProfile, GateInput, GateSeverity,
        FINDING_AUDIT_RETENTION_LOCAL_ONLY,
    };
    let input = GateInput {
        audit_sink_class_durable: true,
        audit_retention_local_only: true,
        ..GateInput::default()
    };
    let evaluation = evaluate_gates(
        Some(DeploymentProfile::EvidenceGrade),
        &input,
        &[],
        "2026-06-13",
    );
    let found = evaluation
        .findings
        .iter()
        .find(|f| f.id == FINDING_AUDIT_RETENTION_LOCAL_ONLY)
        .expect("notary.audit.retention_local_only present under evidence_grade");
    assert_eq!(
        found.severity,
        GateSeverity::StartupFail,
        "evidence_grade retention_local_only must be startup_fail"
    );
    assert!(evaluation
        .startup_failures
        .contains(&FINDING_AUDIT_RETENTION_LOCAL_ONLY.to_string()));
    assert!(!evaluation
        .readiness_failures
        .contains(&FINDING_AUDIT_RETENTION_LOCAL_ONLY.to_string()));
}

#[test]
fn evidence_grade_file_sink_without_attestation_refuses_startup() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment("deployment:\n  profile: evidence_grade\n")
        .build();

    let error = match compile_notary_runtime_with_provenance(
        config,
        ConfigSource::SignedBundleFile,
        None,
    ) {
        Ok(_) => panic!("evidence_grade local-only audit retention must refuse startup"),
        Err(error) => error,
    };
    match error {
        StandaloneServerError::DeploymentGateStartupFailure { findings, .. } => assert!(
            findings.contains("notary.audit.retention_local_only"),
            "startup failure must name the audit retention gate: {findings}"
        ),
        other => panic!("expected a deployment gate startup failure, got: {other:?}"),
    }
}

#[test]
fn retention_local_only_waiver_is_honored_under_production() {
    use registry_notary_core::deployment::{
        evaluate_gates, DeploymentFindingStatus, DeploymentProfile, DeploymentWaiverConfig,
        GateInput, FINDING_AUDIT_RETENTION_LOCAL_ONLY,
    };
    let input = GateInput {
        audit_sink_class_durable: true,
        audit_retention_local_only: true,
        ..GateInput::default()
    };
    let waiver = DeploymentWaiverConfig {
        finding: FINDING_AUDIT_RETENTION_LOCAL_ONLY.to_string(),
        reason: "synthetic test waiver, ticket TEST-1".to_string(),
        expires: "2999-01-01".to_string(),
    };
    let evaluation = evaluate_gates(
        Some(DeploymentProfile::Production),
        &input,
        &[waiver],
        "2026-06-13",
    );
    let found = evaluation
        .findings
        .iter()
        .find(|f| f.id == FINDING_AUDIT_RETENTION_LOCAL_ONLY)
        .expect("waived retention_local_only finding present");
    assert_eq!(found.status, DeploymentFindingStatus::Waived);
    assert!(found.waiver.is_some());
}
