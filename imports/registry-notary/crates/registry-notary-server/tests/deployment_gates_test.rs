// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the operator-declared deployment profile gates.
//!
//! These exercise the gate framework end to end: startup failures, readiness
//! failures, posture rendering of the `deployment` and `audit` objects, and
//! waiver behaviour. They build their own minimal config so they stay
//! independent of the broader standalone HTTP test fixtures.

use axum::http::StatusCode;
use axum_test::TestServer;
use registry_notary_core::{
    EvidenceCredentialConfig, RegistryNotaryAdminListenerMode, StandaloneRegistryNotaryConfig,
};
use registry_notary_server::{
    compile_notary_runtime, notary_router_from_runtime, standalone_router, StandaloneServerError,
};
use registry_platform_authcommon::{
    credential_fingerprint_commitment, CredentialCommitmentContext, CredentialFingerprintProvider,
    CredentialFingerprintRef, CredentialProduct, CredentialType,
};
use serde_json::Value;

const AUDIT_SECRET: &str = "0123456789abcdef0123456789abcdef";
// The raw caseworker API-key fingerprint env value and its precomputed
// commitment. The tests here never present the credential (they exercise
// startup, readiness, and posture only), so the pair only needs to load.
const CASEWORKER_KEY_HASH: &str =
    "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51";
const CASEWORKER_COMMITMENT: &str =
    "sha256:6c1874c8df397cc85277166d01625853a21afb53a4cff37e66fc108a0fc8cffb";

fn set_env() {
    // SAFETY: the integration test binary is single-threaded at setup time.
    unsafe {
        std::env::set_var("REGISTRY_NOTARY_GATES_AUDIT_HASH_SECRET", AUDIT_SECRET);
        std::env::set_var("REGISTRY_NOTARY_GATES_SOURCE_TOKEN", "gates-source-token");
    }
}

/// A minimal but complete config skeleton, parameterised by the knobs the gates
/// read: whether the audit sink is durable and a YAML `deployment:` block.
/// Replay storage stays the in-memory default. High-risk replay mode is driven
/// through the operator-declared `deployment.multi_instance` flag, which keeps
/// the fixture small and avoids standing up a full federation config.
struct ConfigBuilder {
    durable_audit: bool,
    audit_path: String,
    deployment_block: String,
}

impl ConfigBuilder {
    fn new(audit_path: &str) -> Self {
        Self {
            durable_audit: true,
            audit_path: audit_path.to_string(),
            deployment_block: String::new(),
        }
    }

    fn durable_audit(mut self, durable: bool) -> Self {
        self.durable_audit = durable;
        self
    }

    fn deployment(mut self, block: &str) -> Self {
        self.deployment_block = block.to_string();
        self
    }

    fn audit_section(&self) -> String {
        if self.durable_audit {
            format!(
                "audit:\n  sink: file\n  path: \"{}\"\n  hash_secret_env: REGISTRY_NOTARY_GATES_AUDIT_HASH_SECRET\n",
                self.audit_path
            )
        } else {
            "audit:\n  sink: stdout\n  hash_secret_env: REGISTRY_NOTARY_GATES_AUDIT_HASH_SECRET\n"
                .to_string()
        }
    }

    fn build(&self) -> StandaloneRegistryNotaryConfig {
        set_env();
        let raw = format!(
            r#"
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: caseworker
      fingerprint:
        provider: env
        name: TEST_GATES_API_KEY_HASH
        commitment: {CASEWORKER_COMMITMENT}
      scopes: [farmer_registry:evidence_verification]
{audit}evidence:
  enabled: true
  service_id: evidence.test
  api_base_url: https://evidence.example.test
  source_connections:
    farmer_registry:
      base_url: "http://127.0.0.1:1"
      allow_insecure_localhost: true
      token_env: REGISTRY_NOTARY_GATES_SOURCE_TOKEN
  claims:
    - id: farmed-land-size
      title: Farmed land size
      version: 2026-05
      subject_type: person
      value:
        type: number
        unit: hectare
      source_bindings:
        farmer:
          connector: registry_data_api
          connection: farmer_registry
          required_scope: farmer_registry:evidence_verification
          dataset: farmer_registry
          entity: farmer
          lookup:
            input: target.id
            field: id
            op: eq
            cardinality: one
          fields:
            total_farmed_area:
              field: total_farmed_area
              type: number
              unit: hectare
              required: true
      rule:
        type: extract
        source: farmer
        field: total_farmed_area
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
{deployment}"#,
            audit = self.audit_section(),
            deployment = self.deployment_block,
        );
        // The caseworker fingerprint env var must resolve at runtime.
        // SAFETY: see set_env.
        unsafe {
            std::env::set_var("TEST_GATES_API_KEY_HASH", CASEWORKER_KEY_HASH);
        }
        serde_norway::from_str(&raw).expect("gates config deserializes")
    }
}

fn env_fingerprint_ref(id: &str, env_name: &str, fingerprint: &str) -> CredentialFingerprintRef {
    CredentialFingerprintRef {
        provider: CredentialFingerprintProvider::Env,
        name: Some(env_name.to_string()),
        path: None,
        commitment: credential_fingerprint_commitment(
            CredentialCommitmentContext {
                product: CredentialProduct::RegistryNotary,
                credential_type: CredentialType::ApiKey,
                credential_id: id,
            },
            fingerprint,
        ),
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
    let app = notary_router_from_runtime(runtime);
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
fn evidence_grade_in_memory_high_risk_refuses_startup() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment("deployment:\n  profile: evidence_grade\n  multi_instance: true\n")
        .build();

    let error = expect_compile_rejected(config, "evidence_grade must refuse startup");
    match error {
        StandaloneServerError::DeploymentGateStartupFailure { profile, findings } => {
            assert_eq!(profile, "evidence_grade");
            assert!(
                findings.contains("notary.replay.in_memory_high_risk"),
                "expected the high-risk replay gate in: {findings}"
            );
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
fn local_profile_binds_no_gates_even_when_high_risk() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .durable_audit(false)
        .deployment("deployment:\n  profile: local\n  multi_instance: true\n")
        .build();

    // local binds no gates, so an in-memory high-risk deployment still starts.
    compile_notary_runtime(config).expect("local profile binds no gates");
}

#[test]
fn undeclared_profile_starts_and_preserves_behaviour() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .durable_audit(false)
        .build();

    // No deployment block: zero gates bound, startup unaffected.
    compile_notary_runtime(config).expect("undeclared profile preserves startup");
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
async fn production_high_risk_replay_reports_readiness_failure() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment("deployment:\n  profile: production\n  multi_instance: true\n")
        .build();
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::SharedWithPublic;

    let app = standalone_router(config).expect("production high-risk config still starts");
    let server = TestServer::builder().http_transport().build(app);
    let ready = server.get("/ready").await;
    // A readiness_fail gate is bound and triggered, so /ready reports not-ready.
    ready.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = ready.json();
    assert_eq!(body["readiness_status"], "not_ready");
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
}

#[tokio::test]
async fn posture_reports_undeclared_profile_finding() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp)).build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    assert!(
        posture["deployment"].get("profile").is_none(),
        "an undeclared profile must not render a profile value"
    );
    let findings = posture["deployment"]["findings"]
        .as_array()
        .expect("deployment findings is an array");
    assert!(
        findings
            .iter()
            .any(|finding| finding["id"] == "deployment.profile_undeclared"),
        "expected deployment.profile_undeclared in: {findings:#?}"
    );
}

#[tokio::test]
async fn posture_reports_waived_finding_with_active_waiver() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment(
            "deployment:\n  profile: hosted_lab\n  multi_instance: true\n  waivers:\n    - finding: notary.replay.in_memory_high_risk\n      reason: \"synthetic single-node lab, ticket TEST-1\"\n      expires: 2999-01-01\n",
        )
        .build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    let findings = posture["deployment"]["findings"]
        .as_array()
        .expect("deployment findings is an array");
    let waived = findings
        .iter()
        .find(|finding| finding["id"] == "notary.replay.in_memory_high_risk")
        .expect("high-risk replay finding is present");
    assert_eq!(waived["status"], "waived");
    assert_eq!(waived["waiver"]["expires"], "2999-01-01");

    let waivers = posture["deployment"]["waivers"]
        .as_array()
        .expect("deployment waivers is an array");
    assert!(
        waivers
            .iter()
            .any(|waiver| waiver["finding"] == "notary.replay.in_memory_high_risk"),
        "active waiver must be echoed in: {waivers:#?}"
    );
}

#[tokio::test]
async fn posture_re_triggers_expired_waiver() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = ConfigBuilder::new(&audit_path(&tmp))
        .deployment(
            "deployment:\n  profile: hosted_lab\n  multi_instance: true\n  waivers:\n    - finding: notary.replay.in_memory_high_risk\n      reason: \"synthetic expired waiver\"\n      expires: 2000-01-01\n",
        )
        .build();

    let posture = fetch_posture(config).await;
    assert_matches_posture_schema(&posture);

    let findings = posture["deployment"]["findings"]
        .as_array()
        .expect("deployment findings is an array");
    let replay = findings
        .iter()
        .find(|finding| finding["id"] == "notary.replay.in_memory_high_risk")
        .expect("high-risk replay finding is present");
    // An expired waiver stops suppressing the finding: it is active again.
    assert_eq!(replay["status"], "active");
    assert!(
        findings
            .iter()
            .any(|finding| finding["id"] == "deployment.waiver_expired"),
        "expected deployment.waiver_expired in: {findings:#?}"
    );
}
