// SPDX-License-Identifier: Apache-2.0
//! Acceptance tests for the deployment profile gate train.
//!
//! The pure gate-evaluation logic (all profiles, undeclared, waiver
//! suppress/expire, per-finding triggering and non-triggering) is covered by
//! unit tests in `src/deployment/mod.rs`, and the posture serialization shape
//! and tier filtering by unit tests in `src/api/admin.rs`. This file covers the
//! wiring that only an integration test can reach:
//!
//! * an invalid profile value fails config parse,
//! * deployment waivers must carry a non-empty reason and a well-formed expiry,
//! * `evidence_grade` from an unsigned local file refuses startup,
//! * the audit write-policy hook behaves under the default `fail_closed`
//!   policy and explicit `availability_first` opt-out, proven with an
//!   injected audit write failure.

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use axum_test::TestServer;
use registry_platform_audit::{AuditChainHasher, AuditEnvelope, AuditError, AuditSink};
use registry_platform_ops::AuditWritePolicy;
use registry_relay::audit::{AuditPipeline, InMemorySink, AUDIT_WRITE_FAILED_CODE};
use registry_relay::auth::api_key::ApiKeyAuth;
use registry_relay::auth::AuthProvider;
use registry_relay::config::{self, Config};
use registry_relay::server::build_app;

/// A sink whose `write` always fails, modelling a durable audit write failure
/// (disk full, sink unreachable). `tail_hash` succeeds with an empty chain so
/// the pipeline reaches the `write` call before failing.
struct AlwaysFailWriteSink;

#[async_trait]
impl AuditSink for AlwaysFailWriteSink {
    async fn write(&self, _envelope: &AuditEnvelope) -> Result<(), AuditError> {
        Err(AuditError::Io(std::io::Error::other(
            "injected audit write failure",
        )))
    }

    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(None)
    }

    async fn tail_hash_with_hasher(
        &self,
        hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        let _ = hasher;
        Ok(None)
    }
}

fn load_example_config() -> Config {
    config::test_support::load_example_config_for_tests("relay-deployment-gates-secret-32-bytes")
}

/// Minimal config used by the parse/validate tests. The admin module's own
/// minimal fixture is private, so this file carries its own copy.
fn minimal_config_yaml() -> String {
    r#"
server:
  bind: "127.0.0.1:8080"
catalog:
  title: "Test Registry"
  base_url: "https://data.example.test"
  publisher: "Test Ministry"
auth:
  mode: api_key
  api_keys: []
audit:
  sink: stdout
datasets: []
"#
    .to_string()
}

fn parse_config(yaml: &str) -> Result<Config, serde_saphyr::Error> {
    serde_saphyr::from_str::<Config>(yaml)
}

// --- config parse / validate ------------------------------------------------

#[test]
fn invalid_profile_value_fails_parse() {
    let yaml = format!(
        "{}\ndeployment:\n  profile: pre_production\n",
        minimal_config_yaml()
    );
    let result = parse_config(&yaml);
    assert!(
        result.is_err(),
        "an undeclared profile value must be rejected at parse time, not silently inferred"
    );
}

#[test]
fn each_declared_profile_value_parses() {
    for profile in ["local", "hosted_lab", "production", "evidence_grade"] {
        let yaml = format!(
            "{}\ndeployment:\n  profile: {profile}\n",
            minimal_config_yaml()
        );
        assert!(
            parse_config(&yaml).is_ok(),
            "profile `{profile}` must parse"
        );
    }
}

#[test]
fn waiver_missing_reason_is_rejected() {
    let yaml = format!(
        "{}\ndeployment:\n  profile: hosted_lab\n  waivers:\n    - finding: relay.config.unsigned\n      reason: \"\"\n      expires: \"2999-01-01\"\n",
        minimal_config_yaml()
    );
    let config = parse_config(&yaml).expect("config parses");
    assert!(
        config::validate::run(&config).is_err(),
        "a waiver with an empty reason must fail validation"
    );
}

#[test]
fn waiver_bad_expiry_is_rejected() {
    let yaml = format!(
        "{}\ndeployment:\n  profile: hosted_lab\n  waivers:\n    - finding: relay.config.unsigned\n      reason: \"synthetic-waiver-not-a-secret\"\n      expires: \"soon\"\n",
        minimal_config_yaml()
    );
    let config = parse_config(&yaml).expect("config parses");
    assert!(
        config::validate::run(&config).is_err(),
        "a waiver with a malformed expiry date must fail validation"
    );
}

#[test]
fn waiver_with_valid_expiry_passes_validation() {
    let yaml = format!(
        "{}\ndeployment:\n  profile: hosted_lab\n  waivers:\n    - finding: relay.config.unsigned\n      reason: \"synthetic-waiver-not-a-secret\"\n      expires: \"2999-01-01\"\n",
        minimal_config_yaml()
    );
    let config = parse_config(&yaml).expect("config parses");
    assert!(
        config::validate::run(&config).is_ok(),
        "a well-formed hosted_lab waiver must pass validation"
    );
}

#[test]
fn evidence_grade_from_local_file_refuses_startup() {
    // `relay.config.unsigned` is `startup_fail` under evidence_grade, and a
    // local YAML file is unsigned, so validation must reject startup. The gate
    // is never waivable, so even a waiver cannot rescue it.
    let yaml = format!(
        "{}\ndeployment:\n  profile: evidence_grade\n  evidence:\n    ingress_rate_limit: true\n    api_key_rotation: true\n",
        minimal_config_yaml()
    );
    let config = parse_config(&yaml).expect("config parses");
    assert!(
        config::validate::run(&config).is_err(),
        "evidence_grade from an unsigned local file must refuse startup"
    );
}

#[test]
fn undeclared_profile_validates_like_before() {
    // The default config declares no profile; validation must pass exactly as
    // it did before the gate train (zero gates bound).
    let config = parse_config(&minimal_config_yaml()).expect("config parses");
    assert!(
        config::validate::run(&config).is_ok(),
        "an undeclared profile must not change validation behavior"
    );
}

#[test]
fn evidence_grade_via_signed_bundle_source_validates_and_boots() {
    // The same evidence_grade config that an unsigned local file rejects must
    // validate and boot when the candidate carries a signed-bundle source: the
    // `relay.config.unsigned` startup gate does not fire for a signed bundle.
    let yaml = format!(
        "{}\ndeployment:\n  profile: evidence_grade\n  evidence:\n    ingress_rate_limit: true\n    api_key_rotation: true\n",
        minimal_config_yaml()
    );
    let config = parse_config(&yaml).expect("config parses");
    // Sanity: the very same config is rejected when treated as a local file.
    assert!(
        config::validate::run_with_source(&config, registry_platform_ops::ConfigSource::LocalFile)
            .is_err(),
        "evidence_grade from a local file must still refuse startup"
    );
    for source in [
        registry_platform_ops::ConfigSource::SignedBundleFile,
        registry_platform_ops::ConfigSource::SignedBundleEndpoint,
    ] {
        config::validate::run_with_source(&config, source).unwrap_or_else(|err| {
            panic!("evidence_grade via {source:?} must validate and boot, got {err:?}")
        });
    }
}

#[test]
fn governed_candidate_apply_accepts_evidence_grade_with_signed_provenance() {
    // The governed apply path threads the candidate's real source into gate
    // evaluation, so an evidence_grade candidate delivered as a signed bundle is
    // accepted (its `relay.config.unsigned` startup gate does not fire).
    let yaml = format!(
        "{}\ndeployment:\n  profile: evidence_grade\n  evidence:\n    ingress_rate_limit: true\n    api_key_rotation: true\n",
        minimal_config_yaml()
    );
    let (_config, provenance) = config::governed::parse_candidate_config_with_provenance(
        &yaml,
        "bundle-evidence-grade",
        1,
        registry_platform_ops::ConfigSource::SignedBundleFile,
    )
    .expect("evidence_grade candidate with signed provenance must apply");
    assert_eq!(
        provenance.source,
        registry_platform_ops::ConfigSource::SignedBundleFile
    );
}

// --- boot audit records for waived gates ------------------------------------

#[tokio::test]
async fn boot_audit_records_waived_gate() {
    let yaml = format!(
        "{}\ndeployment:\n  profile: hosted_lab\n  waivers:\n    - finding: relay.config.unsigned\n      reason: \"synthetic-waiver-not-a-secret\"\n      expires: \"2999-01-01\"\n",
        minimal_config_yaml()
    );
    let config = parse_config(&yaml).expect("config parses");
    let sink = InMemorySink::new();
    let pipeline = AuditPipeline::from_sink(sink.clone());

    registry_relay::server::audit_waived_deployment_gates(
        &config,
        &pipeline,
        registry_platform_ops::ConfigSource::LocalFile,
    )
    .await
    .expect("waived gate audit writes");

    let lines = sink.snapshot();
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one operational audit record: {lines:?}"
    );
    assert!(
        lines[0].contains("/__events/deployment.gate_waived"),
        "expected the waived-gate audit path: {}",
        lines[0]
    );
    assert!(
        lines[0].contains("relay.config.unsigned"),
        "expected the waived gate id in the audit record: {}",
        lines[0]
    );
}

#[tokio::test]
async fn boot_audit_writes_nothing_without_waivers() {
    let yaml = format!("{}\ndeployment:\n  profile: local\n", minimal_config_yaml());
    let config = parse_config(&yaml).expect("config parses");
    let sink = InMemorySink::new();
    let pipeline = AuditPipeline::from_sink(sink.clone());

    registry_relay::server::audit_waived_deployment_gates(
        &config,
        &pipeline,
        registry_platform_ops::ConfigSource::LocalFile,
    )
    .await
    .expect("no waived gates means no audit write failure");

    assert!(
        sink.snapshot().is_empty(),
        "expected no audit records without waived gates"
    );
}

#[tokio::test]
async fn boot_audit_failure_fails_closed_for_waived_gate() {
    let yaml = format!(
        "{}\ndeployment:\n  profile: hosted_lab\n  waivers:\n    - finding: relay.config.unsigned\n      reason: \"synthetic-waiver-not-a-secret\"\n      expires: \"2999-01-01\"\n",
        minimal_config_yaml()
    );
    let config = parse_config(&yaml).expect("config parses");
    assert_eq!(config.audit.write_policy, AuditWritePolicy::FailClosed);
    let pipeline = AuditPipeline::from_sink(AlwaysFailWriteSink);

    let err = registry_relay::server::audit_waived_deployment_gates(
        &config,
        &pipeline,
        registry_platform_ops::ConfigSource::LocalFile,
    )
    .await
    .expect_err("fail_closed must surface waived-gate audit write failure");

    assert!(
        matches!(err, AuditError::Io(_)),
        "expected injected audit write failure, got {err:?}"
    );
}

#[tokio::test]
async fn boot_audit_failure_is_best_effort_when_availability_first() {
    let yaml = format!(
        "{}\ndeployment:\n  profile: hosted_lab\n  waivers:\n    - finding: relay.config.unsigned\n      reason: \"synthetic-waiver-not-a-secret\"\n      expires: \"2999-01-01\"\n",
        minimal_config_yaml()
    );
    let mut config = parse_config(&yaml).expect("config parses");
    config.audit.write_policy = AuditWritePolicy::AvailabilityFirst;
    assert_eq!(
        config.audit.write_policy,
        AuditWritePolicy::AvailabilityFirst
    );
    let pipeline = AuditPipeline::from_sink(AlwaysFailWriteSink);

    registry_relay::server::audit_waived_deployment_gates(
        &config,
        &pipeline,
        registry_platform_ops::ConfigSource::LocalFile,
    )
    .await
    .expect("availability_first keeps waived-gate audit best effort");
}

// --- audit write policy (end to end) ----------------------------------------

/// Under explicit `availability_first` an audit write failure is swallowed:
/// the request keeps its original outcome (here a 401 from the auth layer,
/// since the catalog route is protected and no key is presented).
#[tokio::test]
async fn availability_first_swallows_audit_write_failure() {
    let mut config = load_example_config();
    config.audit.write_policy = AuditWritePolicy::AvailabilityFirst;
    let config = Arc::new(config);
    let auth: Arc<dyn AuthProvider> = Arc::new(ApiKeyAuth::new(Vec::new()));
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(AlwaysFailWriteSink);
    let server = TestServer::new(build_app(config, auth, sink).expect("app builds"));

    let response = server.get("/v1/datasets").await;
    // The audit write fails, but availability_first returns the original
    // response unchanged. It is anything but the fail_closed 503 code.
    assert_ne!(
        response.status_code(),
        StatusCode::SERVICE_UNAVAILABLE,
        "availability_first must not surface the audit write failure"
    );
    let body = response.json::<serde_json::Value>();
    assert_ne!(
        body.get("code").and_then(|c| c.as_str()),
        Some(AUDIT_WRITE_FAILED_CODE),
        "availability_first must not return the fail_closed error code"
    );
}

/// By default, the same injected audit write failure fails the request with the
/// stable `audit.write_failed` code so no outcome is returned without a durable
/// audit record.
#[tokio::test]
async fn default_fail_closed_fails_request_on_audit_write_failure() {
    let config = load_example_config();
    assert_eq!(config.audit.write_policy, AuditWritePolicy::FailClosed);
    let config = Arc::new(config);
    let auth: Arc<dyn AuthProvider> = Arc::new(ApiKeyAuth::new(Vec::new()));
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(AlwaysFailWriteSink);
    let server = TestServer::new(build_app(config, auth, sink).expect("app builds"));

    let response = server.get("/v1/datasets").await;
    assert_eq!(
        response.status_code(),
        StatusCode::SERVICE_UNAVAILABLE,
        "fail_closed must fail the request when the audit record cannot be written"
    );
    let body = response.json::<serde_json::Value>();
    assert_eq!(
        body["code"], AUDIT_WRITE_FAILED_CODE,
        "fail_closed response must carry the stable audit.write_failed code"
    );
    assert_eq!(body["status"], 503);
}

/// A healthy sink under `fail_closed` must NOT fail requests: the policy only
/// bites when the audit write actually fails.
#[tokio::test]
async fn fail_closed_passes_when_audit_write_succeeds() {
    let mut config = load_example_config();
    config.audit.write_policy = AuditWritePolicy::FailClosed;
    let config = Arc::new(config);
    let auth: Arc<dyn AuthProvider> = Arc::new(ApiKeyAuth::new(Vec::new()));
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let server = TestServer::new(build_app(config, auth, sink).expect("app builds"));

    let response = server.get("/v1/datasets").await;
    // The request still 401s at the auth layer (no key), but the point is that
    // fail_closed did not turn a successful audit write into a 503.
    assert_ne!(
        response.status_code(),
        StatusCode::SERVICE_UNAVAILABLE,
        "fail_closed must not fail requests when the audit write succeeds"
    );
    let body = response.json::<serde_json::Value>();
    assert_ne!(
        body.get("code").and_then(|c| c.as_str()),
        Some(AUDIT_WRITE_FAILED_CODE),
        "a successful audit write must not produce the fail_closed code"
    );
}
