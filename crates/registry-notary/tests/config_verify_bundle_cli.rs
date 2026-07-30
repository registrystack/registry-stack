// SPDX-License-Identifier: Apache-2.0
//! Binary-level coverage for config bundle v1 verification.

use std::path::PathBuf;
use std::process::Command;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_config::{
    sha256_uri, ConfigBundleFile, ConfigBundleManifest, ConfigBundleSignature,
    ConfigBundleSignatureEnvelope, ConfigTrustAnchor, ConfigTrustAnchorSigner,
    ProductAcceptanceIdentityV1, ProductAcceptanceLaneV1, ProductAcceptanceProductV1,
    ProductTrustDomainV1,
};
use registry_platform_crypto::{canonicalize_json, sign, PrivateJwk};
use registry_platform_ops::{
    AntiRollbackKey, AntiRollbackRecord, ConfigOverrideMode, ConfigOverridePin,
    FileAntiRollbackStore, BUNDLE_VERIFICATION_CODE_DEFINITIONS,
};
use serde_json::Value;
use tempfile::TempDir;

const PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
const TEST_TOKEN_HASH: &str =
    "sha256:31f2999a69fa6301763a9f61eea44388a13318ce8b80a16a115a9efdb62b883b";
const TEST_AUDIT_HASH_SECRET: &str = "registry-notary-cli-audit-secret-32-bytes";
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const USER_SENTINEL: &str = "redaction-user@example.test";
const COUNTRY_SENTINEL: &str = "REDACTION_COUNTRY_VALUE";
const STREAM_ID: &str = "notary-test-stream";
const BUNDLE_ID: &str = "notary-test-bundle";
const ERROR_MESSAGE_SENTINELS: &[&str] = &[
    USER_SENTINEL,
    COUNTRY_SENTINEL,
    TEST_AUDIT_HASH_SECRET,
    "REDACTION_SECRET_VALUE",
    "REDACTION_PARSER_STRING",
    "REDACTION_LOCAL_PATH",
    "/Users/",
];

struct BundleFixture {
    bundle_dir: PathBuf,
    anchor_path: PathBuf,
    state_path: PathBuf,
    config_path: PathBuf,
    config_hash: String,
    signer_kid: String,
}

#[test]
fn config_verify_bundle_cli_reports_verified_signed_bundle() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-notary", 0);

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = stdout_json(&output);
    assert_eq!(report["result"], "verified");
    assert_eq!(report["component"], "registry-notary");
    assert_eq!(report["stream_id"], STREAM_ID);
    assert_eq!(report["bundle_id"], BUNDLE_ID);
    assert_eq!(report["bundle_sequence"], 1);
    assert_eq!(report["previous_config_hash"], ZERO_HASH);
    assert_eq!(report["config_hash"], fixture.config_hash);
    assert_eq!(report["errors"], serde_json::json!([]));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr is UTF-8"),
        ""
    );
}

#[test]
fn config_verify_bundle_cli_reports_rejected_rollback() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-notary", 2);

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_eq!(report["result"], "rejected_rollback");
    assert_eq!(report["errors"][0]["code"], "rejected_rollback");
    assert_rejected_output_boundary(&output, &report, "rejected_rollback", &fixture, &[]);
}

#[test]
fn config_verify_bundle_cli_rejects_expired_override_pin() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-notary", 2);
    std::fs::write(
        &fixture.state_path,
        serde_json::to_vec_pretty(&AntiRollbackRecord {
            key: AntiRollbackKey {
                acceptance_identity: notary_acceptance_identity(),
            },
            last_sequence: 2,
            last_config_hash:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            last_bundle_manifest_hash:
                "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            last_bundle_id: "preceding-bundle".to_string(),
            accepted_anchor: registry_platform_ops::AcceptedAnchorPinV1::from_trust_anchor(
                &registry_platform_config::load_trust_anchor(&fixture.anchor_path)
                    .expect("anchor loads"),
            )
            .expect("anchor pin derives"),
            override_pin: Some(ConfigOverridePin {
                active: true,
                mode: ConfigOverrideMode::AcceptRollback,
                config_hash: fixture.config_hash.clone(),
                config_path: None,
                expires_at: Some("2026-07-07T10:00:00Z".to_string()),
                used_at: "2026-07-07T09:00:00Z".to_string(),
                operator: USER_SENTINEL.to_string(),
                reason: format!(
                    "{COUNTRY_SENTINEL} REDACTION_SECRET_VALUE REDACTION_PARSER_STRING REDACTION_LOCAL_PATH"
                ),
            }),
            break_glass: Default::default(),
            local_approvals: Default::default(),
        })
        .expect("state serializes"),
    )
    .expect("state writes");

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_eq!(report["result"], "rejected_rollback");
    assert_eq!(report["errors"][0]["code"], "rejected_rollback");
    assert_rejected_output_boundary(&output, &report, "rejected_rollback", &fixture, &[]);
}

#[test]
fn config_verify_bundle_cli_reports_rejected_binding() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-relay", 0);

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_eq!(report["result"], "rejected_binding");
    assert_eq!(report["errors"][0]["code"], "rejected_binding");
    assert_rejected_output_boundary(&output, &report, "rejected_binding", &fixture, &[]);
}

#[test]
fn config_verify_bundle_cli_rejects_missing_instance_binding_value_free() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-notary", 0);
    rewrite_manifest_instance_id(&fixture, None);

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_rejected_output_boundary(&output, &report, "rejected_binding", &fixture, &[]);
    let record = FileAntiRollbackStore::new(&fixture.state_path)
        .load(&AntiRollbackKey {
            acceptance_identity: notary_acceptance_identity(),
        })
        .expect("existing instance lane remains readable");
    assert_eq!(record.last_sequence, 1);
}

#[test]
fn config_verify_bundle_cli_reports_rejected_signature_for_hash_mismatch() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-notary", 0);
    let changed = b"changed config bytes";
    let actual_hash = sha256_uri(changed);
    std::fs::write(&fixture.config_path, changed).expect("config changes");

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_eq!(report["result"], "rejected_signature");
    assert_eq!(report["errors"][0]["code"], "rejected_signature");
    assert_rejected_output_boundary(
        &output,
        &report,
        "rejected_signature",
        &fixture,
        &[
            "config/notary.yaml",
            fixture.config_hash.as_str(),
            actual_hash.as_str(),
            fixture.config_path.to_str().expect("path is UTF-8"),
        ],
    );
}

#[test]
fn config_verify_bundle_cli_malformed_anchor_has_value_free_stdout_and_stderr() {
    let temp = TempDir::new().expect("tempdir");
    let mut fixture = write_bundle_fixture(&temp, "registry-notary", 0);
    let private_dir = temp
        .path()
        .join(format!("REDACTION_LOCAL_PATH-{USER_SENTINEL}"));
    std::fs::create_dir_all(&private_dir).expect("private anchor dir");
    fixture.anchor_path = private_dir.join(format!("{COUNTRY_SENTINEL}-anchor.json"));
    std::fs::write(
        &fixture.anchor_path,
        "{\"secret\":\"REDACTION_SECRET_VALUE\",\"parser\":[\"REDACTION_PARSER_STRING\"",
    )
    .expect("malformed anchor writes");

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_rejected_output_boundary(
        &output,
        &report,
        "rejected_validation",
        &fixture,
        &[fixture.anchor_path.to_str().expect("path is UTF-8")],
    );
}

#[test]
fn config_verify_bundle_cli_file_closure_has_value_free_stdout_and_stderr() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-notary", 0);
    let unexpected_path = fixture
        .bundle_dir
        .join("config")
        .join(format!("{COUNTRY_SENTINEL}-REDACTION_SECRET_VALUE.yaml"));
    std::fs::write(
        &unexpected_path,
        format!("{USER_SENTINEL} REDACTION_PARSER_STRING"),
    )
    .expect("unexpected bundle file writes");

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_rejected_output_boundary(
        &output,
        &report,
        "rejected_signature",
        &fixture,
        &[unexpected_path.to_str().expect("path is UTF-8")],
    );
}

#[test]
fn config_verify_bundle_cli_config_parser_failure_has_value_free_stdout_and_stderr() {
    let temp = TempDir::new().expect("tempdir");
    let malformed_config = format!(
        "country: {COUNTRY_SENTINEL}\nsecret: [REDACTION_SECRET_VALUE\nparser: REDACTION_PARSER_STRING\nuser: {USER_SENTINEL}\n"
    );
    let fixture =
        write_bundle_fixture_with_config(&temp, "registry-notary", 0, malformed_config.clone());

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_rejected_output_boundary(
        &output,
        &report,
        "rejected_validation",
        &fixture,
        &[malformed_config.as_str()],
    );
}

#[test]
fn config_verify_bundle_cli_non_utf8_config_has_value_free_stdout_and_stderr() {
    let temp = TempDir::new().expect("tempdir");
    let mut fixture = write_bundle_fixture(&temp, "registry-notary", 0);
    let invalid_utf8 = b"\xffREDACTION_SECRET_VALUE REDACTION_PARSER_STRING";
    resign_config_bytes(&mut fixture, invalid_utf8);

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_rejected_output_boundary(
        &output,
        &report,
        "rejected_validation",
        &fixture,
        &["REDACTION_SECRET_VALUE", "REDACTION_PARSER_STRING"],
    );
}

#[test]
fn config_verify_bundle_cli_shared_parity_matrix() {
    let cases = [
        (
            "valid_signed_bundle",
            "registry-notary",
            0,
            false,
            true,
            "verified",
        ),
        (
            "rollback",
            "registry-notary",
            2,
            false,
            false,
            "rejected_rollback",
        ),
        (
            "binding_mismatch",
            "registry-relay",
            0,
            false,
            false,
            "rejected_binding",
        ),
        (
            "hash_mismatch",
            "registry-notary",
            0,
            true,
            false,
            "rejected_signature",
        ),
    ];

    for (name, manifest_product, last_sequence, change_config, should_succeed, expected) in cases {
        let temp = TempDir::new().expect(name);
        let fixture = write_bundle_fixture(&temp, manifest_product, last_sequence);
        if change_config {
            std::fs::write(&fixture.config_path, b"changed config bytes").expect(name);
        }

        let output = verify_bundle_command(&fixture).output().expect(name);

        assert_eq!(
            output.status.success(),
            should_succeed,
            "{name} stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report = stdout_json(&output);
        assert_eq!(report["result"], expected, "{name}");
        if should_succeed {
            assert_eq!(report["component"], "registry-notary", "{name}");
        } else {
            assert_eq!(report["errors"][0]["code"], expected, "{name}");
            assert_rejected_output_boundary(&output, &report, expected, &fixture, &[]);
        }
    }
}

#[test]
fn config_verify_bundle_cli_runs_deployment_gates() {
    let temp = TempDir::new().expect("tempdir");
    let config = notary_config_yaml().replace("  profile: local", "  profile: evidence_grade");
    let fixture = write_bundle_fixture_with_config(&temp, "registry-notary", 0, config);

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_eq!(report["result"], "rejected_validation");
    assert_eq!(report["errors"][0]["code"], "rejected_validation");
    assert_rejected_output_boundary(
        &output,
        &report,
        "rejected_validation",
        &fixture,
        &["notary.audit.sink_missing"],
    );
}

#[test]
fn config_verify_bundle_cli_rejects_governed_shared_admin_listener() {
    let temp = TempDir::new().expect("tempdir");
    let config = notary_config_yaml().replace(
        "server:\n  bind: 127.0.0.1:0\n  admin_listener:\n    mode: dedicated\n    bind: 127.0.0.1:1\n",
        "server:\n  bind: 127.0.0.1:0\n  admin_listener:\n    mode: shared_with_public\n",
    );
    let fixture = write_bundle_fixture_with_config(&temp, "registry-notary", 0, config);

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_eq!(report["result"], "rejected_validation");
    assert_eq!(report["errors"][0]["code"], "rejected_validation");
    assert_rejected_output_boundary(
        &output,
        &report,
        "rejected_validation",
        &fixture,
        &["server.admin_listener.mode = dedicated"],
    );
}

fn bundle_code_definition(
    expected_code: &str,
) -> &'static registry_platform_ops::BundleVerificationCodeDefinition {
    BUNDLE_VERIFICATION_CODE_DEFINITIONS
        .iter()
        .find(|definition| definition.code.as_str() == expected_code)
        .expect("published code has a catalog definition")
}

fn assert_rejected_output_boundary(
    output: &std::process::Output,
    report: &Value,
    expected_code: &str,
    fixture: &BundleFixture,
    extra_sentinels: &[&str],
) {
    assert_eq!(report["result"], expected_code);
    assert_eq!(report["errors"][0]["code"], expected_code);
    let definition = bundle_code_definition(expected_code);
    assert_eq!(
        report["errors"][0]["message"], definition.safe_report_message,
        "public message must be the reviewed static catalog meaning and remediation"
    );
    assert_eq!(report["stream_id"], "unknown");
    for field in [
        "bundle_id",
        "bundle_sequence",
        "previous_config_hash",
        "config_hash",
    ] {
        assert_eq!(
            report[field],
            Value::Null,
            "rejected report must not publish manifest-derived {field}"
        );
    }
    let stderr = String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8");
    assert_eq!(
        stderr,
        format!(
            "ERROR {expected_code}: {}\n",
            definition.safe_report_message
        ),
        "child stderr must contain only the stable catalog failure"
    );
    let full_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for sentinel in ERROR_MESSAGE_SENTINELS
        .iter()
        .copied()
        .chain([
            STREAM_ID,
            BUNDLE_ID,
            ZERO_HASH,
            fixture.config_hash.as_str(),
            fixture.signer_kid.as_str(),
            fixture.config_path.to_str().expect("path is UTF-8"),
            fixture.bundle_dir.to_str().expect("path is UTF-8"),
            fixture.state_path.to_str().expect("path is UTF-8"),
        ])
        .chain(extra_sentinels.iter().copied())
    {
        assert!(
            !full_output.contains(sentinel),
            "rejected command leaked sentinel {sentinel:?}: {full_output}"
        );
    }
}

fn verify_bundle_command(fixture: &BundleFixture) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-notary"));
    command.args([
        "config",
        "verify-bundle",
        "--bundle-dir",
        fixture.bundle_dir.to_str().expect("path is UTF-8"),
        "--anchor-path",
        fixture.anchor_path.to_str().expect("path is UTF-8"),
        "--state-path",
        fixture.state_path.to_str().expect("path is UTF-8"),
    ]);
    command.env("TEST_TOKEN_HASH", TEST_TOKEN_HASH);
    command.env("TEST_AUDIT_HASH_SECRET", TEST_AUDIT_HASH_SECRET);
    command.env("ISSUER_KEY", PRIVATE_JWK);
    command
}

fn write_bundle_fixture(
    temp: &TempDir,
    manifest_product: &str,
    last_sequence: u64,
) -> BundleFixture {
    write_bundle_fixture_with_config(temp, manifest_product, last_sequence, notary_config_yaml())
}

fn notary_acceptance_identity() -> ProductAcceptanceIdentityV1 {
    ProductAcceptanceIdentityV1 {
        trust_domain: ProductTrustDomainV1::Governed,
        project: "notary-cli-project".to_string(),
        environment: "development".to_string(),
        lane: ProductAcceptanceLaneV1::Notary,
        product: ProductAcceptanceProductV1::RegistryNotary,
        stream: STREAM_ID.to_string(),
        instance: "notary-cli".to_string(),
    }
}

fn acceptance_identity_for_product(product: &str) -> ProductAcceptanceIdentityV1 {
    let mut identity = notary_acceptance_identity();
    if product == "registry-relay" {
        identity.lane = ProductAcceptanceLaneV1::RelayConsultation;
        identity.product = ProductAcceptanceProductV1::RegistryRelay;
    } else {
        assert_eq!(product, "registry-notary");
    }
    identity
}

fn write_bundle_fixture_with_config(
    temp: &TempDir,
    manifest_product: &str,
    last_sequence: u64,
    config: String,
) -> BundleFixture {
    let bundle_dir = temp.path().join("bundle");
    let config_dir = bundle_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("bundle config dir");
    let config_path = config_dir.join("notary.yaml");
    std::fs::write(&config_path, config.as_bytes()).expect("config writes");
    let config_hash = sha256_uri(config.as_bytes());

    let private = PrivateJwk::parse(PRIVATE_JWK).expect("private JWK parses");
    let public = private.public();
    let kid = public.jkt().expect("thumbprint computes");
    let manifest = ConfigBundleManifest {
        schema: "registry.platform.config_bundle.v1".to_string(),
        acceptance_identity: acceptance_identity_for_product(manifest_product),
        bundle_id: BUNDLE_ID.to_string(),
        sequence: 1,
        previous_config_hash: Some(ZERO_HASH.to_string()),
        config_hash: config_hash.clone(),
        files: vec![ConfigBundleFile {
            path: "config/notary.yaml".to_string(),
            sha256: config_hash.clone(),
        }],
        created_at: "2026-07-07T10:00:00Z".to_string(),
    };
    write_manifest_and_signature(&bundle_dir, &manifest, &private, &kid);

    let anchor = ConfigTrustAnchor {
        schema: "registry.platform.config_trust_anchor.v1".to_string(),
        acceptance_identity: acceptance_identity_for_product(manifest_product),
        version: 1,
        threshold: 1,
        enabled_signers: vec![ConfigTrustAnchorSigner {
            kid: kid.clone(),
            jwk: public,
        }],
    };
    let anchor_path = temp.path().join("trust_anchor.json");
    std::fs::write(
        &anchor_path,
        serde_json::to_vec_pretty(&anchor).expect("anchor serializes"),
    )
    .expect("anchor writes");

    let state_path = temp.path().join("antirollback.json");
    let verified = registry_platform_config::verify_config_bundle(&bundle_dir, &anchor_path)
        .expect("fixture bundle verifies");
    let accepted_anchor =
        registry_platform_ops::AcceptedAnchorPinV1::from_trust_anchor(&verified.trust_anchor)
            .expect("anchor pin derives");
    let state = AntiRollbackRecord {
        key: AntiRollbackKey {
            acceptance_identity: notary_acceptance_identity(),
        },
        last_sequence: if last_sequence == 0 {
            manifest.sequence
        } else {
            last_sequence
        },
        last_config_hash: if last_sequence == 0 {
            config_hash.clone()
        } else {
            "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string()
        },
        last_bundle_manifest_hash: if last_sequence == 0 {
            verified.manifest_hash
        } else {
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_string()
        },
        last_bundle_id: if last_sequence == 0 {
            BUNDLE_ID.to_string()
        } else {
            "preceding-bundle".to_string()
        },
        accepted_anchor,
        override_pin: None,
        break_glass: Default::default(),
        local_approvals: Default::default(),
    };
    std::fs::write(
        &state_path,
        serde_json::to_vec_pretty(&state).expect("state serializes"),
    )
    .expect("pre-existing state writes");

    BundleFixture {
        bundle_dir,
        anchor_path,
        state_path,
        config_path,
        config_hash,
        signer_kid: kid,
    }
}

fn rewrite_manifest_instance_id(fixture: &BundleFixture, instance_id: Option<&str>) {
    let manifest_path = fixture.bundle_dir.join("manifest.json");
    let mut manifest: ConfigBundleManifest =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("manifest reads"))
            .expect("manifest parses");
    manifest.acceptance_identity.instance = instance_id.unwrap_or_default().to_string();
    let private = PrivateJwk::parse(PRIVATE_JWK).expect("private JWK parses");
    write_manifest_and_signature(
        &fixture.bundle_dir,
        &manifest,
        &private,
        &fixture.signer_kid,
    );
}

fn resign_config_bytes(fixture: &mut BundleFixture, config_bytes: &[u8]) {
    std::fs::write(&fixture.config_path, config_bytes).expect("config bytes write");
    let config_hash = sha256_uri(config_bytes);
    let manifest_path = fixture.bundle_dir.join("manifest.json");
    let mut manifest: ConfigBundleManifest =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("manifest reads"))
            .expect("manifest parses");
    manifest.config_hash = config_hash.clone();
    manifest.files[0].sha256 = config_hash.clone();
    let private = PrivateJwk::parse(PRIVATE_JWK).expect("private JWK parses");
    write_manifest_and_signature(
        &fixture.bundle_dir,
        &manifest,
        &private,
        &fixture.signer_kid,
    );
    let verified =
        registry_platform_config::verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect("resigned bundle verifies");
    let key = AntiRollbackKey {
        acceptance_identity: notary_acceptance_identity(),
    };
    let mut record = FileAntiRollbackStore::new(&fixture.state_path)
        .load(&key)
        .expect("acceptance state loads");
    record.last_config_hash = config_hash.clone();
    record.last_bundle_manifest_hash = verified.manifest_hash;
    record.last_bundle_id = verified.manifest.bundle_id;
    std::fs::write(
        &fixture.state_path,
        serde_json::to_vec_pretty(&record).expect("updated state serializes"),
    )
    .expect("updated state writes");
    fixture.config_hash = config_hash;
}

fn write_manifest_and_signature(
    bundle_dir: &std::path::Path,
    manifest: &ConfigBundleManifest,
    private: &PrivateJwk,
    kid: &str,
) {
    let manifest_value = serde_json::to_value(manifest).expect("manifest value");
    let canonical = canonicalize_json(&manifest_value).expect("canonical manifest");
    let signature = sign(&canonical, private).expect("manifest signs");
    let envelope = ConfigBundleSignatureEnvelope {
        schema: "registry.platform.config_bundle_signatures.v1".to_string(),
        signatures: vec![ConfigBundleSignature {
            kid: kid.to_string(),
            alg: "EdDSA".to_string(),
            sig: URL_SAFE_NO_PAD.encode(signature),
        }],
    };
    std::fs::write(
        bundle_dir.join("manifest.json"),
        serde_json::to_vec_pretty(manifest).expect("manifest serializes"),
    )
    .expect("manifest writes");
    std::fs::write(
        bundle_dir.join("manifest.sig.json"),
        serde_json::to_vec_pretty(&envelope).expect("signature serializes"),
    )
    .expect("signature writes");
}

fn stdout_json(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not JSON: {error}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn notary_config_yaml() -> String {
    r#"
instance:
  id: notary-cli
  environment: development
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
  admin_listener:
    mode: dedicated
    bind: 127.0.0.1:1
auth:
  api_keys:
    - id: test-key
      fingerprint:
        provider: env
        name: TEST_TOKEN_HASH
audit:
  sink: stdout
  hash_secret_env: TEST_AUDIT_HASH_SECRET
evidence:
  enabled: true
  signing_keys:
    issuer-key:
      provider: local_jwk_env
      private_jwk_env: ISSUER_KEY
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
"#
    .to_string()
}
