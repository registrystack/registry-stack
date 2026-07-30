// SPDX-License-Identifier: Apache-2.0
//! CLI coverage for config bundle v1 verification.

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
    AcceptedAnchorPinV1, AntiRollbackKey, AntiRollbackRecord, ConfigOverrideMode,
    ConfigOverridePin, FileAntiRollbackStore, BUNDLE_VERIFICATION_CODE_DEFINITIONS,
};
use serde_json::Value;
use tempfile::TempDir;

const PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const VALIDATION_SENTINEL_PATH: &str = "REDACTION_COUNTRY_VALUE/redaction-user@example.test/REDACTION_SECRET_VALUE/REDACTION_PARSER_STRING/REDACTION_LOCAL_PATH.yaml";
const ERROR_MESSAGE_SENTINELS: &[&str] = &[
    "REDACTION_COUNTRY_VALUE",
    "redaction-user@example.test",
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
}

fn fixture_antirollback_key() -> AntiRollbackKey {
    AntiRollbackKey {
        acceptance_identity: ProductAcceptanceIdentityV1 {
            trust_domain: ProductTrustDomainV1::Governed,
            project: "relay-test-project".to_string(),
            environment: "lab".to_string(),
            lane: ProductAcceptanceLaneV1::RelayPublic,
            product: ProductAcceptanceProductV1::RegistryRelay,
            stream: "relay-test-stream".to_string(),
            instance: "relay-lab".to_string(),
        },
    }
}

fn fixture_anchor_pin(fixture: &BundleFixture) -> AcceptedAnchorPinV1 {
    let anchor = registry_platform_config::load_trust_anchor(&fixture.anchor_path)
        .expect("fixture anchor loads");
    AcceptedAnchorPinV1::from_trust_anchor(&anchor).expect("fixture anchor pin")
}

#[test]
fn config_verify_bundle_cli_reports_verified_signed_bundle() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-relay", 0);

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
    assert_eq!(report["component"], "registry-relay");
    assert_eq!(report["stream_id"], "relay-test-stream");
    assert_eq!(report["bundle_id"], "relay-test-bundle");
    assert_eq!(report["bundle_sequence"], 1);
    assert_eq!(report["config_hash"], fixture.config_hash);
}

#[test]
fn config_verify_bundle_cli_reports_rejected_rollback() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-relay", 2);

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_eq!(report["result"], "rejected_rollback");
    assert_eq!(report["errors"][0]["code"], "rejected_rollback");
    assert_safe_bundle_error(&report, "rejected_rollback");
    assert_rejected_identity_is_redacted(&report);
    assert_output_excludes(
        &output,
        &[
            "relay-test-stream",
            "relay-test-bundle",
            fixture.config_hash.as_str(),
            fixture.state_path.to_str().expect("path is UTF-8"),
        ],
    );
}

#[test]
fn config_verify_bundle_cli_rejects_expired_override_pin() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-relay", 2);
    std::fs::write(
        &fixture.state_path,
        serde_json::to_vec_pretty(&AntiRollbackRecord {
            key: fixture_antirollback_key(),
            last_sequence: 2,
            last_config_hash:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            last_bundle_manifest_hash: ZERO_HASH.to_string(),
            last_bundle_id: "previous-bundle".to_string(),
            accepted_anchor: fixture_anchor_pin(&fixture),
            override_pin: Some(ConfigOverridePin {
                active: true,
                mode: ConfigOverrideMode::AcceptRollback,
                config_hash: fixture.config_hash.clone(),
                config_path: None,
                expires_at: Some("2026-07-07T10:00:00Z".to_string()),
                used_at: "2026-07-07T09:00:00Z".to_string(),
                operator: "jeremi".to_string(),
                reason: "expired rollback".to_string(),
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
    assert_safe_bundle_error(&report, "rejected_rollback");
    assert_rejected_identity_is_redacted(&report);
    assert_output_excludes(
        &output,
        &[
            "jeremi",
            "expired rollback",
            "relay-test-stream",
            "relay-test-bundle",
            fixture.config_hash.as_str(),
            fixture.state_path.to_str().expect("path is UTF-8"),
        ],
    );
}

#[test]
fn config_verify_bundle_cli_reports_rejected_binding() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-notary", 0);

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_eq!(report["result"], "rejected_binding");
    assert_eq!(report["errors"][0]["code"], "rejected_binding");
    assert_safe_bundle_error(&report, "rejected_binding");
    assert_rejected_identity_is_redacted(&report);
    assert_output_excludes(
        &output,
        &[
            "relay-test-stream",
            "relay-test-bundle",
            fixture.config_hash.as_str(),
        ],
    );
}

#[test]
fn config_verify_bundle_cli_rejects_missing_instance_binding_value_free() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-relay", 0);
    rewrite_manifest_instance_id(&fixture, None);

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_safe_bundle_error(&report, "rejected_binding");
    assert_rejected_identity_is_redacted(&report);
    assert_output_excludes(
        &output,
        &[
            "relay-test-stream",
            "relay-test-bundle",
            fixture.config_hash.as_str(),
            fixture.state_path.to_str().expect("path is UTF-8"),
        ],
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("relay.startup.bundle_binding_rejected")
    );
    let record = FileAntiRollbackStore::new(&fixture.state_path)
        .load(&fixture_antirollback_key())
        .expect("existing instance lane remains readable");
    assert_eq!(record.last_sequence, 1);
}

#[test]
fn config_verify_bundle_cli_reports_rejected_signature_for_hash_mismatch() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-relay", 0);
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
    assert_safe_bundle_error(&report, "rejected_signature");
    assert_error_message_excludes(
        &report,
        &[
            "config/relay.yaml",
            fixture.config_hash.as_str(),
            actual_hash.as_str(),
            fixture.config_path.to_str().expect("path is UTF-8"),
        ],
    );
    assert_rejected_identity_is_redacted(&report);
    assert_output_excludes(
        &output,
        &[
            fixture.config_hash.as_str(),
            actual_hash.as_str(),
            fixture.config_path.to_str().expect("path is UTF-8"),
        ],
    );
}

#[test]
fn config_verify_bundle_cli_shared_parity_matrix() {
    let cases = [
        (
            "valid_signed_bundle",
            "registry-relay",
            0,
            false,
            true,
            "verified",
        ),
        (
            "rollback",
            "registry-relay",
            2,
            false,
            false,
            "rejected_rollback",
        ),
        (
            "binding_mismatch",
            "registry-notary",
            0,
            false,
            false,
            "rejected_binding",
        ),
        (
            "hash_mismatch",
            "registry-relay",
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
            assert_eq!(report["component"], "registry-relay", "{name}");
        } else {
            assert_eq!(report["errors"][0]["code"], expected, "{name}");
            assert_safe_bundle_error(&report, expected);
            assert_rejected_identity_is_redacted(&report);
        }
    }
}

#[test]
fn config_verify_bundle_cli_rejects_missing_split_metadata() {
    let temp = TempDir::new().expect("tempdir");
    let config = relay_config_yaml().replace(
        "catalog:\n",
        &format!("metadata:\n  source:\n    path: {VALIDATION_SENTINEL_PATH}\ncatalog:\n"),
    );
    let fixture = write_bundle_fixture_with_config(&temp, "registry-relay", 0, config);

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_eq!(report["result"], "rejected_validation");
    assert_eq!(report["errors"][0]["code"], "rejected_validation");
    assert_safe_bundle_error(&report, "rejected_validation");
    assert_error_message_excludes(
        &report,
        &[fixture.config_path.to_str().expect("path is UTF-8")],
    );
    assert_rejected_identity_is_redacted(&report);
    assert_output_excludes(&output, ERROR_MESSAGE_SENTINELS);
}

#[test]
fn config_verify_bundle_cli_requires_signed_metadata_digest() {
    let temp = TempDir::new().expect("tempdir");
    let config = relay_config_yaml().replace(
        "catalog:\n",
        "metadata:\n  source:\n    path: ../metadata.yaml\ncatalog:\n",
    );
    let fixture = write_bundle_fixture_with_extra_files(
        &temp,
        "registry-relay",
        0,
        config,
        vec![(
            "metadata.yaml".to_string(),
            metadata_manifest_yaml().into_bytes(),
        )],
    );

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_eq!(report["result"], "rejected_validation");
    assert_eq!(report["errors"][0]["code"], "rejected_validation");
    assert_safe_bundle_error(&report, "rejected_validation");
    assert_rejected_identity_is_redacted(&report);
}

#[test]
fn config_verify_bundle_cli_redacts_malformed_anchor_from_stdout_and_stderr() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-relay", 0);
    let sentinel = "COUNTRY_PARSER_ERROR redaction-user@example.test /COUNTRY/private/anchor.json";
    std::fs::write(&fixture.anchor_path, format!("{{ {sentinel}")).expect("anchor corrupts");

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_safe_bundle_error(&report, "rejected_validation");
    assert_rejected_identity_is_redacted(&report);
    assert_output_excludes(
        &output,
        &[
            sentinel,
            "redaction-user@example.test",
            "/COUNTRY/private/anchor.json",
            fixture.anchor_path.to_str().expect("path is UTF-8"),
        ],
    );
}

#[test]
fn config_verify_bundle_cli_redacts_file_closure_from_stdout_and_stderr() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-relay", 0);
    let unlisted = fixture
        .bundle_dir
        .join("COUNTRY_PRIVATE_REDACTION_SENTINEL.yaml");
    std::fs::write(&unlisted, "country: COUNTRY_VALUE").expect("unlisted file writes");

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_safe_bundle_error(&report, "rejected_signature");
    assert_rejected_identity_is_redacted(&report);
    assert_output_excludes(
        &output,
        &[
            "COUNTRY_PRIVATE_REDACTION_SENTINEL",
            "COUNTRY_VALUE",
            unlisted.to_str().expect("path is UTF-8"),
        ],
    );
}

#[test]
fn config_verify_bundle_cli_redacts_bundle_parser_sentinel_from_stdout_and_stderr() {
    let temp = TempDir::new().expect("tempdir");
    let parser_sentinel =
        "COUNTRY_PARSER_ERROR redaction-user@example.test /COUNTRY/private/config.yaml";
    let fixture = write_bundle_fixture_with_config(
        &temp,
        "registry-relay",
        0,
        format!("deployment:\n  profile: local\n{parser_sentinel}\n\t- invalid"),
    );

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_safe_bundle_error(&report, "rejected_validation");
    assert_rejected_identity_is_redacted(&report);
    assert_output_excludes(
        &output,
        &[
            parser_sentinel,
            "COUNTRY_PARSER_ERROR",
            "redaction-user@example.test",
            "/COUNTRY/private/config.yaml",
        ],
    );
}

fn assert_safe_bundle_error(report: &Value, expected_code: &str) {
    assert_eq!(report["result"], expected_code);
    assert_eq!(report["errors"][0]["code"], expected_code);
    let definition = BUNDLE_VERIFICATION_CODE_DEFINITIONS
        .iter()
        .find(|definition| definition.code.as_str() == expected_code)
        .expect("published code has a catalog definition");
    assert_eq!(
        report["errors"][0]["message"], definition.safe_report_message,
        "public message must be the reviewed static catalog meaning and remediation"
    );
    assert_error_message_excludes(report, ERROR_MESSAGE_SENTINELS);
}

fn assert_error_message_excludes(report: &Value, sentinels: &[&str]) {
    let message = report["errors"][0]["message"]
        .as_str()
        .expect("error message is a string");
    for sentinel in sentinels {
        assert!(
            !message.contains(sentinel),
            "public error message leaked sentinel {sentinel:?}: {message:?}"
        );
    }
}

fn assert_rejected_identity_is_redacted(report: &Value) {
    for field in [
        "stream_id",
        "bundle_id",
        "bundle_sequence",
        "previous_config_hash",
        "config_hash",
    ] {
        assert!(
            report[field].is_null(),
            "rejected report leaked untrusted identity field {field}: {}",
            report[field]
        );
    }
    let object = report.as_object().expect("report is an object");
    for field in ["signer_kids", "signers", "operator", "operator_id"] {
        assert!(
            object.get(field).is_none_or(Value::is_null),
            "rejected report leaked untrusted identity field {field}"
        );
    }
}

fn assert_output_excludes(output: &std::process::Output, sentinels: &[&str]) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for sentinel in sentinels {
        assert!(
            !stdout.contains(sentinel),
            "stdout leaked sentinel {sentinel:?}: {stdout}"
        );
        assert!(
            !stderr.contains(sentinel),
            "stderr leaked sentinel {sentinel:?}: {stderr}"
        );
    }
    assert!(
        stderr.contains("relay.startup."),
        "stderr must contain a stable Relay startup code: {stderr}"
    );
}

fn verify_bundle_command(fixture: &BundleFixture) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-relay"));
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
    command
}

fn write_bundle_fixture(
    temp: &TempDir,
    manifest_product: &str,
    last_sequence: u64,
) -> BundleFixture {
    write_bundle_fixture_with_config(temp, manifest_product, last_sequence, relay_config_yaml())
}

fn write_bundle_fixture_with_config(
    temp: &TempDir,
    manifest_product: &str,
    last_sequence: u64,
    config: String,
) -> BundleFixture {
    write_bundle_fixture_with_extra_files(temp, manifest_product, last_sequence, config, Vec::new())
}

fn write_bundle_fixture_with_extra_files(
    temp: &TempDir,
    manifest_product: &str,
    last_sequence: u64,
    config: String,
    extra_files: Vec<(String, Vec<u8>)>,
) -> BundleFixture {
    let bundle_dir = temp.path().join("bundle");
    let config_dir = bundle_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("bundle config dir");
    let config_path = config_dir.join("relay.yaml");
    std::fs::write(&config_path, config.as_bytes()).expect("config writes");
    let config_hash = sha256_uri(config.as_bytes());
    let mut files = vec![ConfigBundleFile {
        path: "config/relay.yaml".to_string(),
        sha256: config_hash.clone(),
    }];
    for (path, bytes) in extra_files {
        let full_path = bundle_dir.join(&path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent).expect("extra file parent");
        }
        std::fs::write(&full_path, &bytes).expect("extra file writes");
        files.push(ConfigBundleFile {
            path,
            sha256: sha256_uri(&bytes),
        });
    }

    let private = PrivateJwk::parse(PRIVATE_JWK).expect("private JWK parses");
    let public = private.public();
    let kid = public.jkt().expect("thumbprint computes");
    let (lane, product) = if manifest_product == "registry-relay" {
        (
            ProductAcceptanceLaneV1::RelayPublic,
            ProductAcceptanceProductV1::RegistryRelay,
        )
    } else {
        (
            ProductAcceptanceLaneV1::Notary,
            ProductAcceptanceProductV1::RegistryNotary,
        )
    };
    let acceptance_identity = ProductAcceptanceIdentityV1 {
        trust_domain: ProductTrustDomainV1::Governed,
        project: "relay-test-project".to_string(),
        environment: "lab".to_string(),
        lane,
        product,
        stream: "relay-test-stream".to_string(),
        instance: "relay-lab".to_string(),
    };
    let manifest = ConfigBundleManifest {
        schema: "registry.platform.config_bundle.v1".to_string(),
        acceptance_identity: acceptance_identity.clone(),
        bundle_id: "relay-test-bundle".to_string(),
        sequence: 1,
        previous_config_hash: Some(ZERO_HASH.to_string()),
        config_hash: config_hash.clone(),
        files,
        created_at: "2026-07-07T10:00:00Z".to_string(),
    };
    write_manifest_and_signature(&bundle_dir, &manifest, &private, &kid);

    let anchor = ConfigTrustAnchor {
        schema: "registry.platform.config_trust_anchor.v1".to_string(),
        acceptance_identity,
        version: 1,
        threshold: 1,
        enabled_signers: vec![ConfigTrustAnchorSigner { kid, jwk: public }],
    };
    let anchor_path = temp.path().join("trust_anchor.json");
    std::fs::write(
        &anchor_path,
        serde_json::to_vec_pretty(&anchor).expect("anchor serializes"),
    )
    .expect("anchor writes");

    let state_path = temp.path().join("antirollback.json");
    let manifest_hash = sha256_uri(
        &canonicalize_json(&serde_json::to_value(&manifest).expect("manifest value"))
            .expect("manifest canonicalizes"),
    );
    std::fs::write(
        &state_path,
        serde_json::to_vec_pretty(&AntiRollbackRecord {
            key: AntiRollbackKey {
                acceptance_identity: anchor.acceptance_identity.clone(),
            },
            last_sequence: if last_sequence == 0 {
                manifest.sequence
            } else {
                last_sequence
            },
            last_config_hash: if last_sequence == 0 {
                manifest.config_hash.clone()
            } else {
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string()
            },
            last_bundle_manifest_hash: if last_sequence == 0 {
                manifest_hash
            } else {
                ZERO_HASH.to_string()
            },
            last_bundle_id: if last_sequence == 0 {
                manifest.bundle_id.clone()
            } else {
                "previous-bundle".to_string()
            },
            accepted_anchor: AcceptedAnchorPinV1::from_trust_anchor(&anchor).expect("anchor pin"),
            override_pin: None,
            break_glass: Default::default(),
            local_approvals: Default::default(),
        })
        .expect("state serializes"),
    )
    .expect("state writes");

    BundleFixture {
        bundle_dir,
        anchor_path,
        state_path,
        config_path,
        config_hash,
    }
}

fn rewrite_manifest_instance_id(fixture: &BundleFixture, instance_id: Option<&str>) {
    let manifest_path = fixture.bundle_dir.join("manifest.json");
    let mut manifest: ConfigBundleManifest =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("manifest reads"))
            .expect("manifest parses");
    manifest.acceptance_identity.instance = instance_id.unwrap_or_default().to_string();
    let private = PrivateJwk::parse(PRIVATE_JWK).expect("private JWK parses");
    let kid = private.public().jkt().expect("thumbprint computes");
    write_manifest_and_signature(&fixture.bundle_dir, &manifest, &private, &kid);
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

fn relay_config_yaml() -> String {
    r#"
instance:
  id: relay-lab
  environment: lab
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
vocabularies: {}
auth:
  mode: api_key
  api_keys: []
datasets: []
audit:
  sink: stdout
"#
    .to_string()
}

fn metadata_manifest_yaml() -> String {
    r#"
schema_version: registry-manifest/v1
catalog:
  id: split-demo
  base_url: https://metadata.example.test/
  title: Split Metadata Catalog
  publisher:
    name: Metadata Ministry
datasets: []
"#
    .to_string()
}
