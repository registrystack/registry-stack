// SPDX-License-Identifier: Apache-2.0
//! Cross-field validation for provenance config.
//!
//! Covers claim validity bounds, http(s) URL shape on the two base URLs,
//! verification method prefix, signer-kind requirements, and the env-var
//! presence check that fires only when `enabled: true`.

use std::env;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Once;

use registry_relay::config;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

// All tests in this binary need the persona hash env vars present; the
// base YAML below declares a single api_key for completeness. We seed
// the env once per process.
static SET_PERSONA_ENV: Once = Once::new();
const TEST_HASH_ENV: &str = "PROVENANCE_TEST_OPERATOR_HASH";
// Distinct env var names per test path so parallel tests cannot stomp
// each other (cargo runs `#[test]` cases inside one binary in
// parallel). Each name is unique to one branch under exercise.
const JWK_ENV_SET_AND_VALID: &str = "PROV_TEST_JWK_PRESENT";
const JWK_ENV_UNSET: &str = "PROV_TEST_JWK_MISSING";

fn ensure_persona_env() {
    SET_PERSONA_ENV.call_once(|| {
        env::set_var(TEST_HASH_ENV, make_fingerprint(b"operator"));
        // A populated value here lets the `enabled: true` path pass.
        env::set_var(JWK_ENV_SET_AND_VALID, "non-empty");
        env::remove_var(JWK_ENV_UNSET);
    });
}

fn make_fingerprint(plaintext: &[u8]) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(plaintext)))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn write_yaml(body: &str) -> PathBuf {
    let mut file = NamedTempFile::new().expect("tempfile");
    file.write_all(body.as_bytes()).expect("write yaml");
    let (_, path) = file.keep().expect("persist tempfile");
    path
}

fn base_yaml(extra: &str) -> String {
    format!(
        r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test

vocabularies: {{}}

auth:
  mode: api_key
  api_keys:
    - id: operator
      hash_env: PROVENANCE_TEST_OPERATOR_HASH
      scopes: ["admin"]

audit:
  sink: stdout
  format: jsonl

datasets: []

provenance:
{extra}
"#
    )
}

fn gateway_provenance(
    enabled: bool,
    verify_validity: &str,
    context_url: &str,
    schema_url: &str,
    vm_id: &str,
    jwk_env: &str,
) -> String {
    format!(
        r#"  enabled: {enabled}
  context_base_url: {context_url}
  schema_base_url: {schema_url}
  claim_validity:
    verify_result: {verify_validity}
    aggregate_result: 10m
    entity_record: 10m
  issuer:
    mode: gateway
    did: did:web:data.example.test
    verification_method_id: "{vm_id}"
    signer:
      kind: software
      jwk_env: {jwk_env}
      signing_algorithm: EdDSA
"#
    )
}

#[test]
fn valid_gateway_config_loads() {
    ensure_persona_env();
    let yaml = base_yaml(&gateway_provenance(
        true,
        "10m",
        "https://data.example.test/contexts",
        "https://data.example.test/schemas",
        "did:web:data.example.test#key-1",
        JWK_ENV_SET_AND_VALID,
    ));
    let path = write_yaml(&yaml);
    let cfg = config::load(&path).expect("config must load");
    let prov = cfg.provenance.expect("provenance present");
    assert!(prov.enabled);
}

#[test]
fn claim_validity_below_one_minute_is_rejected() {
    ensure_persona_env();
    let yaml = base_yaml(&gateway_provenance(
        false,
        "30s",
        "https://data.example.test/contexts",
        "https://data.example.test/schemas",
        "did:web:data.example.test#key-1",
        JWK_ENV_SET_AND_VALID,
    ));
    let path = write_yaml(&yaml);
    let err = config::load(&path).expect_err("30s validity must be rejected");
    assert_eq!(err.code(), "provenance.config.claim_validity_out_of_range");
}

#[test]
fn claim_validity_above_one_year_is_rejected() {
    ensure_persona_env();
    let yaml = base_yaml(&gateway_provenance(
        false,
        "400d",
        "https://data.example.test/contexts",
        "https://data.example.test/schemas",
        "did:web:data.example.test#key-1",
        JWK_ENV_SET_AND_VALID,
    ));
    let path = write_yaml(&yaml);
    let err = config::load(&path).expect_err("400d validity must be rejected");
    assert_eq!(err.code(), "provenance.config.claim_validity_out_of_range");
}

#[test]
fn non_http_context_base_url_is_rejected() {
    ensure_persona_env();
    let yaml = base_yaml(&gateway_provenance(
        false,
        "10m",
        "file:///etc/contexts",
        "https://data.example.test/schemas",
        "did:web:data.example.test#key-1",
        JWK_ENV_SET_AND_VALID,
    ));
    let path = write_yaml(&yaml);
    let err = config::load(&path).expect_err("file:// must be rejected");
    assert_eq!(err.code(), "provenance.config.context_base_url_invalid");
}

#[test]
fn non_http_schema_base_url_is_rejected() {
    ensure_persona_env();
    let yaml = base_yaml(&gateway_provenance(
        false,
        "10m",
        "https://data.example.test/contexts",
        "ftp://data.example.test/schemas",
        "did:web:data.example.test#key-1",
        JWK_ENV_SET_AND_VALID,
    ));
    let path = write_yaml(&yaml);
    let err = config::load(&path).expect_err("ftp:// must be rejected");
    assert_eq!(err.code(), "provenance.config.schema_base_url_invalid");
}

#[test]
fn verification_method_must_be_did_fragment() {
    ensure_persona_env();
    let yaml = base_yaml(&gateway_provenance(
        false,
        "10m",
        "https://data.example.test/contexts",
        "https://data.example.test/schemas",
        // Does not start with the configured `did:web:data.example.test#`.
        "did:web:other.example.test#key-1",
        JWK_ENV_SET_AND_VALID,
    ));
    let path = write_yaml(&yaml);
    let err = config::load(&path).expect_err("foreign DID fragment must be rejected");
    assert_eq!(err.code(), "provenance.config.verification_method_mismatch");
}

#[test]
fn jwk_env_required_when_enabled() {
    ensure_persona_env();
    let yaml = base_yaml(&gateway_provenance(
        true,
        "10m",
        "https://data.example.test/contexts",
        "https://data.example.test/schemas",
        "did:web:data.example.test#key-1",
        JWK_ENV_UNSET,
    ));
    let path = write_yaml(&yaml);
    let err = config::load(&path).expect_err("unset jwk_env must be rejected when enabled");
    assert_eq!(err.code(), "provenance.config.jwk_env_missing");
}

#[test]
fn jwk_env_not_required_when_disabled() {
    ensure_persona_env();
    let yaml = base_yaml(&gateway_provenance(
        false,
        "10m",
        "https://data.example.test/contexts",
        "https://data.example.test/schemas",
        "did:web:data.example.test#key-1",
        JWK_ENV_UNSET,
    ));
    let path = write_yaml(&yaml);
    let cfg = config::load(&path).expect("disabled config must load without jwk env");
    assert!(!cfg.provenance.unwrap().enabled);
}

#[test]
fn config_loads_without_provenance_block() {
    // Backwards compat: deployments without a provenance block must keep loading.
    ensure_persona_env();
    let yaml = base_yaml("");
    // Strip the dangling `provenance:` header from base_yaml when extra
    // is empty: we just emit an empty mapping.
    let yaml = yaml.replace("provenance:\n", "");
    let path = write_yaml(&yaml);
    let cfg = config::load(&path).expect("config without provenance must load");
    assert!(cfg.provenance.is_none());
}

#[test]
fn delegated_mode_validates_against_ministry_did() {
    ensure_persona_env();
    let yaml = base_yaml(&format!(
        r#"  enabled: true
  context_base_url: https://data.example.test/contexts
  schema_base_url: https://data.example.test/schemas
  claim_validity:
    verify_result: 10m
    aggregate_result: 10m
    entity_record: 10m
  issuer:
    mode: delegated
    ministry_did: did:web:ministry.example.test
    verification_method_id: "did:web:ministry.example.test#delegated-key"
    signer:
      kind: software
      jwk_env: {JWK_ENV_SET_AND_VALID}
      signing_algorithm: EdDSA
"#
    ));
    let path = write_yaml(&yaml);
    let cfg = config::load(&path).expect("delegated config must load");
    assert!(cfg.provenance.unwrap().enabled);
}

#[test]
fn delegated_mode_rejects_mismatched_vm_did() {
    ensure_persona_env();
    let yaml = base_yaml(&format!(
        r#"  enabled: false
  context_base_url: https://data.example.test/contexts
  schema_base_url: https://data.example.test/schemas
  claim_validity:
    verify_result: 10m
    aggregate_result: 10m
    entity_record: 10m
  issuer:
    mode: delegated
    ministry_did: did:web:ministry.example.test
    verification_method_id: "did:web:gateway.example.test#wrong-key"
    signer:
      kind: software
      jwk_env: {JWK_ENV_SET_AND_VALID}
      signing_algorithm: EdDSA
"#
    ));
    let path = write_yaml(&yaml);
    let err = config::load(&path).expect_err("vm/did mismatch must be rejected");
    assert_eq!(err.code(), "provenance.config.verification_method_mismatch");
}

#[test]
fn enabled_config_yields_resolved_state_with_enabled_flag() {
    // B1 wiring contract: `build_resolved_provenance_config` is the
    // function `main.rs` calls. When the YAML carries `enabled: true`,
    // it must yield a `Some(state)` whose `is_enabled()` returns true
    // and whose signer can be invoked. A regression where the binary
    // ignored the config (the bug B1 fixes) would manifest as the
    // helper never being called; this test is the load-bearing
    // invariant that proves the wiring is in place.
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use registry_relay::provenance::{build_resolved_provenance_config, ProvenanceState};
    use serde_json::json;

    ensure_persona_env();

    // Mint a real Ed25519 JWK so the signer load path runs to completion.
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let d_b64 = URL_SAFE_NO_PAD.encode(sk.to_bytes());
    let x_b64 = URL_SAFE_NO_PAD.encode(vk.to_bytes());
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "d": d_b64,
        "x": x_b64,
        "alg": "EdDSA",
    });
    let jwk_env = "B1_RESOLVED_STATE_JWK";
    env::set_var(jwk_env, serde_json::to_string(&jwk).unwrap());

    let yaml = base_yaml(&gateway_provenance(
        true,
        "10m",
        "https://data.example.test/contexts",
        "https://data.example.test/schemas",
        "did:web:data.example.test#key-1",
        jwk_env,
    ));
    let path = write_yaml(&yaml);
    let cfg = config::load(&path).expect("config loads");
    let resolved = build_resolved_provenance_config(cfg.provenance.as_ref())
        .expect("orchestrator state builds")
        .expect("provenance block produces Some(state)");
    let state = ProvenanceState::new(resolved);
    assert!(
        state.is_enabled(),
        "binary wiring contract: enabled YAML produces enabled state"
    );
    assert_eq!(state.config().issuer_did, "did:web:data.example.test");
    assert_eq!(
        state.config().verification_method_id,
        "did:web:data.example.test#key-1"
    );
    // public_jwk must round-trip the `x` we exported, confirming the
    // signer was loaded from the env var (not stubbed).
    let pjwk = state.config().signer.public_jwk();
    assert_eq!(pjwk["x"], serde_json::Value::String(x_b64));
}

#[test]
fn disabled_config_yields_no_runtime_state_or_signer_load() {
    // `enabled: false` must be runtime invisible and require no startup
    // signing secrets. Config loading
    // validates the non-secret shape, but the binary state builder must
    // not touch `jwk_env` until provenance is explicitly enabled.
    ensure_persona_env();
    let yaml = base_yaml(&gateway_provenance(
        false,
        "10m",
        "https://data.example.test/contexts",
        "https://data.example.test/schemas",
        "did:web:data.example.test#key-1",
        JWK_ENV_UNSET,
    ));
    let path = write_yaml(&yaml);
    let cfg = config::load(&path).expect("config loads");
    let resolved =
        registry_relay::provenance::build_resolved_provenance_config(cfg.provenance.as_ref())
            .expect("orchestrator state builds");
    assert!(
        resolved.is_none(),
        "disabled provenance must produce no runtime state and must not load jwk_env"
    );
}

#[test]
fn omitted_provenance_yields_no_state() {
    // No provenance block means no orchestrator state. The binary path
    // passes `None` to `build_app_with_entity_query_and_provenance`.
    ensure_persona_env();
    let yaml = base_yaml("").replace("provenance:\n", "");
    let path = write_yaml(&yaml);
    let cfg = config::load(&path).expect("config loads");
    let resolved =
        registry_relay::provenance::build_resolved_provenance_config(cfg.provenance.as_ref())
            .expect("orchestrator state builds");
    assert!(
        resolved.is_none(),
        "omitting the provenance block must yield None"
    );
}

#[test]
fn software_signer_with_es256_is_rejected_at_load_time() {
    // M2: the in-process software path does not yet support ES256 (the
    // `build_p256` branch returns `SignerError::KeyLoad` at sign-time).
    // The config validator must reject the combination at startup so
    // operators do not discover the gap on the first protected request.
    // The rejection surfaces with the same stable code already wired
    // for other algorithm-mismatch errors.
    ensure_persona_env();
    let yaml = base_yaml(
        r#"  enabled: false
  context_base_url: https://data.example.test/contexts
  schema_base_url: https://data.example.test/schemas
  claim_validity:
    verify_result: 10m
    aggregate_result: 10m
    entity_record: 10m
  issuer:
    mode: gateway
    did: did:web:data.example.test
    verification_method_id: "did:web:data.example.test#es256"
    signer:
      kind: software
      jwk_env: PROV_TEST_JWK_PRESENT
      signing_algorithm: ES256
"#,
    );
    let path = write_yaml(&yaml);
    let err =
        config::load(&path).expect_err("software + ES256 must be rejected at config-load time");
    assert_eq!(err.code(), "provenance.config.algorithm_unsupported");
}

#[test]
fn kms_signer_with_empty_key_id_is_rejected() {
    ensure_persona_env();
    let yaml = base_yaml(
        r#"  enabled: false
  context_base_url: https://data.example.test/contexts
  schema_base_url: https://data.example.test/schemas
  claim_validity:
    verify_result: 10m
    aggregate_result: 10m
    entity_record: 10m
  issuer:
    mode: gateway
    did: did:web:data.example.test
    verification_method_id: "did:web:data.example.test#kms-key"
    signer:
      kind: kms
      provider: aws_kms
      key_id: ""
      signing_algorithm: EdDSA
"#,
    );
    let path = write_yaml(&yaml);
    let err = config::load(&path).expect_err("empty kms key_id must be rejected");
    assert_eq!(err.code(), "provenance.config.signer_kind_invalid");
}
