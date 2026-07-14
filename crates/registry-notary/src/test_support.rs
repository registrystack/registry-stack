use crate::*;
pub(crate) use std::sync::Mutex;

pub(crate) use axum::http::StatusCode;
pub(crate) use axum::routing::get;
pub(crate) use axum::Router;
pub(crate) use axum_test::TestServer;
pub(crate) use registry_platform_config::{
    sha256_uri, ConfigBundleFile, ConfigBundleManifest, ConfigBundleSignature,
    ConfigBundleSignatureEnvelope, ConfigTrustAnchor, ConfigTrustAnchorSigner,
};
pub(crate) use registry_platform_crypto::{canonicalize_json, sign, PrivateJwk};

pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());
pub(crate) const CONFIG_BUNDLE_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;

pub(crate) struct SignedBundleFixture {
    pub(crate) bundle_dir: PathBuf,
    pub(crate) anchor_path: PathBuf,
    pub(crate) state_path: PathBuf,
    pub(crate) config_hash: String,
}

pub(crate) fn write_signed_notary_bundle(tmp: &tempfile::TempDir) -> SignedBundleFixture {
    let bundle_dir = tmp.path().join("bundle");
    let config_dir = bundle_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("bundle config dir");
    let config = notary_bundle_runtime_config();
    std::fs::write(config_dir.join("notary.yaml"), config.as_bytes()).expect("config writes");
    let config_hash = sha256_uri(config.as_bytes());
    let private = PrivateJwk::parse(CONFIG_BUNDLE_PRIVATE_JWK).expect("private jwk");
    let public = private.public();
    let kid = public.jkt().expect("thumbprint");
    let manifest = ConfigBundleManifest {
        schema: "registry.platform.config_bundle.v1".to_string(),
        product: "registry-notary".to_string(),
        environment: "development".to_string(),
        stream_id: "notary-loader-test".to_string(),
        instance_id: None,
        bundle_id: "notary-loader-bundle".to_string(),
        sequence: 1,
        previous_config_hash: None,
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
        product: "registry-notary".to_string(),
        environment: "development".to_string(),
        stream_id: "notary-loader-test".to_string(),
        instance_id: "notary-loader".to_string(),
        signers: vec![ConfigTrustAnchorSigner {
            kid,
            jwk: public,
            enabled: true,
        }],
    };
    let anchor_path = tmp.path().join("trust_anchor.json");
    std::fs::write(
        &anchor_path,
        serde_json::to_vec_pretty(&anchor).expect("anchor serializes"),
    )
    .expect("anchor writes");
    SignedBundleFixture {
        bundle_dir,
        anchor_path,
        state_path: tmp.path().join("antirollback.json"),
        config_hash,
    }
}

pub(crate) fn write_manifest_and_signature(
    bundle_dir: &Path,
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

pub(crate) fn notary_bundle_runtime_config() -> String {
    r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:4255
  admin_listener:
    mode: dedicated
    bind: 127.0.0.1:4256
auth:
  mode: api_key
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_NOTARY_LOADER_API_HASH
      scopes: [registry_notary:credential_issue]
audit:
  sink: stdout
  hash_secret_env: TEST_NOTARY_LOADER_AUDIT_HASH_SECRET
evidence:
  enabled: true
  signing_keys:
    issuer:
      provider: local_jwk_env
      private_jwk_env: TEST_NOTARY_LOADER_ISSUER_JWK
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
"#
    .to_string()
}

pub(crate) fn notary_bootstrap_config(fixture: &SignedBundleFixture) -> String {
    format!(
        r#"{}
config_trust:
  trust_anchor_path: {}
  bundle_path: {}
  antirollback_state_path: {}
"#,
        notary_bundle_runtime_config(),
        fixture.anchor_path.display(),
        fixture.bundle_dir.display(),
        fixture.state_path.display()
    )
}

pub(crate) fn notary_test_config() -> StandaloneRegistryNotaryConfig {
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
      scopes: [registry_notary:credential_issue]
audit:
  sink: stdout
evidence:
  enabled: true
  service_id: doctor-live-test
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
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#;
    serde_norway::from_str::<StandaloneRegistryNotaryConfig>(raw).expect("config parses")
}
