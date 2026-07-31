use crate::*;
pub(crate) use std::sync::Mutex;

pub(crate) use axum::http::StatusCode;
pub(crate) use axum::routing::get;
pub(crate) use axum::Router;
pub(crate) use axum_test::TestServer;
pub(crate) use registry_platform_config::{
    sha256_uri, ConfigBundleFile, ConfigBundleManifest, ConfigBundleSignature,
    ConfigBundleSignatureEnvelope, ConfigTrustAnchor, ConfigTrustAnchorSigner,
    ProductAcceptanceIdentityV1, ProductAcceptanceLaneV1, ProductAcceptanceProductV1,
    ProductTrustDomainV1,
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
    write_signed_notary_bundle_with_config(tmp, notary_bundle_runtime_config())
}

pub(crate) fn write_signed_notary_bundle_with_config(
    tmp: &tempfile::TempDir,
    config: String,
) -> SignedBundleFixture {
    let bundle_dir = tmp.path().join("bundle");
    let config_dir = bundle_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("bundle config dir");
    std::fs::write(config_dir.join("notary.yaml"), config.as_bytes()).expect("config writes");
    let config_hash = sha256_uri(config.as_bytes());
    let private = PrivateJwk::parse(CONFIG_BUNDLE_PRIVATE_JWK).expect("private jwk");
    let public = private.public();
    let kid = public.jkt().expect("thumbprint");
    let manifest = ConfigBundleManifest {
        schema: "registry.platform.config_bundle.v1".to_string(),
        acceptance_identity: notary_acceptance_identity(),
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
        acceptance_identity: notary_acceptance_identity(),
        version: 1,
        threshold: 1,
        enabled_signers: vec![ConfigTrustAnchorSigner { kid, jwk: public }],
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

pub(crate) fn notary_acceptance_identity() -> ProductAcceptanceIdentityV1 {
    ProductAcceptanceIdentityV1 {
        trust_domain: ProductTrustDomainV1::Governed,
        project: "notary-loader-project".to_string(),
        environment: "development".to_string(),
        lane: ProductAcceptanceLaneV1::Notary,
        product: ProductAcceptanceProductV1::RegistryNotary,
        stream: "notary-loader-test".to_string(),
        instance: "notary-loader".to_string(),
    }
}

pub(crate) fn notary_accepted_anchor_pin() -> registry_platform_ops::AcceptedAnchorPinV1 {
    registry_platform_ops::AcceptedAnchorPinV1 {
        digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        version: 1,
        threshold: 1,
        enabled_signers: vec!["kid-1".to_string()],
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

pub(crate) fn rewrite_signed_bundle_instance_id(
    fixture: &SignedBundleFixture,
    instance_id: Option<&str>,
) {
    let mut manifest: ConfigBundleManifest = serde_json::from_slice(
        &std::fs::read(fixture.bundle_dir.join("manifest.json")).expect("manifest reads"),
    )
    .expect("manifest parses");
    manifest.acceptance_identity.instance = instance_id.unwrap_or_default().to_string();
    let private = PrivateJwk::parse(CONFIG_BUNDLE_PRIVATE_JWK).expect("private JWK parses");
    let kid = private.public().jkt().expect("signer thumbprint");
    write_manifest_and_signature(&fixture.bundle_dir, &manifest, &private, &kid);
}

pub(crate) fn notary_bundle_runtime_config() -> String {
    r#"
deployment:
  profile: local
state:
  storage: in_memory
server:
  bind: 127.0.0.1:4255
  admin_listener:
    mode: dedicated
    bind: 127.0.0.1:4256
auth:
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
  allowed_purposes: [doctor-test]
  relay:
    base_url: https://relay.internal.example
    workload_client_id: registry-notary
    token_file: /run/secrets/registry-notary-relay.jwt
  claims:
    - id: registry-backed-test
      title: Registry-backed test
      version: 2026-05
      subject_type: person
      purpose: doctor-test
      required_scopes: [registry_notary:credential_issue]
      evidence_mode:
        type: registry_backed
        consultations:
          test_source:
            profile:
              id: example.test-source.exact
              contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            inputs:
              subject_id: target.id
            outputs:
              active: { type: boolean, nullable: false }
      value:
        type: boolean
        nullable: false
      rule:
        type: consultation_matched
        consultation: test_source
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#;
    serde_norway::from_str::<StandaloneRegistryNotaryConfig>(raw).expect("config parses")
}
