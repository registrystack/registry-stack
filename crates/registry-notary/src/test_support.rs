use crate::*;
pub(crate) use std::sync::atomic::{AtomicBool, Ordering};
pub(crate) use std::sync::{Arc, Mutex};

pub(crate) use axum::extract::State;
pub(crate) use axum::http::{HeaderMap, StatusCode};
pub(crate) use axum::response::{IntoResponse, Response};
pub(crate) use axum::routing::{get, post};
pub(crate) use axum::{Json, Router};
pub(crate) use axum_test::TestServer;
pub(crate) use registry_platform_config::{
    sha256_uri, ConfigBundleFile, ConfigBundleManifest, ConfigBundleSignature,
    ConfigBundleSignatureEnvelope, ConfigTrustAnchor, ConfigTrustAnchorSigner,
};
pub(crate) use registry_platform_crypto::{canonicalize_json, sign, PrivateJwk};

pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());
pub(crate) const CONFIG_BUNDLE_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;

#[derive(Clone, Default)]
pub(crate) struct DoctorLiveState {
    pub(crate) token_called: Arc<AtomicBool>,
    pub(crate) dci_called: Arc<AtomicBool>,
}

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

pub(crate) async fn test_oauth_token(
    State(state): State<DoctorLiveState>,
    Json(body): Json<Value>,
) -> Response {
    state.token_called.store(true, Ordering::SeqCst);
    if body["grant_type"] != json!("client_credentials")
        || body["client_id"] != json!("doctor-client")
        || body["client_secret"] != json!("doctor-secret")
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    Json(json!({
        "access_token": "doctor-live-token",
        "expires_in": 300,
    }))
    .into_response()
}

pub(crate) async fn test_dci_search(
    State(state): State<DoctorLiveState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    state.dci_called.store(true, Ordering::SeqCst);
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some("Bearer doctor-live-token")
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if headers
        .get("data-purpose")
        .and_then(|value| value.to_str().ok())
        != Some("https://registry-notary.local/purpose/doctor")
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let query = &body["message"]["search_request"][0]["search_criteria"]["query"];
    if query["type"] != json!("SUBJECT_ID") || query["value"] != json!("secret-subject-123") {
        return StatusCode::BAD_REQUEST.into_response();
    }
    Json(json!({
        "message": {
            "search_response": [{
                "data": {
                    "reg_records": [{
                        "id": "record-1"
                    }]
                }
            }]
        }
    }))
    .into_response()
}

pub(crate) async fn doctor_live_upstream(
    State(state): State<DoctorLiveState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Json(body): Json<Value>,
) -> Response {
    match uri.path() {
        "/oauth/token" => test_oauth_token(State(state), Json(body)).await,
        "/registry/sync/search" => test_dci_search(State(state), headers, Json(body)).await,
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

pub(crate) fn test_dci_options(demo_issuer: bool) -> InitDciOptions {
    InitDciOptions {
        base_url: "https://dci.example.test".to_string(),
        token_url: "https://dci.example.test/oauth2/client/token".to_string(),
        lookup_field: "SUBJECT_ID".to_string(),
        claim_id: "dci-record-exists".to_string(),
        claim_title: "DCI record exists".to_string(),
        demo_issuer,
        with_env_file: false,
        force: false,
        print_secrets: false,
    }
}

pub(crate) fn doctor_live_test_config(base_url: &str) -> StandaloneRegistryNotaryConfig {
    let raw = format!(
        r#"
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
  service_id: doctor-live-test
  source_connections:
    dci_registry:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      source_auth:
        type: oauth2_client_credentials
        token_url: "{base_url}/oauth/token"
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
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#
    );
    serde_norway::from_str::<StandaloneRegistryNotaryConfig>(&raw).expect("config parses")
}
