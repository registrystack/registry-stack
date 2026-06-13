// SPDX-License-Identifier: Apache-2.0
//! Focused production-wiring tests for the admin reload API slice.

use std::num::NonZeroU64;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use aws_lc_rs::rand::SystemRandom;
use axum::http::StatusCode;
use axum_test::TestServer;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use datafusion::execution::context::SessionContext;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use registry_manifest_core::{canonicalize_json, source_manifest_digest, MetadataManifest};
use registry_platform_audit::{AuditEnvelope, AuditError, AuditSink};
use registry_platform_authcommon::{
    credential_fingerprint_commitment, CredentialCommitmentContext, CredentialProduct,
    CredentialType,
};
use registry_platform_ops::{
    internal_config_hash, posture_safe_runtime_config_hash, AntiRollbackKey, AntiRollbackRecord,
    ConfigProvenance, FileAntiRollbackStore, FileLocalApprovalStore,
};
use registry_relay::api::admin::{
    router as admin_router, CandidateProvenanceResolver, CandidateProvenanceResolverRef,
};
use registry_relay::audit::{AuditPipeline, InMemorySink, AUDIT_WRITE_FAILED_CODE};
use registry_relay::auth::api_key::{ApiKeyAuth, ApiKeyEntry};
use registry_relay::auth::middleware::{AuthProviderRef, RuntimeAuthProvider};
use registry_relay::auth::ScopeSet;
use registry_relay::config::{self, Config, ProvenanceConfig};
use registry_relay::entity::EntityRegistry;
use registry_relay::format::FormatRegistry;
use registry_relay::ingest::{IngestRegistry, ReadinessSnapshot};
use registry_relay::observability::RequestMetrics;
use registry_relay::provenance::{
    build_resolved_provenance_config, BuildStateError, ClaimType, IssuanceContext, ProvenanceState,
    ResolvedProvenanceConfig, Signer, SignerError, SigningAlgorithm,
};
use registry_relay::query::{AggregateQueryEngine, EntityQueryEngine};
use registry_relay::runtime_config::{CursorSigner, RelayRuntimeHandle, RelayRuntimeSnapshot};
use registry_relay::server::{
    build_admin_app, build_app_with_entity_query_metadata_provenance_and_metrics,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::watch;
use tough::editor::signed::PathExists;
use tough::editor::signed::SignedRole;
use tough::editor::RepositoryEditor;
use tough::key_source::LocalKeySource;
use tough::schema::{KeyHolder, Root, Signed, Snapshot, Target, Timestamp};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ADMIN_KEY: &str = "admin-test-token-0123456789";
const NON_ADMIN_KEY: &str = "non-admin-test-token-0123456789";
const OPS_KEY: &str = "ops-test-token-0123456789";
const AUDIT_SECRET_VALUE: &str = "relay-admin-reload-audit-secret-32-bytes";
const NON_KEY_PLACEHOLDER_VALUE: &str = "relay-admin-reload-private-jwk-placeholder";
const TUF_TARGETS_SIGNER_KID: &str =
    "8ec3a843a0f9328c863cac4046ab1cacbbc67888476ac7acf73d9bcd9a223ada";
const FORGED_TUF_SIGNER_KID: &str =
    "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
const EMERGENCY_CHANGE_CLASS: &str = "emergency.break_glass";

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
}

struct ReadinessOverrideResolver {
    readiness: registry_platform_crypto::KeyReadiness,
}

impl CandidateProvenanceResolver for ReadinessOverrideResolver {
    fn resolve_candidate_provenance(
        &self,
        cfg: Option<&ProvenanceConfig>,
    ) -> Result<Option<ResolvedProvenanceConfig>, BuildStateError> {
        let Some(mut resolved) = build_resolved_provenance_config(cfg)? else {
            return Ok(None);
        };
        resolved.signer = Arc::new(ReadinessOverrideSigner {
            inner: Arc::clone(&resolved.signer),
            readiness: self.readiness,
        });
        Ok(Some(resolved))
    }
}

struct ReadinessOverrideSigner {
    inner: Arc<dyn Signer>,
    readiness: registry_platform_crypto::KeyReadiness,
}

impl Signer for ReadinessOverrideSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        self.inner.algorithm()
    }

    fn verification_method_id(&self) -> &str {
        self.inner.verification_method_id()
    }

    fn sign(&self, header: Value, payload: Value) -> Result<String, SignerError> {
        self.inner.sign(header, payload)
    }

    fn public_jwk(&self) -> Value {
        self.inner.public_jwk()
    }

    fn readiness(&self) -> registry_platform_crypto::KeyReadiness {
        self.readiness
    }
}

struct AdminFixture {
    _tmp: TempDir,
    server: TestServer,
    public_server: TestServer,
    handle: Arc<RelayRuntimeHandle>,
    audit_sink: InMemorySink,
    config_path: std::path::PathBuf,
    antirollback_path: std::path::PathBuf,
    local_approval_path: std::path::PathBuf,
    current_config_hash: String,
    source_path: std::path::PathBuf,
}

struct SignedConfigFixture {
    root_path: std::path::PathBuf,
    metadata_dir: std::path::PathBuf,
    targets_dir: std::path::PathBuf,
    datastore_dir: std::path::PathBuf,
    target_name: String,
}

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn tough_fixture(name: &str) -> std::path::PathBuf {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".cargo"))
        })
        .expect("CARGO_HOME or HOME is set");
    let src_root = cargo_home.join("registry/src");
    let registry = std::fs::read_dir(&src_root)
        .expect("cargo registry src exists")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.join("tough-0.22.0/tests/data").is_dir())
        .expect("tough-0.22.0 source fixture directory exists");
    registry.join("tough-0.22.0/tests/data").join(name)
}

fn make_fingerprint(plain: &str) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(plain.as_bytes())))
}

fn fingerprint_ref_yaml(id: &str, env_name: &str, fingerprint: &str, indent: &str) -> String {
    let commitment = credential_fingerprint_commitment(
        CredentialCommitmentContext {
            product: CredentialProduct::RegistryRelay,
            credential_type: CredentialType::ApiKey,
            credential_id: id,
        },
        fingerprint,
    );
    format!(
        "{indent}fingerprint:\n{indent}  provider: env\n{indent}  name: {env_name}\n{indent}  commitment: {commitment}"
    )
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

fn sha256_uri(bytes: &[u8]) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(bytes)))
}

fn find_metadata_file(dir: &Path, suffix: &str) -> std::path::PathBuf {
    std::fs::read_dir(dir)
        .expect("metadata dir reads")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(suffix))
        })
        .unwrap_or_else(|| panic!("metadata file ending in {suffix} exists"))
}

fn forge_extra_targets_signature(metadata_dir: &Path) -> String {
    let targets_path = find_metadata_file(metadata_dir, "targets.json");
    let mut value: Value =
        serde_json::from_slice(&std::fs::read(&targets_path).expect("targets reads"))
            .expect("targets parses");
    let signatures = value["signatures"]
        .as_array_mut()
        .expect("signatures is an array");
    let real_keyid = signatures
        .iter()
        .filter_map(|signature| signature["keyid"].as_str())
        .find(|kid| *kid != FORGED_TUF_SIGNER_KID)
        .expect("real keyid exists")
        .to_string();
    signatures.push(json!({
        "keyid": FORGED_TUF_SIGNER_KID,
        "sig": "abababababababababababababababababababababababababababababababab"
    }));
    std::fs::write(
        &targets_path,
        serde_json::to_vec_pretty(&value).expect("targets serializes"),
    )
    .expect("targets rewrites");
    real_keyid
}

fn set_meta(signed_value: &mut Value, suffix: &str, length: u64, hash_hex: &str) {
    let meta = signed_value["signed"]["meta"]
        .as_object_mut()
        .expect("meta object");
    let key = meta
        .keys()
        .find(|key| key.ends_with(suffix))
        .cloned()
        .unwrap_or_else(|| panic!("snapshot/timestamp meta entry for {suffix} exists"));
    let entry = meta
        .get_mut(&key)
        .and_then(Value::as_object_mut)
        .expect("meta entry object");
    entry.insert("length".to_string(), json!(length));
    entry.insert("hashes".to_string(), json!({ "sha256": hash_hex }));
}

async fn reseal_snapshot_and_timestamp(metadata_dir: &Path) {
    let root: Signed<Root> = serde_json::from_slice(
        &std::fs::read(tough_fixture("simple-rsa").join("root.json")).unwrap(),
    )
    .expect("root parses");
    let key_holder = KeyHolder::Root(root.signed.clone());
    let keys: Vec<Box<dyn tough::key_source::KeySource>> = vec![Box::new(LocalKeySource {
        path: tough_fixture("snakeoil.pem"),
    })];
    let rng = SystemRandom::new();

    let targets_bytes = std::fs::read(find_metadata_file(metadata_dir, "targets.json")).unwrap();
    let mut snapshot_value: Value = serde_json::from_slice(
        &std::fs::read(find_metadata_file(metadata_dir, "snapshot.json")).unwrap(),
    )
    .expect("snapshot parses");
    set_meta(
        &mut snapshot_value,
        "targets.json",
        targets_bytes.len() as u64,
        &hex_lower(&Sha256::digest(&targets_bytes)),
    );
    let snapshot: Snapshot =
        serde_json::from_value(snapshot_value["signed"].clone()).expect("snapshot deserializes");
    SignedRole::new(snapshot, &key_holder, &keys, &rng)
        .await
        .expect("snapshot re-signs")
        .write(metadata_dir, true)
        .await
        .expect("snapshot writes");

    let snapshot_bytes = std::fs::read(find_metadata_file(metadata_dir, "snapshot.json")).unwrap();
    let mut timestamp_value: Value = serde_json::from_slice(
        &std::fs::read(find_metadata_file(metadata_dir, "timestamp.json")).unwrap(),
    )
    .expect("timestamp parses");
    set_meta(
        &mut timestamp_value,
        "snapshot.json",
        snapshot_bytes.len() as u64,
        &hex_lower(&Sha256::digest(&snapshot_bytes)),
    );
    let timestamp: Timestamp =
        serde_json::from_value(timestamp_value["signed"].clone()).expect("timestamp deserializes");
    SignedRole::new(timestamp, &key_holder, &keys, &rng)
        .await
        .expect("timestamp re-signs")
        .write(metadata_dir, true)
        .await
        .expect("timestamp writes");
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
        "posture response did not match registry.ops.posture.v1: {errors:?}\n{body:#}"
    );
}

fn assert_matches_admin_capabilities_schema(body: &Value) {
    let schema: Value = serde_json::from_str(registry_platform_ops::ADMIN_CAPABILITIES_SCHEMA_V1)
        .expect("admin capabilities schema parses");
    let compiled =
        jsonschema::JSONSchema::compile(&schema).expect("admin capabilities schema compiles");
    let errors = compiled
        .validate(body)
        .err()
        .map(|errors| errors.map(|error| error.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();
    assert!(
        errors.is_empty(),
        "capabilities response did not match registry.admin.capabilities.v1: {errors:?}\n{body:#}"
    );
}

fn write_config(tmp: &TempDir) -> std::path::PathBuf {
    write_config_with_instance(
        tmp,
        Some(
            r#"instance:
  id: relay-test-instance
  environment: lab
  owner: Test Ministry
  jurisdiction: ZZ
"#,
        ),
    )
}

fn write_ed25519_jwk(path: &Path, kid: &str) -> Value {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let public_jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(vk.to_bytes()),
        "alg": "EdDSA",
        "kid": kid,
    });
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "d": URL_SAFE_NO_PAD.encode(sk.to_bytes()),
        "x": URL_SAFE_NO_PAD.encode(vk.to_bytes()),
        "alg": "EdDSA",
        "kid": kid,
    });
    std::fs::write(path, serde_json::to_string(&jwk).unwrap()).expect("write file_watch jwk");
    public_jwk
}

fn write_config_with_instance(tmp: &TempDir, instance_block: Option<&str>) -> std::path::PathBuf {
    write_config_with_instance_and_trust(tmp, instance_block, true)
}

fn write_config_with_instance_and_trust(
    tmp: &TempDir,
    instance_block: Option<&str>,
    include_config_trust: bool,
) -> std::path::PathBuf {
    write_config_with_instance_trust_and_admin_bind(tmp, instance_block, include_config_trust, true)
}

fn write_config_without_admin_bind(tmp: &TempDir) -> std::path::PathBuf {
    write_config_with_instance_trust_and_admin_bind(
        tmp,
        Some(
            r#"instance:
  id: relay-test-instance
  environment: lab
  owner: Test Ministry
  jurisdiction: ZZ
"#,
        ),
        true,
        false,
    )
}

fn split_metadata_manifest_yaml(title: &str) -> String {
    format!(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: relay-test
  base_url: https://metadata.example.test/
  title: {title}
  publisher:
    name: Test Ministry
datasets:
  - id: social_registry
    title: Social Registry
    entities:
      - name: beneficiary
        identifiers:
          - name: id
            kind: primary
        fields:
          - name: id
            type: integer
          - name: household_size
            type: integer
          - name: municipality_code
            type: string
          - name: program
            type: string
          - name: amount_eur
            type: number
          - name: joined_date
            type: date
          - name: last_updated
            type: date
"#
    )
}

fn metadata_source_digest(metadata_yaml: &str) -> String {
    let manifest: MetadataManifest =
        serde_saphyr::from_str(metadata_yaml).expect("metadata manifest parses");
    source_manifest_digest(&manifest).expect("metadata digest computes")
}

fn insert_metadata_digest(path: &Path, digest: &str) {
    let yaml = std::fs::read_to_string(path).expect("config reads");
    std::fs::write(
        path,
        yaml.replace(
            "    path: metadata.yaml\n",
            &format!("    path: metadata.yaml\n    digest: {digest}\n"),
        ),
    )
    .expect("config writes");
}

fn write_config_with_instance_trust_and_admin_bind(
    tmp: &TempDir,
    instance_block: Option<&str>,
    include_config_trust: bool,
    include_admin_bind: bool,
) -> std::path::PathBuf {
    let cache_dir = tmp.path().join("cache");
    let antirollback_path = tmp.path().join("config-antirollback.json");
    let local_approval_path = tmp.path().join("config-local-approvals.json");
    let source_path = tmp.path().join("social_registry.csv");
    std::fs::copy(fixture("social_registry.csv"), &source_path).expect("copy source fixture");
    let instance_block = instance_block.unwrap_or("");
    let tuf_root_sha256 = sha256_uri(
        &std::fs::read(tough_fixture("simple-rsa").join("root.json"))
            .expect("trusted TUF root fixture reads"),
    );
    let config_trust_block = if include_config_trust {
        format!(
            r#"
config_trust:
  antirollback_state_path: "{}"
  local_approval_state_path: "{}"
  break_glass_rate_limit:
    max_accepted: 1
    window_seconds: 3600
  accepted_roots:
    - root_id: ops-root
      production: false
      tuf_root_sha256: "{}"
      high_risk_change_classes: []
      signers:
        {}:
          kid: {}
          enabled: true
        kid-b:
          kid: kid-b
          enabled: true
      roles:
        - name: config-admin
          threshold: 1
          signer_kids:
            - {}
            - kid-b
          allowed_change_classes:
            - public_metadata
            - signing_key_cleanup
            - signing_key_rotation
            - emergency.break_glass
            - root_transition
            - client_credential_rotation
            - client_access_change
"#,
            antirollback_path.to_string_lossy(),
            local_approval_path.to_string_lossy(),
            tuf_root_sha256,
            TUF_TARGETS_SIGNER_KID,
            TUF_TARGETS_SIGNER_KID,
            TUF_TARGETS_SIGNER_KID
        )
    } else {
        String::new()
    };
    let admin_bind_line = if include_admin_bind {
        "  admin_bind: 127.0.0.1:0\n"
    } else {
        ""
    };
    let yaml = format!(
        r#"
{instance_block}
server:
  bind: 127.0.0.1:0
{admin_bind_line}
  cache_dir: "{cache_dir}"
{config_trust_block}

metadata:
  source:
    path: metadata.yaml

catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test Ministry

vocabularies: {{}}

auth:
  mode: api_key
  api_keys: []

datasets:
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    defaults:
      refresh:
        mode: manual
    tables:
      - id: beneficiaries_csv
        source:
          type: file
          path: "{source_path}"
          format:
            csv:
              header_row: 1
        primary_key: beneficiary_id
        schema:
          strict: true
          fields:
            - name: beneficiary_id
              type: integer
              nullable: false
            - name: household_size
              type: integer
              nullable: false
            - name: municipality_code
              type: string
              nullable: false
            - name: program
              type: string
              nullable: false
            - name: amount_eur
              type: number
              nullable: false
            - name: joined_date
              type: date
              nullable: false
            - name: last_updated
              type: date
              nullable: true
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
        api:
          default_limit: 100
          max_limit: 1000
      - id: beneficiaries_copy_csv
        source:
          type: file
          path: "{source_path}"
          format:
            csv:
              header_row: 1
        primary_key: beneficiary_id
        schema:
          strict: true
          fields:
            - name: beneficiary_id
              type: integer
              nullable: false
            - name: household_size
              type: integer
              nullable: false
            - name: municipality_code
              type: string
              nullable: false
            - name: program
              type: string
              nullable: false
            - name: amount_eur
              type: number
              nullable: false
            - name: joined_date
              type: date
              nullable: false
            - name: last_updated
              type: date
              nullable: true
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
        api:
          default_limit: 100
          max_limit: 1000
    entities:
      - name: beneficiary
        table: beneficiaries_csv
        fields:
          - name: id
            from: beneficiary_id
          - name: household_size
            from: household_size
          - name: municipality_code
            from: municipality_code
          - name: program
            from: program
          - name: amount_eur
            from: amount_eur
          - name: joined_date
            from: joined_date
          - name: last_updated
            from: last_updated
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 1000

audit:
  sink: stdout
  format: jsonl
  hash_secret_env: REGISTRY_RELAY_TEST_AUDIT_HASH_SECRET

provenance:
  enabled: false
  accepted_media_types:
    - application/vc+jwt
  schema_base_url: https://data.example.test/schemas
  context_base_url: https://data.example.test/contexts
  claim_validity:
    aggregate_result: 10m
    entity_record: 10m
  issuer:
    mode: gateway
    did: did:web:data.example.test
    verification_method_id: did:web:data.example.test#relay-public-key
    signer:
      kind: software
      jwk_env: REGISTRY_RELAY_TEST_PRIVATE_JWK
      signing_algorithm: EdDSA
"#,
        instance_block = instance_block,
        admin_bind_line = admin_bind_line,
        cache_dir = cache_dir.to_string_lossy(),
        config_trust_block = config_trust_block,
        source_path = source_path.to_string_lossy(),
    );
    let path = tmp.path().join("admin-reload.yaml");
    std::fs::write(&path, yaml).expect("write config");
    path
}

fn build_fixture_from_config_path(tmp: TempDir, config_path: std::path::PathBuf) -> AdminFixture {
    build_fixture_from_config_path_with_provenance_state(tmp, config_path, false)
}

fn build_fixture_from_config_path_with_provenance_state(
    tmp: TempDir,
    config_path: std::path::PathBuf,
    include_provenance_state: bool,
) -> AdminFixture {
    build_fixture_from_config_path_with_provenance_state_and_admin_resolver(
        tmp,
        config_path,
        include_provenance_state,
        None,
    )
}

fn build_fixture_from_config_path_with_provenance_state_and_admin_resolver(
    tmp: TempDir,
    config_path: std::path::PathBuf,
    include_provenance_state: bool,
    admin_resolver: Option<CandidateProvenanceResolverRef>,
) -> AdminFixture {
    let audit_sink = InMemorySink::new();
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(audit_sink.clone());
    build_fixture_from_config_path_with_audit_pipeline(
        tmp,
        config_path,
        include_provenance_state,
        admin_resolver,
        sink,
        audit_sink,
    )
}

fn build_fixture_from_config_path_with_audit_pipeline(
    tmp: TempDir,
    config_path: std::path::PathBuf,
    include_provenance_state: bool,
    admin_resolver: Option<CandidateProvenanceResolverRef>,
    sink: Arc<AuditPipeline>,
    audit_sink: InMemorySink,
) -> AdminFixture {
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("REGISTRY_RELAY_TEST_AUDIT_HASH_SECRET", AUDIT_SECRET_VALUE);
        std::env::set_var("REGISTRY_RELAY_TEST_PRIVATE_JWK", NON_KEY_PLACEHOLDER_VALUE);
    }
    let config: Arc<Config> = Arc::new(config::load(&config_path).expect("config loads"));
    let provenance_state = if include_provenance_state {
        build_resolved_provenance_config(config.provenance.as_ref())
            .expect("provenance state builds")
            .map(ProvenanceState::new)
            .map(Arc::new)
    } else {
        None
    };
    let config_provenance = local_provenance_from_path(&config_path);
    initialize_antirollback_state(&config, &config_provenance);
    let df_ctx = Arc::new(SessionContext::new());
    let ingest = Arc::new(
        IngestRegistry::from_config(
            &config,
            Arc::new(FormatRegistry::with_v1_defaults()),
            Arc::from(config.server.cache_dir.as_path()),
            Arc::clone(&df_ctx),
        )
        .expect("ingest registry builds"),
    );
    let (readiness_tx, readiness_rx) = watch::channel::<ReadinessSnapshot>(ingest.snapshot());
    let auth = build_auth();
    let entity_registry = Arc::new(EntityRegistry::from_config(&config).expect("registry builds"));
    let entity_query = Arc::new(EntityQueryEngine::new(
        Arc::clone(&df_ctx),
        Arc::clone(&entity_registry),
    ));
    let aggregate_query = Arc::new(AggregateQueryEngine::new(
        Arc::clone(&df_ctx),
        Arc::clone(&entity_registry),
        Arc::clone(&config),
    ));
    let metrics = RequestMetrics::shared();
    let handle = Arc::new(RelayRuntimeHandle::new(RelayRuntimeSnapshot::new(
        Arc::clone(&config),
        config_provenance.clone(),
        None,
        None,
        None,
        auth.clone(),
        Arc::clone(&sink),
        config.server.bind,
        config.server.admin_bind,
        "memory",
        Arc::clone(&df_ctx),
        Arc::clone(&ingest),
        Arc::clone(&entity_registry),
        Arc::clone(&entity_query),
        Arc::clone(&aggregate_query),
        readiness_tx.clone(),
        readiness_rx.clone(),
        Arc::new(CursorSigner::new_random()),
        provenance_state,
        None,
        #[cfg(feature = "spdci-api-standards")]
        None,
        Arc::clone(&metrics),
    )));
    let runtime_auth: AuthProviderRef = Arc::new(RuntimeAuthProvider::new(Arc::clone(&handle)));
    let public_app = build_app_with_entity_query_metadata_provenance_and_metrics(
        Arc::clone(&config),
        runtime_auth.clone(),
        Arc::clone(&sink),
        readiness_rx.clone(),
        Arc::clone(&entity_registry),
        Arc::clone(&entity_query),
        Arc::clone(&aggregate_query),
        None,
        handle.load_full().provenance_state.clone(),
        Arc::clone(&metrics),
    )
    .expect("public app builds")
    .layer(axum::Extension(Arc::clone(&handle)));
    let mut app = build_admin_app(
        Arc::clone(&config),
        runtime_auth,
        sink,
        readiness_rx,
        readiness_tx,
        ingest,
    )
    .expect("admin app builds")
    .layer(axum::Extension(Arc::clone(&handle)));
    if let Some(admin_resolver) = admin_resolver {
        app = app.layer(axum::Extension(admin_resolver));
    }

    AdminFixture {
        _tmp: tmp,
        server: TestServer::new(app),
        public_server: TestServer::new(public_app),
        handle,
        audit_sink,
        config_path: config_path.clone(),
        antirollback_path: config
            .config_trust
            .as_ref()
            .map(|trust| trust.antirollback_state_path.clone())
            .unwrap_or_else(|| config_path.with_file_name("config-antirollback.json")),
        local_approval_path: config
            .config_trust
            .as_ref()
            .map(|trust| trust.local_approval_state_path.clone())
            .unwrap_or_else(|| config_path.with_file_name("config-local-approvals.json")),
        current_config_hash: config_provenance.internal_config_hash.clone(),
        source_path: config_path
            .parent()
            .expect("config path has parent")
            .join("social_registry.csv"),
    }
}

fn snapshot_with_provenance_state(
    current: &RelayRuntimeSnapshot,
    provenance_state: Option<Arc<ProvenanceState>>,
) -> RelayRuntimeSnapshot {
    current.with_provenance_state(provenance_state)
}

fn local_provenance_from_path(path: &Path) -> ConfigProvenance {
    let raw = std::fs::read_to_string(path).expect("config reads");
    let value: Value = serde_saphyr::from_str(&raw).expect("config parses as value");
    ConfigProvenance::local_file(
        internal_config_hash(raw.as_bytes()),
        posture_safe_runtime_config_hash(&value),
        false,
    )
}

fn initialize_antirollback_state(config: &Config, provenance: &ConfigProvenance) {
    let Some(trust) = &config.config_trust else {
        return;
    };
    FileAntiRollbackStore::new(&trust.antirollback_state_path)
        .initialize(AntiRollbackRecord {
            key: AntiRollbackKey {
                product: "registry-relay".to_string(),
                instance_id: config.instance.id.clone(),
                environment: config
                    .instance
                    .environment
                    .clone()
                    .unwrap_or_else(|| "development".to_string()),
                stream_id: "test-stream".to_string(),
            },
            last_sequence: 0,
            last_config_hash: provenance.internal_config_hash.clone(),
            root_version: None,
            break_glass: Default::default(),
            local_approvals: Default::default(),
        })
        .expect("antirollback state initializes");
}

fn build_auth() -> Arc<ApiKeyAuth> {
    let entries = vec![
        ApiKeyEntry::new(
            "admin".to_string(),
            ScopeSet::from_iter([
                "registry_relay:admin",
                "social_registry:metadata",
                "social_registry:rows",
            ]),
            make_fingerprint(ADMIN_KEY),
        )
        .expect("admin fingerprint parses"),
        ApiKeyEntry::new(
            "reader".to_string(),
            ScopeSet::from_iter(["social_registry:metadata"]),
            make_fingerprint(NON_ADMIN_KEY),
        )
        .expect("reader fingerprint parses"),
        ApiKeyEntry::new(
            "ops".to_string(),
            ScopeSet::from_iter(["registry_relay:ops_read"]),
            make_fingerprint(OPS_KEY),
        )
        .expect("ops fingerprint parses"),
    ];
    Arc::new(ApiKeyAuth::new(entries))
}

fn build_fixture() -> AdminFixture {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    build_fixture_from_config_path(tmp, config_path)
}

fn build_fixture_with_required_break_glass_approvers(count: usize) -> AdminFixture {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let config = std::fs::read_to_string(&config_path).expect("config reads");
    std::fs::write(
        &config_path,
        config.replace(
            "  break_glass_rate_limit:\n    max_accepted: 1\n    window_seconds: 3600\n",
            &format!(
                "  break_glass_rate_limit:\n    max_accepted: 1\n    window_seconds: 3600\n  required_approver_count:\n    emergency.break_glass: {count}\n"
            ),
        ),
    )
    .expect("config writes");
    build_fixture_from_config_path(tmp, config_path)
}

fn build_fail_closed_fixture_with_failing_audit_sink() -> AdminFixture {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let raw = std::fs::read_to_string(&config_path).expect("config reads");
    std::fs::write(
        &config_path,
        raw.replace(
            "  hash_secret_env: REGISTRY_RELAY_TEST_AUDIT_HASH_SECRET\n",
            "  hash_secret_env: REGISTRY_RELAY_TEST_AUDIT_HASH_SECRET\n  write_policy: fail_closed\n",
        ),
    )
    .expect("config writes");
    build_fixture_from_config_path_with_audit_pipeline(
        tmp,
        config_path,
        false,
        None,
        AuditPipeline::from_sink(AlwaysFailWriteSink),
        InMemorySink::new(),
    )
}

fn build_fixture_with_remote_tuf_repository(server: &MockServer) -> AdminFixture {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    insert_remote_tuf_repository(&config_path, &tmp, server);
    build_fixture_from_config_path(tmp, config_path)
}

fn insert_remote_tuf_repository(config_path: &Path, tmp: &TempDir, server: &MockServer) {
    let yaml = std::fs::read_to_string(config_path).expect("config reads");
    let repo_dir = tmp.path().join("signed-config-5");
    let remote = format!(
        r#"  remote_tuf_repositories:
    - root_path: "{}"
      metadata_base_url: "{}/metadata"
      targets_base_url: "{}/targets"
      datastore_dir: "{}"
      allow_dev_insecure_fetch_urls: true
"#,
        repo_dir.join("metadata/1.root.json").display(),
        server.uri(),
        server.uri(),
        repo_dir.join("datastore").display()
    );
    std::fs::write(
        config_path,
        yaml.replace("  accepted_roots:\n", &(remote + "  accepted_roots:\n")),
    )
    .expect("config writes");
}

fn build_fixture_without_admin_bind() -> AdminFixture {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config_without_admin_bind(&tmp);
    build_fixture_from_config_path(tmp, config_path)
}

fn build_fixture_without_metadata() -> AdminFixture {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let config = std::fs::read_to_string(&config_path)
        .expect("config reads")
        .replace("\nmetadata:\n  source:\n    path: metadata.yaml\n", "\n");
    std::fs::write(&config_path, config).expect("config writes");
    build_fixture_from_config_path(tmp, config_path)
}

#[test]
fn simple_local_config_without_config_trust_still_loads() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config_with_instance_and_trust(
        &tmp,
        Some(
            r#"instance:
  id: relay-test-instance
  environment: lab
"#,
        ),
        false,
    );

    let config = config::load(&config_path).expect("simple local config loads");

    assert!(config.config_trust.is_none());
}

async fn assert_problem(resp: axum_test::TestResponse, status: StatusCode, code: &str) -> Value {
    resp.assert_status(status);
    assert!(resp
        .header("content-type")
        .to_str()
        .expect("content-type is ASCII")
        .starts_with("application/problem+json"));
    let body: Value = resp.json();
    assert_eq!(body["code"], code);
    body
}

fn assert_not_contains_any(haystack: &str, forbidden: &[&str]) {
    for needle in forbidden {
        assert!(
            !haystack.contains(needle),
            "posture response leaked forbidden material: {needle}"
        );
    }
}

#[tokio::test]
async fn health_remains_unauthenticated_on_admin_app() {
    let fixture = build_fixture();

    let resp = fixture.server.get("/healthz").await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["checks"]["total"], 1);
    assert_eq!(body["checks"]["ok"], 1);
    assert_eq!(body["checks"]["failed"], 0);
}

#[tokio::test]
async fn table_reload_without_credential_is_rejected() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .post("/admin/v1/datasets/social_registry/tables/beneficiaries_csv/reload")
        .await;

    assert_problem(resp, StatusCode::UNAUTHORIZED, "auth.missing_credential").await;
}

#[tokio::test]
async fn table_reload_without_credential_is_rejected_before_runtime_inspection() {
    let server = TestServer::new(admin_router());

    let resp = server
        .post("/admin/v1/datasets/social_registry/tables/beneficiaries_csv/reload")
        .await;

    assert_problem(resp, StatusCode::UNAUTHORIZED, "auth.missing_credential").await;
}

#[tokio::test]
async fn table_reload_with_non_admin_key_is_rejected() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .post("/admin/v1/datasets/social_registry/tables/beneficiaries_csv/reload")
        .add_header("Authorization", format!("Bearer {NON_ADMIN_KEY}"))
        .await;

    let body = assert_problem(resp, StatusCode::FORBIDDEN, "auth.scope_denied").await;
    assert_eq!(body["detail"], "required scope: registry_relay:admin");
}

#[tokio::test]
async fn table_reload_with_admin_key_reaches_registry_reload_path() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .post("/admin/v1/datasets/social_registry/tables/beneficiaries_csv/reload")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["counts"]["reloaded"], 1);
    assert!(body.get("dataset_id").is_none());
    assert!(body.get("table_id").is_none());
    let dump = body.to_string();
    assert!(!dump.contains("social_registry"));
    assert!(!dump.contains("beneficiaries_csv"));
}

#[tokio::test]
async fn posture_requires_ops_read_scope() {
    let fixture = build_fixture();

    let missing = fixture.server.get("/admin/v1/posture").await;
    assert_problem(missing, StatusCode::UNAUTHORIZED, "auth.missing_credential").await;

    let admin_only = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await;
    let body = assert_problem(admin_only, StatusCode::FORBIDDEN, "auth.scope_denied").await;
    assert_eq!(body["detail"], "required scope: registry_relay:ops_read");

    let ops = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    ops.assert_status(StatusCode::OK);
}

#[tokio::test]
async fn invalid_posture_tier_uses_shared_admin_error_code() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .get("/admin/v1/posture?tier=complete")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;

    let body = assert_problem(
        resp,
        StatusCode::BAD_REQUEST,
        "registry.admin.posture.invalid_tier",
    )
    .await;
    assert_eq!(body["schema"], "registry.admin.error.v1");
    assert_eq!(body["message"], "invalid posture tier");
    assert_eq!(body["detail"], "posture tier must be default or restricted");
}

#[tokio::test]
async fn capabilities_requires_ops_read_and_reports_relay_admin_surface() {
    let fixture = build_fixture();

    let missing = fixture.server.get("/admin/v1/capabilities").await;
    assert_problem(missing, StatusCode::UNAUTHORIZED, "auth.missing_credential").await;

    let admin_only = fixture
        .server
        .get("/admin/v1/capabilities")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await;
    let body = assert_problem(admin_only, StatusCode::FORBIDDEN, "auth.scope_denied").await;
    assert_eq!(body["detail"], "required scope: registry_relay:ops_read");

    let resp = fixture
        .server
        .get("/admin/v1/capabilities")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    resp.assert_status(StatusCode::OK);
    assert_eq!(
        resp.header("cache-control")
            .to_str()
            .expect("cache-control is ASCII"),
        "no-store"
    );
    let body: Value = resp.json();
    assert_matches_admin_capabilities_schema(&body);
    assert_eq!(body["schema"], "registry.admin.capabilities.v1");
    assert_eq!(body["product"], "registry-relay");
    assert_eq!(
        body["supported_posture_tiers"],
        json!(["default", "restricted"])
    );
    assert_eq!(body.get("scopes"), None);
    assert_eq!(
        body["config"]["verify"],
        json!({
            "supported": true,
            "currently_available": true
        })
    );
    assert_eq!(
        body["config"]["dry_run"],
        json!({
            "supported": true,
            "currently_available": true
        })
    );
    assert_eq!(body["config"]["apply"]["requires_signed_input"], true);
    assert_eq!(
        body["config"]["apply"]["supported_sources"],
        json!(["tuf_local", "tuf_remote"])
    );
    assert_eq!(body["break_glass"]["rate_limit_scope"], "instance");
    assert_eq!(
        body["listeners"],
        json!({
            "admin": {
                "mode": "dedicated",
                "public_admin_routes": false
            },
            "metrics": {
                "mode": "admin",
                "requires_admin_scope": false,
                "required_scope": "registry_relay:metrics_read"
            }
        })
    );
    assert_eq!(body["listeners"]["admin"].get("bind"), None);
    assert_eq!(body["listeners"]["metrics"].get("bind"), None);
    assert_eq!(body["root_transition"]["supported"], true);
    assert_eq!(
        body["hot_swap"]["components"],
        json!([
            "config_provenance",
            "compiled_metadata",
            "auth_provider",
            "provenance_state"
        ])
    );
    assert_eq!(body["reload"]["resource_reload"]["supported"], true);
    assert_eq!(body["reload"]["table_reload"]["supported"], true);
    assert_eq!(body["reload"]["config_reload"]["supported"], false);
}

#[tokio::test]
async fn capabilities_reports_disabled_listener_topology_without_admin_bind() {
    let fixture = build_fixture_without_admin_bind();

    let resp = fixture
        .server
        .get("/admin/v1/capabilities")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    resp.assert_status(StatusCode::OK);

    let body: Value = resp.json();
    assert_matches_admin_capabilities_schema(&body);
    assert_eq!(
        body["listeners"],
        json!({
            "admin": {
                "mode": "disabled",
                "public_admin_routes": false
            },
            "metrics": {
                "mode": "disabled",
                "requires_admin_scope": false,
                "required_scope": "registry_relay:metrics_read"
            }
        })
    );
    assert_eq!(body["listeners"]["admin"].get("bind"), None);
    assert_eq!(body["listeners"]["metrics"].get("bind"), None);
}

#[test]
fn governed_config_docs_do_not_ship_unresolved_config_trust_placeholders() {
    let doc = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/configuration.md"),
    )
    .expect("configuration doc reads");

    assert!(
        doc.contains("syntactically valid but illustrative"),
        "governed config example must be explicitly labeled as illustrative"
    );
    assert!(
        !doc.contains("REPLACE_WITH_FINAL"),
        "governed config example must not contain replacement placeholders"
    );
    assert!(
        !doc.contains("TUF_TARGETS_ROLE_KEY_ID"),
        "governed config example must use concrete illustrative key IDs"
    );
    assert!(
        doc.contains("\"1111111111111111111111111111111111111111111111111111111111111111\""),
        "illustrative all-digit TUF key IDs must be quoted for YAML parsers"
    );
}

#[tokio::test]
async fn ops_read_key_cannot_reload() {
    let fixture = build_fixture();

    for route in [
        "/admin/v1/reload",
        "/admin/v1/datasets/social_registry/tables/beneficiaries_csv/reload",
    ] {
        let resp = fixture
            .server
            .post(route)
            .add_header("Authorization", format!("Bearer {OPS_KEY}"))
            .await;

        let body = assert_problem(resp, StatusCode::FORBIDDEN, "auth.scope_denied").await;
        assert_eq!(
            body["detail"], "required scope: registry_relay:admin",
            "route: {route}"
        );
    }
}

fn config_apply_request(fixture: &AdminFixture, config_yaml: String, sequence: u64) -> Value {
    json!({
        "bundle_id": "test-bundle",
        "stream_id": "test-stream",
        "sequence": sequence,
        "previous_config_hash": fixture.current_config_hash,
        "config_yaml": config_yaml,
    })
}

fn signed_tuf_apply_request(signed: &SignedConfigFixture) -> Value {
    json!({
        "tuf": {
            "root_path": signed.root_path,
            "metadata_dir": signed.metadata_dir,
            "targets_dir": signed.targets_dir,
            "datastore_dir": signed.datastore_dir,
            "target_name": signed.target_name,
        }
    })
}

fn remote_signed_tuf_apply_request(signed: &SignedConfigFixture, server: &MockServer) -> Value {
    json!({
        "tuf": {
            "root_path": signed.root_path,
            "metadata_base_url": format!("{}/metadata", server.uri()),
            "targets_base_url": format!("{}/targets", server.uri()),
            "datastore_dir": signed.datastore_dir,
            "target_name": signed.target_name,
            "allow_dev_insecure_fetch_urls": true,
        }
    })
}

async fn mount_signed_tuf_fixture(server: &MockServer, signed: &SignedConfigFixture) {
    mount_directory_files(server, "/metadata", &signed.metadata_dir).await;
    mount_directory_files(server, "/targets", &signed.targets_dir).await;
    Mock::given(method("GET"))
        .and(path("/metadata/2.root.json"))
        .respond_with(ResponseTemplate::new(404))
        .mount(server)
        .await;
}

async fn mount_directory_files(server: &MockServer, url_prefix: &str, dir: &Path) {
    for entry in std::fs::read_dir(dir).expect("directory reads") {
        let entry = entry.expect("directory entry reads");
        let path_on_disk = entry.path();
        if !path_on_disk.is_file() {
            continue;
        }
        let filename = path_on_disk
            .file_name()
            .and_then(|name| name.to_str())
            .expect("fixture filename is UTF-8");
        Mock::given(method("GET"))
            .and(path(format!("{url_prefix}/{filename}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(
                    std::fs::read(path_on_disk).expect("generated repo file reads"),
                ),
            )
            .mount(server)
            .await;
    }
}

fn break_glass_approval() -> Value {
    let expires_at_unix_seconds = Utc::now().timestamp() as u64 + 3600;
    json!({
        "approved_by": "ops@example.test",
        "reason": "recover from bad live config",
        "approval_reference": "INC-4242",
        "emergency_change_class": EMERGENCY_CHANGE_CLASS,
        "expires_at_unix_seconds": expires_at_unix_seconds,
        "rate_limit_identity": "registry-relay/relay-test-instance/lab/test-stream"
    })
}

fn break_glass_rate_limit() -> Value {
    json!({
        "max_accepted": 1,
        "window_seconds": 3600
    })
}

fn local_approval(reference: &str, config_hash: &str, previous_config_hash: &str) -> Value {
    local_approval_for_change_class(
        reference,
        "root_transition",
        config_hash,
        previous_config_hash,
    )
}

fn local_approval_for_change_class(
    reference: &str,
    change_class: &str,
    config_hash: &str,
    previous_config_hash: &str,
) -> Value {
    let expires_at_unix_seconds = Utc::now().timestamp() as u64 + 3600;
    json!({
        "approved_by": "ops@example.test",
        "reason": format!("approve local {change_class}"),
        "approval_reference": reference,
        "change_class": change_class,
        "config_hash": config_hash,
        "previous_config_hash": previous_config_hash,
        "expires_at_unix_seconds": expires_at_unix_seconds,
        "rate_limit_identity": format!("registry-relay/relay-test-instance/lab/test-stream/{change_class}"),
        "rate_limit": {
            "max_accepted": 1,
            "window_seconds": 3600
        }
    })
}

fn durable_break_glass_approval(
    reference: &str,
    config_hash: &str,
    previous_config_hash: Option<&str>,
    approvers: &[&str],
) -> Value {
    let placeholder = fixture_hash_placeholder();
    let mut approval = local_approval_for_change_class(
        reference,
        EMERGENCY_CHANGE_CLASS,
        config_hash,
        previous_config_hash.unwrap_or(&placeholder),
    );
    if previous_config_hash.is_none() {
        approval
            .as_object_mut()
            .expect("approval is object")
            .remove("previous_config_hash");
    }
    approval["approved_by"] = json!("ops-primary@example.test");
    approval["approvers"] = json!(approvers);
    approval["reason"] = json!("stored emergency approval reason");
    approval["rate_limit_identity"] = json!("registry-relay/relay-test-instance/lab/test-stream");
    approval
}

fn fixture_hash_placeholder() -> String {
    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string()
}

fn write_local_approval(fixture: &AdminFixture, approval: Value) {
    std::fs::write(
        &fixture.local_approval_path,
        serde_json::to_vec_pretty(&json!({ "approvals": [approval] }))
            .expect("local approval file serializes"),
    )
    .expect("local approval file writes");
}

fn candidate_with_additional_accepted_root(fixture: &AdminFixture) -> String {
    let config_yaml = std::fs::read_to_string(&fixture.config_path).expect("config reads");
    let tuf_root_sha256 = sha256_uri(
        &std::fs::read(tough_fixture("simple-rsa").join("root.json"))
            .expect("trusted TUF root fixture reads"),
    );
    let additional_root = format!(
        r#"    - root_id: ops-root-next
      production: false
      tuf_root_sha256: "{}"
      high_risk_change_classes: []
      signers:
        {}:
          kid: {}
          enabled: true
      roles:
        - name: config-admin
          threshold: 1
          signer_kids:
            - {}
          allowed_change_classes:
            - root_transition

"#,
        tuf_root_sha256, TUF_TARGETS_SIGNER_KID, TUF_TARGETS_SIGNER_KID, TUF_TARGETS_SIGNER_KID
    );
    config_yaml.replace(
        "\nmetadata:\n  source:",
        &format!("\n{additional_root}metadata:\n  source:"),
    )
}

async fn write_signed_config_tuf_fixture(
    fixture: &AdminFixture,
    config_yaml: &str,
    sequence: u64,
    instance_id: &str,
    signer_kids: &[&str],
) -> SignedConfigFixture {
    write_signed_config_tuf_fixture_with_change_classes(
        fixture,
        config_yaml,
        sequence,
        instance_id,
        signer_kids,
        &["public_metadata"],
    )
    .await
}

async fn write_signed_config_tuf_fixture_with_change_classes(
    fixture: &AdminFixture,
    config_yaml: &str,
    sequence: u64,
    instance_id: &str,
    signer_kids: &[&str],
    change_classes: &[&str],
) -> SignedConfigFixture {
    write_signed_config_tuf_fixture_with_previous_hash_and_change_classes(
        fixture,
        config_yaml,
        sequence,
        instance_id,
        signer_kids,
        change_classes,
        &fixture.current_config_hash,
    )
    .await
}

async fn write_signed_config_tuf_fixture_with_previous_hash_and_change_classes(
    fixture: &AdminFixture,
    config_yaml: &str,
    sequence: u64,
    instance_id: &str,
    signer_kids: &[&str],
    change_classes: &[&str],
    previous_config_hash: &str,
) -> SignedConfigFixture {
    let repo_dir = fixture
        ._tmp
        .path()
        .join(format!("signed-config-{sequence}"));
    let source_dir = repo_dir.join("source");
    let metadata_dir = repo_dir.join("metadata");
    let targets_dir = repo_dir.join("targets");
    let datastore_dir = repo_dir.join("datastore");
    std::fs::create_dir_all(&source_dir).expect("source dir");
    std::fs::create_dir_all(&datastore_dir).expect("datastore dir");
    let target_name = "registry-relay.yaml";
    let target_path = source_dir.join(target_name);
    std::fs::write(&target_path, config_yaml).expect("target config writes");

    let mut target = Target::from_path(&target_path)
        .await
        .expect("target metadata builds");
    let custom = json!({
        "product": "registry-relay",
        "instance_id": instance_id,
        "environment": "lab",
        "stream_id": "test-stream",
        "bundle_id": "test-bundle",
        "sequence": sequence,
        "previous_config_hash": previous_config_hash,
        "config_hash": sha256_uri(config_yaml.as_bytes()),
        "change_classes": change_classes,
        "signer_kids": signer_kids,
        "apply_policy": "live"
    });
    target.custom = custom
        .as_object()
        .expect("custom target metadata is an object")
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    let root_path = tough_fixture("simple-rsa").join("root.json");
    let key_path = tough_fixture("snakeoil.pem");
    let signing_keys: &[Box<dyn tough::key_source::KeySource>] =
        &[Box::new(LocalKeySource { path: key_path })];
    let mut editor = RepositoryEditor::new(&root_path)
        .await
        .expect("repository editor builds");
    editor
        .targets_expires(Utc::now() + chrono::Duration::days(13))
        .expect("targets expiration");
    editor
        .targets_version(NonZeroU64::new(sequence).expect("nonzero targets version"))
        .expect("targets version");
    editor.snapshot_expires(Utc::now() + chrono::Duration::days(21));
    editor.snapshot_version(NonZeroU64::new(sequence).expect("nonzero snapshot version"));
    editor.timestamp_expires(Utc::now() + chrono::Duration::days(3));
    editor.timestamp_version(NonZeroU64::new(sequence).expect("nonzero timestamp version"));
    editor
        .add_target(target_name, target)
        .expect("target added");
    let signed_repo = editor.sign(signing_keys).await.expect("repository signs");
    signed_repo
        .write(&metadata_dir)
        .await
        .expect("metadata writes");
    signed_repo
        .copy_targets(&source_dir, &targets_dir, PathExists::Fail)
        .await
        .expect("targets write");

    SignedConfigFixture {
        root_path: metadata_dir.join("1.root.json"),
        metadata_dir,
        targets_dir,
        datastore_dir,
        target_name: target_name.to_string(),
    }
}

async fn write_signed_config_tuf_fixture_with_metadata(
    fixture: &AdminFixture,
    config_yaml: &str,
    metadata_yaml: &str,
    source_manifest_digest: &str,
    sequence: u64,
) -> SignedConfigFixture {
    let repo_dir = fixture
        ._tmp
        .path()
        .join(format!("signed-config-metadata-{sequence}"));
    let source_dir = repo_dir.join("source");
    let metadata_dir = repo_dir.join("metadata");
    let targets_dir = repo_dir.join("targets");
    let datastore_dir = repo_dir.join("datastore");
    std::fs::create_dir_all(&source_dir).expect("source dir");
    std::fs::create_dir_all(&datastore_dir).expect("datastore dir");
    let target_name = "registry-relay.yaml";
    let metadata_target_name = "metadata.yaml";
    let target_path = source_dir.join(target_name);
    let metadata_path = source_dir.join(metadata_target_name);
    std::fs::write(&target_path, config_yaml).expect("target config writes");
    std::fs::write(&metadata_path, metadata_yaml).expect("metadata target writes");

    let mut target = Target::from_path(&target_path)
        .await
        .expect("target metadata builds");
    let custom = json!({
        "product": "registry-relay",
        "instance_id": "relay-test-instance",
        "environment": "lab",
        "stream_id": "test-stream",
        "bundle_id": "test-bundle",
        "sequence": sequence,
        "previous_config_hash": fixture.current_config_hash,
        "config_hash": sha256_uri(config_yaml.as_bytes()),
        "change_classes": ["public_metadata"],
        "signer_kids": [TUF_TARGETS_SIGNER_KID],
        "apply_policy": "live",
        "metadata_target_name": metadata_target_name,
        "source_manifest_digest": source_manifest_digest,
        "metadata_schema_version": "registry-manifest/v1"
    });
    target.custom = custom
        .as_object()
        .expect("custom target metadata is an object")
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let metadata_target = Target::from_path(&metadata_path)
        .await
        .expect("metadata target metadata builds");

    let root_path = tough_fixture("simple-rsa").join("root.json");
    let key_path = tough_fixture("snakeoil.pem");
    let signing_keys: &[Box<dyn tough::key_source::KeySource>] =
        &[Box::new(LocalKeySource { path: key_path })];
    let mut editor = RepositoryEditor::new(&root_path)
        .await
        .expect("repository editor builds");
    editor
        .targets_expires(Utc::now() + chrono::Duration::days(13))
        .expect("targets expiration");
    editor
        .targets_version(NonZeroU64::new(sequence).expect("nonzero targets version"))
        .expect("targets version");
    editor.snapshot_expires(Utc::now() + chrono::Duration::days(21));
    editor.snapshot_version(NonZeroU64::new(sequence).expect("nonzero snapshot version"));
    editor.timestamp_expires(Utc::now() + chrono::Duration::days(3));
    editor.timestamp_version(NonZeroU64::new(sequence).expect("nonzero timestamp version"));
    editor
        .add_target(target_name, target)
        .expect("config target added");
    editor
        .add_target(metadata_target_name, metadata_target)
        .expect("metadata target added");
    let signed_repo = editor.sign(signing_keys).await.expect("repository signs");
    signed_repo
        .write(&metadata_dir)
        .await
        .expect("metadata writes");
    signed_repo
        .copy_targets(&source_dir, &targets_dir, PathExists::Fail)
        .await
        .expect("targets write");

    SignedConfigFixture {
        root_path: metadata_dir.join("1.root.json"),
        metadata_dir,
        targets_dir,
        datastore_dir,
        target_name: target_name.to_string(),
    }
}

async fn post_admin_config(
    fixture: &AdminFixture,
    route: &str,
    body: Value,
    token: &str,
) -> axum_test::TestResponse {
    fixture
        .server
        .post(route)
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&body)
        .await
}

fn audit_records(fixture: &AdminFixture) -> Vec<Value> {
    fixture
        .audit_sink
        .snapshot()
        .into_iter()
        .map(|line| {
            let envelope: Value =
                serde_json::from_str(line.trim_end()).expect("audit envelope JSON");
            envelope["record"].clone()
        })
        .collect()
}

fn config_audit_record(fixture: &AdminFixture, path: &str) -> Value {
    audit_records(fixture)
        .into_iter()
        .find(|record| record["path"] == path && record.get("config").is_some())
        .unwrap_or_else(|| panic!("missing config audit record for {path}"))
}

#[tokio::test]
async fn config_apply_routes_are_admin_only_and_not_public() {
    let fixture = build_fixture();
    let body = config_apply_request(
        &fixture,
        std::fs::read_to_string(&fixture.config_path).expect("config reads"),
        1,
    );

    for route in [
        "/admin/v1/config/verify",
        "/admin/v1/config/dry-run",
        "/admin/v1/config/apply",
    ] {
        let public = fixture.public_server.post(route).json(&body).await;
        assert!(
            matches!(
                public.status_code(),
                StatusCode::NOT_FOUND | StatusCode::UNAUTHORIZED
            ),
            "route {route} must not be reachable on the public app"
        );

        assert_problem(
            fixture.server.post(route).json(&body).await,
            StatusCode::UNAUTHORIZED,
            "auth.missing_credential",
        )
        .await;

        let ops = post_admin_config(&fixture, route, body.clone(), OPS_KEY).await;
        let body = assert_problem(ops, StatusCode::FORBIDDEN, "auth.scope_denied").await;
        assert_eq!(
            body["detail"], "required scope: registry_relay:admin",
            "route: {route}"
        );
    }
}

#[tokio::test]
async fn admin_json_checks_scope_before_parsing_body() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .post("/admin/v1/config/verify")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .add_header("content-type", "application/json")
        .text("{not json")
        .await;

    let body = assert_problem(resp, StatusCode::FORBIDDEN, "auth.scope_denied").await;
    assert_eq!(body["detail"], "required scope: registry_relay:admin");
}

#[tokio::test]
async fn config_dry_run_reports_restart_required_without_swapping() {
    let fixture = build_fixture();
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("bind: 127.0.0.1:0", "bind: 127.0.0.1:8181");

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/dry-run",
        config_apply_request(&fixture, candidate, 2),
        ADMIN_KEY,
    )
    .await;

    if response.status_code() != StatusCode::OK {
        let body: Value = response.json();
        panic!("client access change apply should succeed, got {body:#}");
    }
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_restart_required");
    assert_eq!(body["posture_result"], "rejected");
    assert_eq!(body["restart_required"], true);
    assert_eq!(body["applied"], false);
    let rendered = body.to_string();
    assert!(!rendered.contains("social_registry.csv"));
    assert!(!rendered.contains("REGISTRY_RELAY_TEST_PRIVATE_JWK"));

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);

    let record = config_audit_record(&fixture, "/admin/v1/config/dry-run");
    assert_eq!(record["config"]["action"], "dry_run");
    assert_eq!(record["config"]["source"], "local_file");
}

#[tokio::test]
async fn config_apply_restart_required_change_is_rejected_without_swapping() {
    let fixture = build_fixture();
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("bind: 127.0.0.1:0", "bind: 127.0.0.1:8181");
    let signed = write_signed_config_tuf_fixture(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_restart_required");
    assert_eq!(body["posture_result"], "rejected");
    assert_eq!(body["restart_required"], true);
    assert_eq!(body["applied"], false);

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["instance"]["owner"], "Test Ministry");
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_invalid_candidate_does_not_swap() {
    let fixture = build_fixture();
    let signed = write_signed_config_tuf_fixture(
        &fixture,
        "not: [valid",
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    let body = assert_problem(
        response,
        StatusCode::BAD_REQUEST,
        "admin.config_candidate_invalid",
    )
    .await;
    assert!(!body.to_string().contains("not: [valid"));

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["instance"]["owner"], "Test Ministry");
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_catalog_base_url_change_is_restart_required_without_swapping() {
    let fixture = build_fixture();
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace(
            "base_url: https://data.example.test",
            "base_url: https://other-data.example.test",
        );
    let signed = write_signed_config_tuf_fixture(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &[TUF_TARGETS_SIGNER_KID],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_restart_required");
    assert_eq!(body["posture_result"], "rejected");
    assert_eq!(body["restart_required"], true);
    assert_eq!(body["applied"], false);

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_trust_change_is_restart_required_without_swapping() {
    let fixture = build_fixture();
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("root_id: ops-root", "root_id: attacker-root");
    let signed = write_signed_config_tuf_fixture(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_restart_required");
    assert_eq!(body["posture_result"], "rejected");
    assert_eq!(body["restart_required"], true);
    assert_eq!(body["applied"], false);

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_instance_identity_change_is_restart_required_without_swapping() {
    let fixture = build_fixture();
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("id: relay-test-instance", "id: relay-other-instance");
    let signed = write_signed_config_tuf_fixture(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_restart_required");
    assert_eq!(body["posture_result"], "rejected");
    assert_eq!(body["restart_required"], true);
    assert_eq!(body["applied"], false);

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["instance"]["id"], "relay-test-instance");
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_client_access_change_swaps_auth_provider() {
    const ROTATED_ADMIN_KEY: &str = "rotated-admin-token";
    const ROTATED_ADMIN_HASH_ENV: &str = "REGISTRY_RELAY_TEST_ROTATED_API_KEY_HASH";
    let rotated_fingerprint = make_fingerprint(ROTATED_ADMIN_KEY);
    std::env::set_var(ROTATED_ADMIN_HASH_ENV, &rotated_fingerprint);
    let fixture = build_fixture_without_metadata();
    let rotated_fingerprint_ref = fingerprint_ref_yaml(
        "rotated_admin",
        ROTATED_ADMIN_HASH_ENV,
        &rotated_fingerprint,
        "      ",
    );
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace(
            "api_keys: []",
            &format!(
                "api_keys:\n    - id: rotated_admin\n{rotated_fingerprint_ref}\n      scopes:\n        - registry_relay:admin\n        - registry_relay:ops_read"
            ),
        );
    let candidate_hash = internal_config_hash(candidate.as_bytes());
    write_local_approval(
        &fixture,
        local_approval_for_change_class(
            "CLIENT-ACCESS-1",
            "client_access_change",
            &candidate_hash,
            &fixture.current_config_hash,
        ),
    );
    let signed = write_signed_config_tuf_fixture_with_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["client_access_change"],
    )
    .await;
    let mut request = signed_tuf_apply_request(&signed);
    request["local_approval_reference"] = json!("CLIENT-ACCESS-1");

    let response = post_admin_config(&fixture, "/admin/v1/config/apply", request, ADMIN_KEY).await;

    if response.status_code() != StatusCode::OK {
        let body: Value = response.json();
        panic!("client access change apply should succeed, got {body:#}");
    }
    let body: Value = response.json();
    assert_eq!(body["result"], "applied");
    assert_eq!(body["applied"], true);
    assert_eq!(body["restart_required"], false);

    let old_admin = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await;
    assert_problem(
        old_admin,
        StatusCode::UNAUTHORIZED,
        "auth.invalid_credential",
    )
    .await;

    let rotated_admin = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {ROTATED_ADMIN_KEY}"))
        .await;
    rotated_admin.assert_status(StatusCode::OK);
}

#[tokio::test]
async fn config_apply_dataset_query_change_is_restart_required_without_swapping() {
    let fixture = build_fixture();
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("max_limit: 1000", "max_limit: 999");
    let signed = write_signed_config_tuf_fixture_with_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["public_metadata"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_restart_required");
    assert_eq!(body["applied"], false);
    assert_eq!(body["restart_required"], true);

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_missing_antirollback_state_fails_closed() {
    let fixture = build_fixture();
    std::fs::remove_file(&fixture.antirollback_path).expect("remove antirollback state");
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("owner: Test Ministry", "owner: Operations Ministry");
    let signed = write_signed_config_tuf_fixture(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_rollback");
    assert_eq!(body["posture_result"], "rejected");
    assert_eq!(body["applied"], false);

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["instance"]["owner"], "Test Ministry");
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_break_glass_is_rejected_without_swapping() {
    let fixture = build_fixture();
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("owner: Test Ministry", "owner: Emergency Ministry");
    let signed = write_signed_config_tuf_fixture(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
    )
    .await;
    let mut request = signed_tuf_apply_request(&signed);
    request["break_glass"] = json!(true);
    request["previous_config_hash"] =
        json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");

    let response = post_admin_config(&fixture, "/admin/v1/config/apply", request, ADMIN_KEY).await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_break_glass");
    assert_eq!(body["posture_result"], "rejected");
    assert_eq!(body["applied"], false);

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["instance"]["owner"], "Test Ministry");
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_break_glass_requires_signed_emergency_change_class() {
    let fixture = build_fixture();
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("owner: Test Ministry", "owner: Emergency Ministry");
    let wrong_previous_hash =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let signed = write_signed_config_tuf_fixture_with_previous_hash_and_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["public_metadata"],
        wrong_previous_hash,
    )
    .await;
    let mut request = signed_tuf_apply_request(&signed);
    request["break_glass"] = json!(true);
    request["break_glass_approval"] = break_glass_approval();

    let response = post_admin_config(&fixture, "/admin/v1/config/apply", request, ADMIN_KEY).await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_break_glass");
    assert_eq!(body["applied"], false);

    let record = FileAntiRollbackStore::new(&fixture.antirollback_path)
        .load(&AntiRollbackKey {
            product: "registry-relay".to_string(),
            instance_id: "relay-test-instance".to_string(),
            environment: "lab".to_string(),
            stream_id: "test-stream".to_string(),
        })
        .expect("antirollback state loads");
    assert_eq!(record.last_sequence, 0);
    assert_eq!(record.last_config_hash, fixture.current_config_hash);
    assert!(record.break_glass.accepted.is_empty());
}

#[tokio::test]
async fn config_apply_signed_tuf_break_glass_with_approval_swaps_runtime_snapshot() {
    let fixture = build_fixture();
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("owner: Test Ministry", "owner: Emergency Ministry");
    let wrong_previous_hash =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let signed = write_signed_config_tuf_fixture_with_previous_hash_and_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["public_metadata", EMERGENCY_CHANGE_CLASS],
        wrong_previous_hash,
    )
    .await;
    let mut request = signed_tuf_apply_request(&signed);
    request["break_glass"] = json!(true);
    request["break_glass_approval"] = break_glass_approval();

    let response = post_admin_config(&fixture, "/admin/v1/config/apply", request, ADMIN_KEY).await;

    if response.status_code() != StatusCode::OK {
        let body: Value = response.json();
        panic!("approved break-glass apply should succeed, got {body:#}");
    }
    let body: Value = response.json();
    assert_eq!(body["result"], "applied");
    assert_eq!(body["posture_result"], "accepted");
    assert_eq!(body["applied"], true);

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["instance"]["owner"], "Emergency Ministry");
    assert_eq!(posture["configuration"]["last_apply_result"], "accepted");

    let record = FileAntiRollbackStore::new(&fixture.antirollback_path)
        .load(&AntiRollbackKey {
            product: "registry-relay".to_string(),
            instance_id: "relay-test-instance".to_string(),
            environment: "lab".to_string(),
            stream_id: "test-stream".to_string(),
        })
        .expect("antirollback state loads");
    assert_eq!(record.last_sequence, 5);
    assert_ne!(record.last_config_hash, fixture.current_config_hash);
    assert_eq!(record.break_glass.accepted.len(), 1);
    assert_eq!(record.break_glass.accepted[0].sequence, 5);
    assert_eq!(
        record.break_glass.accepted[0].approval_reference,
        "INC-4242"
    );
    assert_eq!(
        record.break_glass.accepted[0].rate_limit_identity,
        "registry-relay/relay-test-instance/lab/test-stream"
    );

    let audit_record = config_audit_record(&fixture, "/admin/v1/config/apply");
    let config_audit = &audit_record["config"];
    assert_eq!(config_audit["break_glass"], true);
    assert_eq!(config_audit["break_glass_approval_reference"], "INC-4242");
    assert!(config_audit["break_glass_approved_by"]
        .as_str()
        .is_some_and(|hash| hash.starts_with("sha256:")));
    assert_eq!(
        config_audit["break_glass_emergency_change_class"],
        EMERGENCY_CHANGE_CLASS
    );
    assert_eq!(
        config_audit["break_glass_rate_limit_identity"],
        "registry-relay/relay-test-instance/lab/test-stream"
    );
    assert!(config_audit["break_glass_reason_hash"]
        .as_str()
        .is_some_and(|hash| hash.starts_with("sha256:")));
    assert!(!serde_json::to_string(config_audit)
        .expect("config audit serializes")
        .contains("recover from bad live config"));
    assert!(!serde_json::to_string(config_audit)
        .expect("config audit serializes")
        .contains("ops@example.test"));
}

#[tokio::test]
async fn config_apply_signed_tuf_break_glass_with_stored_reference_emits_emergency_posture() {
    let fixture = build_fixture();
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("owner: Test Ministry", "owner: Stored Emergency Ministry");
    let candidate_hash = internal_config_hash(candidate.as_bytes());
    write_local_approval(
        &fixture,
        durable_break_glass_approval("BG-4242", &candidate_hash, None, &[]),
    );
    let wrong_previous_hash =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let signed = write_signed_config_tuf_fixture_with_previous_hash_and_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["public_metadata", EMERGENCY_CHANGE_CLASS],
        wrong_previous_hash,
    )
    .await;
    let mut request = signed_tuf_apply_request(&signed);
    request["break_glass"] = json!(true);
    request["break_glass_approval_reference"] = json!("BG-4242");

    let response = post_admin_config(&fixture, "/admin/v1/config/apply", request, ADMIN_KEY).await;

    if response.status_code() != StatusCode::OK {
        let body: Value = response.json();
        panic!("stored break-glass apply should succeed, got {body:#}");
    }
    let body: Value = response.json();
    assert_eq!(body["result"], "applied");
    assert_eq!(body["posture_result"], "accepted");
    assert_eq!(body["applied"], true);

    let record = FileAntiRollbackStore::new(&fixture.antirollback_path)
        .load(&AntiRollbackKey {
            product: "registry-relay".to_string(),
            instance_id: "relay-test-instance".to_string(),
            environment: "lab".to_string(),
            stream_id: "test-stream".to_string(),
        })
        .expect("antirollback state loads");
    assert_eq!(record.last_sequence, 5);
    assert_eq!(record.break_glass.accepted.len(), 1);
    assert_eq!(record.break_glass.accepted[0].approval_reference, "BG-4242");
    assert_eq!(
        record.break_glass.accepted[0]
            .emergency_change_class
            .as_deref(),
        Some(EMERGENCY_CHANGE_CLASS)
    );

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_matches_posture_schema(&posture);
    assert_eq!(posture["instance"]["owner"], "Stored Emergency Ministry");
    assert_eq!(
        posture["configuration"]["emergency"]["last_apply_emergency"],
        true
    );
    assert_eq!(
        posture["configuration"]["emergency"]["last_emergency_change_class"],
        EMERGENCY_CHANGE_CLASS
    );
    assert_eq!(
        posture["configuration"]["emergency"]["exception_window_open"],
        true
    );
    assert_eq!(
        posture["configuration"]["emergency"]["open_exception_count"],
        1
    );
    let posture_text = serde_json::to_string(&posture).expect("posture serializes");
    assert!(!posture_text.contains("stored emergency approval reason"));
    assert!(!posture_text.contains("ops-primary@example.test"));

    let audit_record = config_audit_record(&fixture, "/admin/v1/config/apply");
    let audit_text = serde_json::to_string(&audit_record).expect("audit serializes");
    assert!(audit_text.contains("BG-4242"));
    assert!(audit_text.contains(EMERGENCY_CHANGE_CLASS));
    assert!(!audit_text.contains("stored emergency approval reason"));
    assert!(!audit_text.contains("ops-primary@example.test"));

    let replay_signed = write_signed_config_tuf_fixture_with_previous_hash_and_change_classes(
        &fixture,
        &candidate,
        6,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["public_metadata", EMERGENCY_CHANGE_CLASS],
        wrong_previous_hash,
    )
    .await;
    let mut replay_request = signed_tuf_apply_request(&replay_signed);
    replay_request["break_glass"] = json!(true);
    replay_request["break_glass_approval_reference"] = json!("BG-4242");
    let replay_response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        replay_request,
        ADMIN_KEY,
    )
    .await;
    replay_response.assert_status(StatusCode::CONFLICT);
    let replay_body: Value = replay_response.json();
    assert_eq!(replay_body["result"], "rejected_break_glass");

    let record = FileAntiRollbackStore::new(&fixture.antirollback_path)
        .load(&AntiRollbackKey {
            product: "registry-relay".to_string(),
            instance_id: "relay-test-instance".to_string(),
            environment: "lab".to_string(),
            stream_id: "test-stream".to_string(),
        })
        .expect("antirollback state loads");
    assert_eq!(record.last_sequence, 5);
    assert_eq!(record.break_glass.accepted.len(), 1);
}

#[tokio::test]
async fn config_apply_break_glass_required_approver_count_rejects_inline_and_single_stored_record()
{
    let fixture = build_fixture_with_required_break_glass_approvers(2);
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace(
            "owner: Test Ministry",
            "owner: Two Person Emergency Ministry",
        );
    let candidate_hash = internal_config_hash(candidate.as_bytes());
    let wrong_previous_hash =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let signed = write_signed_config_tuf_fixture_with_previous_hash_and_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["public_metadata", EMERGENCY_CHANGE_CLASS],
        wrong_previous_hash,
    )
    .await;

    let mut inline_request = signed_tuf_apply_request(&signed);
    inline_request["break_glass"] = json!(true);
    inline_request["break_glass_approval"] = break_glass_approval();
    let inline_response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        inline_request,
        ADMIN_KEY,
    )
    .await;
    inline_response.assert_status(StatusCode::CONFLICT);
    let inline_body: Value = inline_response.json();
    assert_eq!(inline_body["result"], "rejected_break_glass");

    write_local_approval(
        &fixture,
        durable_break_glass_approval("BG-4242", &candidate_hash, None, &[]),
    );
    let mut stored_request = signed_tuf_apply_request(&signed);
    stored_request["break_glass"] = json!(true);
    stored_request["break_glass_approval_reference"] = json!("BG-4242");
    let stored_response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        stored_request,
        ADMIN_KEY,
    )
    .await;
    stored_response.assert_status(StatusCode::CONFLICT);
    let stored_body: Value = stored_response.json();
    assert_eq!(stored_body["result"], "rejected_break_glass");

    let record = FileAntiRollbackStore::new(&fixture.antirollback_path)
        .load(&AntiRollbackKey {
            product: "registry-relay".to_string(),
            instance_id: "relay-test-instance".to_string(),
            environment: "lab".to_string(),
            stream_id: "test-stream".to_string(),
        })
        .expect("antirollback state loads");
    assert_eq!(record.last_sequence, 0);
    assert!(record.break_glass.accepted.is_empty());

    write_local_approval(
        &fixture,
        durable_break_glass_approval("BG-4243", &candidate_hash, None, &["ops-peer@example.test"]),
    );
    let mut two_approver_request = signed_tuf_apply_request(&signed);
    two_approver_request["break_glass"] = json!(true);
    two_approver_request["break_glass_approval_reference"] = json!("BG-4243");
    let two_approver_response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        two_approver_request,
        ADMIN_KEY,
    )
    .await;
    two_approver_response.assert_status(StatusCode::OK);
    let body: Value = two_approver_response.json();
    assert_eq!(body["result"], "applied");

    let record = FileAntiRollbackStore::new(&fixture.antirollback_path)
        .load(&AntiRollbackKey {
            product: "registry-relay".to_string(),
            instance_id: "relay-test-instance".to_string(),
            environment: "lab".to_string(),
            stream_id: "test-stream".to_string(),
        })
        .expect("antirollback state loads");
    assert_eq!(record.last_sequence, 5);
    assert_eq!(record.break_glass.accepted.len(), 1);
}

#[tokio::test]
async fn config_apply_stored_break_glass_requires_matching_signed_change_class() {
    let fixture = build_fixture();
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace(
            "owner: Test Ministry",
            "owner: Mismatched Emergency Ministry",
        );
    let candidate_hash = internal_config_hash(candidate.as_bytes());
    write_local_approval(
        &fixture,
        durable_break_glass_approval("BG-4242", &candidate_hash, None, &["ops-peer@example.test"]),
    );
    let wrong_previous_hash =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let signed = write_signed_config_tuf_fixture_with_previous_hash_and_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["public_metadata"],
        wrong_previous_hash,
    )
    .await;
    let mut request = signed_tuf_apply_request(&signed);
    request["break_glass"] = json!(true);
    request["break_glass_approval_reference"] = json!("BG-4242");

    let response = post_admin_config(&fixture, "/admin/v1/config/apply", request, ADMIN_KEY).await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_break_glass");
    assert_eq!(body["applied"], false);
}

#[tokio::test]
async fn config_apply_break_glass_rejects_client_supplied_rate_limit() {
    let fixture = build_fixture();
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("owner: Test Ministry", "owner: Emergency Ministry");
    let wrong_previous_hash =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let signed = write_signed_config_tuf_fixture_with_previous_hash_and_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["public_metadata", EMERGENCY_CHANGE_CLASS],
        wrong_previous_hash,
    )
    .await;
    let mut request = signed_tuf_apply_request(&signed);
    request["break_glass"] = json!(true);
    request["break_glass_approval"] = break_glass_approval();
    request["break_glass_rate_limit"] = break_glass_rate_limit();

    let response = post_admin_config(&fixture, "/admin/v1/config/apply", request, ADMIN_KEY).await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_break_glass");
    assert_eq!(body["applied"], false);

    let record = FileAntiRollbackStore::new(&fixture.antirollback_path)
        .load(&AntiRollbackKey {
            product: "registry-relay".to_string(),
            instance_id: "relay-test-instance".to_string(),
            environment: "lab".to_string(),
            stream_id: "test-stream".to_string(),
        })
        .expect("antirollback state loads");
    assert_eq!(record.last_sequence, 0);
    assert!(record.break_glass.accepted.is_empty());
}

#[tokio::test]
async fn config_apply_signed_root_transition_with_local_approval_swaps_runtime_snapshot() {
    let fixture = build_fixture();
    let candidate = candidate_with_additional_accepted_root(&fixture);
    let candidate_hash = internal_config_hash(candidate.as_bytes());
    write_local_approval(
        &fixture,
        local_approval(
            "ROOT-2026-Q2",
            &candidate_hash,
            &fixture.current_config_hash,
        ),
    );
    let signed = write_signed_config_tuf_fixture_with_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &[TUF_TARGETS_SIGNER_KID],
        &["root_transition"],
    )
    .await;
    let mut request = signed_tuf_apply_request(&signed);
    request["local_approval_reference"] = json!("ROOT-2026-Q2");

    let response = post_admin_config(&fixture, "/admin/v1/config/apply", request, ADMIN_KEY).await;

    if response.status_code() != StatusCode::OK {
        let body: Value = response.json();
        panic!("approved root transition apply should succeed, got {body:#}");
    }
    let body: Value = response.json();
    assert_eq!(body["result"], "applied");
    assert_eq!(body["posture_result"], "accepted");
    assert_eq!(body["applied"], true);
    assert_eq!(body["restart_required"], false);

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["configuration"]["last_apply_result"], "accepted");
    assert_eq!(
        fixture
            .handle
            .load_full()
            .config
            .config_trust
            .as_ref()
            .expect("config trust remains configured")
            .accepted_roots
            .len(),
        2
    );

    let record = FileAntiRollbackStore::new(&fixture.antirollback_path)
        .load(&AntiRollbackKey {
            product: "registry-relay".to_string(),
            instance_id: "relay-test-instance".to_string(),
            environment: "lab".to_string(),
            stream_id: "test-stream".to_string(),
        })
        .expect("antirollback state loads");
    assert_eq!(record.last_sequence, 5);
    assert_eq!(record.last_config_hash, candidate_hash);
    assert_eq!(record.local_approvals.accepted.len(), 1);
    assert_eq!(
        record.local_approvals.accepted[0].approval_reference,
        "ROOT-2026-Q2"
    );
    assert_eq!(
        record.local_approvals.accepted[0].change_class,
        "root_transition"
    );

    let loaded_approval = FileLocalApprovalStore::new(&fixture.local_approval_path)
        .load_for_apply(
            "ROOT-2026-Q2",
            "root_transition",
            &candidate_hash,
            Some(&fixture.current_config_hash),
        )
        .expect("local approval remains loadable for audit evidence");
    assert_eq!(loaded_approval.approved_by, "ops@example.test");

    let audit_record = config_audit_record(&fixture, "/admin/v1/config/apply");
    let config_audit = &audit_record["config"];
    assert_eq!(config_audit["local_approval_reference"], "ROOT-2026-Q2");
    assert_eq!(
        config_audit["local_approval_approved_by"],
        "ops@example.test"
    );
    assert_eq!(
        config_audit["local_approval_change_class"],
        "root_transition"
    );
    assert_eq!(
        config_audit["local_approval_rate_limit_identity"],
        "registry-relay/relay-test-instance/lab/test-stream/root_transition"
    );
    assert!(config_audit["local_approval_reason_hash"]
        .as_str()
        .is_some_and(|hash| hash.starts_with("sha256:")));
    assert!(!serde_json::to_string(config_audit)
        .expect("config audit serializes")
        .contains("approve local root transition"));
}

#[tokio::test]
async fn config_apply_signed_root_transition_missing_local_approval_rejects_without_antirollback() {
    let fixture = build_fixture();
    let candidate = candidate_with_additional_accepted_root(&fixture);
    let signed = write_signed_config_tuf_fixture_with_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &[TUF_TARGETS_SIGNER_KID],
        &["root_transition"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_local_approval");
    assert_eq!(body["posture_result"], "rejected");
    assert_eq!(body["applied"], false);
    assert_eq!(body["restart_required"], false);

    let record = FileAntiRollbackStore::new(&fixture.antirollback_path)
        .load(&AntiRollbackKey {
            product: "registry-relay".to_string(),
            instance_id: "relay-test-instance".to_string(),
            environment: "lab".to_string(),
            stream_id: "test-stream".to_string(),
        })
        .expect("antirollback state loads");
    assert_eq!(record.last_sequence, 0);
    assert_eq!(record.last_config_hash, fixture.current_config_hash);
    assert!(record.local_approvals.accepted.is_empty());

    assert_eq!(
        fixture
            .handle
            .load_full()
            .config
            .config_trust
            .as_ref()
            .expect("config trust remains configured")
            .accepted_roots
            .len(),
        1
    );
}

#[tokio::test]
async fn config_apply_signed_root_transition_wrong_class_is_restart_required() {
    let fixture = build_fixture();
    let candidate = candidate_with_additional_accepted_root(&fixture);
    let candidate_hash = internal_config_hash(candidate.as_bytes());
    write_local_approval(
        &fixture,
        local_approval(
            "ROOT-2026-Q2",
            &candidate_hash,
            &fixture.current_config_hash,
        ),
    );
    let signed = write_signed_config_tuf_fixture_with_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &[TUF_TARGETS_SIGNER_KID],
        &["public_metadata"],
    )
    .await;
    let mut request = signed_tuf_apply_request(&signed);
    request["local_approval_reference"] = json!("ROOT-2026-Q2");

    let response = post_admin_config(&fixture, "/admin/v1/config/apply", request, ADMIN_KEY).await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_restart_required");
    assert_eq!(body["posture_result"], "rejected");
    assert_eq!(body["applied"], false);
    assert_eq!(body["restart_required"], true);

    let record = FileAntiRollbackStore::new(&fixture.antirollback_path)
        .load(&AntiRollbackKey {
            product: "registry-relay".to_string(),
            instance_id: "relay-test-instance".to_string(),
            environment: "lab".to_string(),
            stream_id: "test-stream".to_string(),
        })
        .expect("antirollback state loads");
    assert_eq!(record.last_sequence, 0);
    assert!(record.local_approvals.accepted.is_empty());
}

#[tokio::test]
async fn config_apply_inline_metadata_only_change_is_rejected_without_swapping() {
    let fixture = build_fixture();
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("owner: Test Ministry", "owner: Operations Ministry");

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        config_apply_request(&fixture, candidate, 4),
        ADMIN_KEY,
    )
    .await;

    let body = assert_problem(
        response,
        StatusCode::BAD_REQUEST,
        "registry.admin.config.inline_apply_rejected",
    )
    .await;
    assert_eq!(body["schema"], "registry.admin.error.v1");
    assert_eq!(body["detail"], "signed config target is required for apply");

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_matches_posture_schema(&posture);
    assert_eq!(posture["instance"]["owner"], "Test Ministry");
    assert_eq!(posture["configuration"]["source"], "local_file");
    assert_eq!(posture["configuration"]["last_bundle_id"], Value::Null);
    assert_eq!(
        posture["configuration"]["last_bundle_sequence"],
        Value::Null
    );
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
    assert_eq!(posture["configuration"]["restart_required"], false);
}

#[tokio::test]
async fn config_admin_rejects_malformed_previous_config_hash_before_evaluation() {
    let fixture = build_fixture();
    let candidate = std::fs::read_to_string(&fixture.config_path).expect("config reads");
    let mut request = config_apply_request(&fixture, candidate, 2);
    request["previous_config_hash"] = json!("sha256:not-a-digest");

    let response =
        post_admin_config(&fixture, "/admin/v1/config/dry-run", request, ADMIN_KEY).await;

    let body = assert_problem(
        response,
        StatusCode::BAD_REQUEST,
        "admin.config_candidate_invalid",
    )
    .await;
    assert_eq!(
        body["detail"],
        "previous_config_hash must be sha256:<64 lowercase hex>"
    );
}

#[tokio::test]
async fn config_apply_signed_tuf_target_swaps_runtime_snapshot() {
    let fixture = build_fixture();
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("owner: Test Ministry", "owner: Signed Operations Ministry");
    let signed = write_signed_config_tuf_fixture(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    if response.status_code() != StatusCode::OK {
        let body: Value = response.json();
        panic!("signed TUF apply should succeed, got {body:#}");
    }
    let body: Value = response.json();
    assert_eq!(body["bundle_id"], "test-bundle");
    assert_eq!(body["sequence"], 5);
    assert_eq!(body["result"], "applied");
    assert_eq!(body["posture_result"], "accepted");
    assert_eq!(body["applied"], true);
    assert_eq!(body["restart_required"], false);

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_matches_posture_schema(&posture);
    assert_eq!(posture["instance"]["owner"], "Signed Operations Ministry");
    assert_eq!(posture["configuration"]["source"], "signed_bundle_file");
    assert_eq!(posture["configuration"]["last_bundle_id"], "test-bundle");
    assert_eq!(posture["configuration"]["last_bundle_sequence"], 5);
    assert_eq!(posture["configuration"]["last_apply_result"], "accepted");
    assert_eq!(posture["configuration"]["restart_required"], false);

    let record = config_audit_record(&fixture, "/admin/v1/config/apply");
    let config_audit = &record["config"];
    assert_eq!(config_audit["action"], "apply");
    assert_eq!(config_audit["source"], "signed_bundle_file");
    assert_eq!(config_audit["bundle_id"], "test-bundle");
    assert_eq!(config_audit["bundle_sequence"], 5);
    assert_eq!(config_audit["signer_kids"], json!([TUF_TARGETS_SIGNER_KID]));
    assert_eq!(
        config_audit["previous_config_hash"],
        fixture.current_config_hash
    );
    assert!(config_audit["config_hash"]
        .as_str()
        .is_some_and(|hash| hash.starts_with("sha256:")));
    assert_eq!(config_audit["product_validation_result"], "accepted");
    assert_eq!(config_audit["apply_result"], "applied");
    assert_eq!(config_audit["posture_result"], "accepted");
    assert_eq!(config_audit["applied"], true);
    assert_eq!(config_audit["restart_required"], false);

    let audit_text = serde_json::to_string(&record).expect("audit record serializes");
    assert!(!audit_text.contains("Signed Operations Ministry"));
    assert!(!audit_text.contains("registry-relay.yaml"));
    assert!(!audit_text.contains("signed-config-5"));
    assert!(!audit_text.contains("private-jwk-material"));
}

#[tokio::test]
async fn fail_closed_audit_failure_blocks_config_apply_before_state_mutation() {
    let fixture = build_fail_closed_fixture_with_failing_audit_sink();
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("owner: Test Ministry", "owner: Blocked Operations Ministry");
    let signed = write_signed_config_tuf_fixture(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    assert_problem(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        AUDIT_WRITE_FAILED_CODE,
    )
    .await;
    let record = FileAntiRollbackStore::new(&fixture.antirollback_path)
        .load(&AntiRollbackKey {
            product: "registry-relay".to_string(),
            instance_id: "relay-test-instance".to_string(),
            environment: "lab".to_string(),
            stream_id: "test-stream".to_string(),
        })
        .expect("antirollback state loads");
    assert_eq!(record.last_sequence, 0);

    let snapshot = fixture.handle.load_full();
    assert_eq!(snapshot.config.catalog.publisher, "Test Ministry");
    assert_eq!(
        snapshot.config_provenance.internal_config_hash,
        fixture.current_config_hash
    );
}

#[tokio::test]
async fn config_apply_signed_metadata_package_swaps_compiled_metadata() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let metadata_yaml = split_metadata_manifest_yaml("Signed Metadata Catalog");
    let source_digest = metadata_source_digest(&metadata_yaml);
    insert_metadata_digest(&config_path, &source_digest);
    let fixture = build_fixture_from_config_path(tmp, config_path);
    let candidate = std::fs::read_to_string(&fixture.config_path).expect("config reads");
    let signed = write_signed_config_tuf_fixture_with_metadata(
        &fixture,
        &candidate,
        &metadata_yaml,
        &source_digest,
        5,
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    if response.status_code() != StatusCode::OK {
        let body: Value = response.json();
        panic!("signed metadata package apply should succeed, got {body:#}");
    }
    let body: Value = response.json();
    assert_eq!(body["result"], "applied");

    let snapshot = fixture.handle.load_full();
    assert_eq!(
        snapshot.metadata_source_digest.as_deref(),
        Some(source_digest.as_str())
    );
    assert_eq!(
        snapshot
            .compiled_metadata
            .as_ref()
            .expect("compiled metadata swaps in")
            .catalog()
            .title,
        "Signed Metadata Catalog"
    );

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_matches_posture_schema(&posture);
    assert_eq!(
        posture["relay"]["metadata_manifest"]["source_digest"],
        source_digest
    );
    let config_value: Value = serde_saphyr::from_str(&candidate).expect("candidate parses");
    let posture_safe_hash = posture_safe_runtime_config_hash(&config_value);
    let package_config_hash = {
        let config: Config = serde_saphyr::from_str(&candidate).expect("candidate config parses");
        let preimage = json!({
            "schema_version": "registry-runtime-package/v1",
            "product": "registry-relay",
            "instance_id": config.instance.id,
            "environment": config.instance.environment.as_deref().unwrap_or("development"),
            "runtime_config_digest": internal_config_hash(candidate.as_bytes()),
            "source": "signed_bundle_file",
            "source_manifest_digest": source_digest,
        });
        let bytes =
            canonicalize_json(&preimage).expect("package config hash preimage canonicalizes");
        internal_config_hash(&bytes)
    };
    assert_eq!(
        posture["configuration"]["last_config_hash"],
        posture_safe_hash
    );
    assert_ne!(posture_safe_hash, package_config_hash);
    let raw_posture = serde_json::to_string(&posture).expect("posture serializes");
    assert!(!raw_posture.contains(&package_config_hash));
    assert!(!raw_posture.contains(&internal_config_hash(candidate.as_bytes())));
}

#[tokio::test]
async fn config_apply_signed_tuf_stale_sequence_rejects_without_swapping() {
    let fixture = build_fixture();
    let first_candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("owner: Test Ministry", "owner: Signed Operations Ministry");
    let first_signed = write_signed_config_tuf_fixture(
        &fixture,
        &first_candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
    )
    .await;

    let first_response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&first_signed),
        ADMIN_KEY,
    )
    .await;

    if first_response.status_code() != StatusCode::OK {
        let body: Value = first_response.json();
        panic!("first signed TUF apply should succeed, got {body:#}");
    }

    let first_hash = internal_config_hash(first_candidate.as_bytes());
    let stale_candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("owner: Test Ministry", "owner: Stale Operations Ministry");
    let stale_signed = write_signed_config_tuf_fixture_with_previous_hash_and_change_classes(
        &fixture,
        &stale_candidate,
        4,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["public_metadata"],
        &first_hash,
    )
    .await;

    let stale_response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&stale_signed),
        ADMIN_KEY,
    )
    .await;

    stale_response.assert_status(StatusCode::CONFLICT);
    let body: Value = stale_response.json();
    assert_eq!(body["bundle_id"], "test-bundle");
    assert_eq!(body["sequence"], 4);
    assert_eq!(body["result"], "rejected_rollback");
    assert_eq!(body["posture_result"], "rejected");
    assert_eq!(body["applied"], false);
    assert_eq!(body["restart_required"], false);

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_matches_posture_schema(&posture);
    assert_eq!(posture["instance"]["owner"], "Signed Operations Ministry");
    assert_eq!(posture["configuration"]["source"], "signed_bundle_file");
    assert_eq!(posture["configuration"]["last_bundle_id"], "test-bundle");
    assert_eq!(posture["configuration"]["last_bundle_sequence"], 5);
    assert_eq!(posture["configuration"]["last_apply_result"], "accepted");
    assert_eq!(posture["configuration"]["restart_required"], false);

    let record = FileAntiRollbackStore::new(&fixture.antirollback_path)
        .load(&AntiRollbackKey {
            product: "registry-relay".to_string(),
            instance_id: "relay-test-instance".to_string(),
            environment: "lab".to_string(),
            stream_id: "test-stream".to_string(),
        })
        .expect("antirollback state loads");
    assert_eq!(record.last_sequence, 5);
    assert_eq!(record.last_config_hash, first_hash);
}

#[tokio::test]
async fn config_apply_remote_signed_tuf_target_swaps_runtime_snapshot() {
    let server = MockServer::start().await;
    let fixture = build_fixture_with_remote_tuf_repository(&server);
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("owner: Test Ministry", "owner: Remote Signed Ministry");
    let signed = write_signed_config_tuf_fixture(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
    )
    .await;
    mount_signed_tuf_fixture(&server, &signed).await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        remote_signed_tuf_apply_request(&signed, &server),
        ADMIN_KEY,
    )
    .await;

    if response.status_code() != StatusCode::OK {
        let body: Value = response.json();
        panic!("remote signed TUF apply should succeed, got {body:#}");
    }
    let body: Value = response.json();
    assert_eq!(body["bundle_id"], "test-bundle");
    assert_eq!(body["sequence"], 5);
    assert_eq!(body["result"], "applied");
    assert_eq!(body["posture_result"], "accepted");
    assert_eq!(body["applied"], true);
    assert_eq!(body["restart_required"], false);

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_matches_posture_schema(&posture);
    assert_eq!(posture["instance"]["owner"], "Remote Signed Ministry");
    assert_eq!(posture["configuration"]["source"], "signed_bundle_endpoint");
    assert_eq!(posture["configuration"]["last_bundle_id"], "test-bundle");
    assert_eq!(posture["configuration"]["last_bundle_sequence"], 5);
    assert_eq!(posture["configuration"]["last_apply_result"], "accepted");

    let record = config_audit_record(&fixture, "/admin/v1/config/apply");
    let config_audit = &record["config"];
    assert_eq!(config_audit["action"], "apply");
    assert_eq!(config_audit["source"], "signed_bundle_endpoint");
    assert_eq!(config_audit["bundle_id"], "test-bundle");
    assert_eq!(config_audit["bundle_sequence"], 5);
    assert_eq!(config_audit["signer_kids"], json!([TUF_TARGETS_SIGNER_KID]));
    assert_eq!(config_audit["apply_result"], "applied");
    assert_eq!(config_audit["posture_result"], "accepted");
    assert_eq!(config_audit["applied"], true);
    assert_eq!(config_audit["restart_required"], false);
}

#[tokio::test]
async fn config_apply_signed_provenance_rotation_swaps_runtime_snapshot() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let old_key_path = tmp.path().join("provenance-old.jwk");
    let old_kid = "did:web:data.example.test#relay-public-key";
    let old_public_jwk = write_ed25519_jwk(&old_key_path, old_kid);
    let yaml = std::fs::read_to_string(&config_path)
        .expect("config reads")
        .replace("enabled: false", "enabled: true")
        .replace(
            "kind: software\n      jwk_env: REGISTRY_RELAY_TEST_PRIVATE_JWK\n      signing_algorithm: EdDSA",
            &format!(
                "kind: file_watch\n      path: \"{}\"\n      signing_algorithm: EdDSA",
                old_key_path.to_string_lossy()
            ),
        );
    std::fs::write(&config_path, yaml).expect("config writes");
    let fixture = build_fixture_from_config_path_with_provenance_state(tmp, config_path, true);
    let inflight_snapshot = fixture.handle.load_full();
    let inflight_provenance = inflight_snapshot
        .provenance_state
        .clone()
        .expect("in-flight request holds old provenance state");

    let new_key_path = fixture._tmp.path().join("provenance-new.jwk");
    let new_kid = "did:web:data.example.test#relay-public-key-2";
    write_ed25519_jwk(&new_key_path, new_kid);
    unsafe {
        std::env::set_var(
            "REGISTRY_RELAY_RETIRED_PROVENANCE_JWK",
            serde_json::to_string(&old_public_jwk).expect("old public jwk serializes"),
        );
    }
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace(
            "verification_method_id: did:web:data.example.test#relay-public-key\n    signer:\n      kind: file_watch",
            "verification_method_id: did:web:data.example.test#relay-public-key-2\n    signer:\n      kind: file_watch",
        )
        .replace(
            &format!("path: \"{}\"", old_key_path.to_string_lossy()),
            &format!("path: \"{}\"", new_key_path.to_string_lossy()),
        )
        .replace(
            "signing_algorithm: EdDSA\n",
            "signing_algorithm: EdDSA\n    retired_keys:\n      - verification_method_id: did:web:data.example.test#relay-public-key\n        jwk_env: REGISTRY_RELAY_RETIRED_PROVENANCE_JWK\n        retired_after: 2099-06-05T00:00:00Z\n",
        );
    let signed = write_signed_config_tuf_fixture_with_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["signing_key_rotation"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    if response.status_code() != StatusCode::OK {
        let body: Value = response.json();
        panic!("signed provenance rotation should succeed, got {body:#}");
    }
    let body: Value = response.json();
    assert_eq!(body["result"], "applied");
    assert_eq!(body["applied"], true);
    assert_eq!(body["restart_required"], false);

    let posture = fixture
        .server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["relay"]["provenance"]["active_kid"], new_kid);
    assert_eq!(
        posture["relay"]["provenance"]["retired_kids"],
        json!([old_kid])
    );
    assert_eq!(
        posture["relay"]["provenance"]["key_readiness"][new_kid],
        "ready"
    );
    assert_eq!(
        posture["relay"]["provenance"]["key_readiness"][old_kid],
        "ready"
    );
    assert_eq!(posture["configuration"]["last_apply_result"], "accepted");

    let current_provenance = fixture
        .handle
        .load_full()
        .provenance_state
        .clone()
        .expect("current runtime holds new provenance state");
    let subject_uri =
        "https://data.example.test/v1/datasets/social_registry/entities/beneficiary/records/1";
    let issued_at = time::OffsetDateTime::now_utc();
    let inflight_vc = inflight_provenance
        .issue(IssuanceContext {
            claim_type: ClaimType::EntityRecord,
            subject_uri: subject_uri.to_string(),
            credential_subject: json!({
                "id": subject_uri,
                "beneficiary_id": 1,
            }),
            issued_at,
        })
        .expect("in-flight request can finish with old signer");
    let current_vc = current_provenance
        .issue(IssuanceContext {
            claim_type: ClaimType::EntityRecord,
            subject_uri: subject_uri.to_string(),
            credential_subject: json!({
                "id": subject_uri,
                "beneficiary_id": 1,
            }),
            issued_at,
        })
        .expect("new request signs with new signer");
    assert_eq!(inflight_vc.verification_method_id, old_kid);
    assert_eq!(current_vc.verification_method_id, new_kid);

    let did = fixture.public_server.get("/.well-known/did.json").await;
    did.assert_status(StatusCode::OK);
    let did: Value = did.json();
    assert_eq!(did["assertionMethod"], json!([new_kid]));
    let methods = did["verificationMethod"]
        .as_array()
        .expect("verificationMethod is an array");
    let method_ids = methods
        .iter()
        .map(|method| method["id"].as_str().expect("method id").to_string())
        .collect::<Vec<_>>();
    assert!(method_ids.contains(&new_kid.to_string()));
    assert!(method_ids.contains(&old_kid.to_string()));
    for method in methods {
        assert!(
            method["publicKeyJwk"].get("d").is_none(),
            "DID verification method must not expose private key material"
        );
    }
}

#[tokio::test]
async fn config_apply_signed_provenance_rotation_rejects_non_ready_candidate_before_antirollback() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let old_key_path = tmp.path().join("provenance-old.jwk");
    let old_kid = "did:web:data.example.test#relay-public-key";
    let old_public_jwk = write_ed25519_jwk(&old_key_path, old_kid);
    let yaml = std::fs::read_to_string(&config_path)
        .expect("config reads")
        .replace("enabled: false", "enabled: true")
        .replace(
            "kind: software\n      jwk_env: REGISTRY_RELAY_TEST_PRIVATE_JWK\n      signing_algorithm: EdDSA",
            &format!(
                "kind: file_watch\n      path: \"{}\"\n      signing_algorithm: EdDSA",
                old_key_path.to_string_lossy()
            ),
        );
    std::fs::write(&config_path, yaml).expect("config writes");
    let admin_resolver: CandidateProvenanceResolverRef = Arc::new(ReadinessOverrideResolver {
        readiness: registry_platform_crypto::KeyReadiness::Degraded,
    });
    let fixture = build_fixture_from_config_path_with_provenance_state_and_admin_resolver(
        tmp,
        config_path,
        true,
        Some(admin_resolver),
    );

    let new_key_path = fixture._tmp.path().join("provenance-new.jwk");
    let new_kid = "did:web:data.example.test#relay-public-key-2";
    write_ed25519_jwk(&new_key_path, new_kid);
    unsafe {
        std::env::set_var(
            "REGISTRY_RELAY_RETIRED_PROVENANCE_JWK",
            serde_json::to_string(&old_public_jwk).expect("old public jwk serializes"),
        );
    }
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace(
            "verification_method_id: did:web:data.example.test#relay-public-key\n    signer:\n      kind: file_watch",
            "verification_method_id: did:web:data.example.test#relay-public-key-2\n    signer:\n      kind: file_watch",
        )
        .replace(
            &format!("path: \"{}\"", old_key_path.to_string_lossy()),
            &format!("path: \"{}\"", new_key_path.to_string_lossy()),
        )
        .replace(
            "signing_algorithm: EdDSA\n",
            "signing_algorithm: EdDSA\n    retired_keys:\n      - verification_method_id: did:web:data.example.test#relay-public-key\n        jwk_env: REGISTRY_RELAY_RETIRED_PROVENANCE_JWK\n        retired_after: 2026-06-05T00:00:00Z\n",
        );
    let signed = write_signed_config_tuf_fixture_with_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["signing_key_rotation"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_readiness");
    assert_eq!(body["posture_result"], "rejected");
    assert_eq!(body["applied"], false);
    assert_eq!(body["restart_required"], false);

    let record = FileAntiRollbackStore::new(&fixture.antirollback_path)
        .load(&AntiRollbackKey {
            product: "registry-relay".to_string(),
            instance_id: "relay-test-instance".to_string(),
            environment: "lab".to_string(),
            stream_id: "test-stream".to_string(),
        })
        .expect("antirollback state loads");
    assert_eq!(record.last_sequence, 0);
    assert_eq!(record.last_config_hash, fixture.current_config_hash);

    let posture = fixture
        .server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["relay"]["provenance"]["active_kid"], old_kid);
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_signed_provenance_cleanup_removes_expired_retired_key() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let active_key_path = tmp.path().join("provenance-active.jwk");
    let active_kid = "did:web:data.example.test#relay-public-key";
    write_ed25519_jwk(&active_key_path, active_kid);
    let retired_kid = "did:web:data.example.test#relay-public-key-old";
    let retired_key_path = tmp.path().join("provenance-retired.jwk");
    let retired_public_jwk = write_ed25519_jwk(&retired_key_path, retired_kid);
    let retired_after = (Utc::now() - chrono::Duration::days(2)).to_rfc3339();
    unsafe {
        std::env::set_var(
            "REGISTRY_RELAY_RETIRED_PROVENANCE_JWK",
            serde_json::to_string(&retired_public_jwk).expect("retired public jwk serializes"),
        );
    }
    let retired_block = format!(
        "signing_algorithm: EdDSA\n    retired_keys:\n      - verification_method_id: {retired_kid}\n        jwk_env: REGISTRY_RELAY_RETIRED_PROVENANCE_JWK\n        retired_after: {retired_after}\n"
    );
    let yaml = std::fs::read_to_string(&config_path)
        .expect("config reads")
        .replace("enabled: false", "enabled: true")
        .replace(
            "kind: software\n      jwk_env: REGISTRY_RELAY_TEST_PRIVATE_JWK\n      signing_algorithm: EdDSA",
            &format!(
                "kind: file_watch\n      path: \"{}\"\n      {retired_block}",
                active_key_path.to_string_lossy()
            ),
        );
    std::fs::write(&config_path, yaml).expect("config writes");
    let fixture = build_fixture_from_config_path_with_provenance_state(tmp, config_path, true);

    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace(&retired_block, "signing_algorithm: EdDSA\n");
    let signed = write_signed_config_tuf_fixture_with_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["signing_key_cleanup"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["result"], "applied");
    assert_eq!(body["restart_required"], false);

    let posture = fixture
        .server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["relay"]["provenance"]["active_kid"], active_kid);
    assert_eq!(posture["relay"]["provenance"]["retired_kids"], json!([]));
    assert_eq!(posture["configuration"]["last_apply_result"], "accepted");
}

#[tokio::test]
async fn config_apply_signed_provenance_cleanup_rejects_unexpired_retired_key() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let active_key_path = tmp.path().join("provenance-active.jwk");
    let active_kid = "did:web:data.example.test#relay-public-key";
    write_ed25519_jwk(&active_key_path, active_kid);
    let retired_kid = "did:web:data.example.test#relay-public-key-old";
    let retired_key_path = tmp.path().join("provenance-retired.jwk");
    let retired_public_jwk = write_ed25519_jwk(&retired_key_path, retired_kid);
    let retired_after = Utc::now().to_rfc3339();
    unsafe {
        std::env::set_var(
            "REGISTRY_RELAY_RETIRED_PROVENANCE_JWK",
            serde_json::to_string(&retired_public_jwk).expect("retired public jwk serializes"),
        );
    }
    let retired_block = format!(
        "signing_algorithm: EdDSA\n    retired_keys:\n      - verification_method_id: {retired_kid}\n        jwk_env: REGISTRY_RELAY_RETIRED_PROVENANCE_JWK\n        retired_after: {retired_after}\n"
    );
    let yaml = std::fs::read_to_string(&config_path)
        .expect("config reads")
        .replace("enabled: false", "enabled: true")
        .replace(
            "kind: software\n      jwk_env: REGISTRY_RELAY_TEST_PRIVATE_JWK\n      signing_algorithm: EdDSA",
            &format!(
                "kind: file_watch\n      path: \"{}\"\n      {retired_block}",
                active_key_path.to_string_lossy()
            ),
        );
    std::fs::write(&config_path, yaml).expect("config writes");
    let fixture = build_fixture_from_config_path_with_provenance_state(tmp, config_path, true);

    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace(&retired_block, "signing_algorithm: EdDSA\n");
    let signed = write_signed_config_tuf_fixture_with_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["signing_key_cleanup"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;
    let body = assert_problem(
        response,
        StatusCode::BAD_REQUEST,
        "admin.config_candidate_invalid",
    )
    .await;
    assert_eq!(
        body["detail"],
        "candidate provenance cleanup removed retired key before verification window expired"
    );

    let posture = fixture
        .server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["relay"]["provenance"]["active_kid"], active_kid);
    assert_eq!(
        posture["relay"]["provenance"]["retired_kids"],
        json!([retired_kid])
    );
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_signed_provenance_cleanup_class_cannot_rotate_active_key() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let old_key_path = tmp.path().join("provenance-old.jwk");
    let old_kid = "did:web:data.example.test#relay-public-key";
    let old_public_jwk = write_ed25519_jwk(&old_key_path, old_kid);
    let yaml = std::fs::read_to_string(&config_path)
        .expect("config reads")
        .replace("enabled: false", "enabled: true")
        .replace(
            "kind: software\n      jwk_env: REGISTRY_RELAY_TEST_PRIVATE_JWK\n      signing_algorithm: EdDSA",
            &format!(
                "kind: file_watch\n      path: \"{}\"\n      signing_algorithm: EdDSA",
                old_key_path.to_string_lossy()
            ),
        );
    std::fs::write(&config_path, yaml).expect("config writes");
    let fixture = build_fixture_from_config_path_with_provenance_state(tmp, config_path, true);

    let new_key_path = fixture._tmp.path().join("provenance-new.jwk");
    let new_kid = "did:web:data.example.test#relay-public-key-2";
    write_ed25519_jwk(&new_key_path, new_kid);
    unsafe {
        std::env::set_var(
            "REGISTRY_RELAY_RETIRED_PROVENANCE_JWK",
            serde_json::to_string(&old_public_jwk).expect("old public jwk serializes"),
        );
    }
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace(
            "verification_method_id: did:web:data.example.test#relay-public-key\n    signer:\n      kind: file_watch",
            "verification_method_id: did:web:data.example.test#relay-public-key-2\n    signer:\n      kind: file_watch",
        )
        .replace(
            &format!("path: \"{}\"", old_key_path.to_string_lossy()),
            &format!("path: \"{}\"", new_key_path.to_string_lossy()),
        )
        .replace(
            "signing_algorithm: EdDSA\n",
            "signing_algorithm: EdDSA\n    retired_keys:\n      - verification_method_id: did:web:data.example.test#relay-public-key\n        jwk_env: REGISTRY_RELAY_RETIRED_PROVENANCE_JWK\n        retired_after: 2026-06-05T00:00:00Z\n",
        );
    let signed = write_signed_config_tuf_fixture_with_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["signing_key_cleanup"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_restart_required");
    assert_eq!(body["applied"], false);
    assert_eq!(body["restart_required"], true);

    let posture = fixture
        .server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["relay"]["provenance"]["active_kid"], old_kid);
    assert_eq!(posture["relay"]["provenance"]["retired_kids"], json!([]));
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_signed_provenance_rotation_class_cannot_cleanup_retired_key() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let active_key_path = tmp.path().join("provenance-active.jwk");
    let active_kid = "did:web:data.example.test#relay-public-key";
    write_ed25519_jwk(&active_key_path, active_kid);
    let retired_kid = "did:web:data.example.test#relay-public-key-old";
    let retired_key_path = tmp.path().join("provenance-retired.jwk");
    let retired_public_jwk = write_ed25519_jwk(&retired_key_path, retired_kid);
    let retired_after = (Utc::now() - chrono::Duration::days(2)).to_rfc3339();
    unsafe {
        std::env::set_var(
            "REGISTRY_RELAY_RETIRED_PROVENANCE_JWK",
            serde_json::to_string(&retired_public_jwk).expect("retired public jwk serializes"),
        );
    }
    let retired_block = format!(
        "signing_algorithm: EdDSA\n    retired_keys:\n      - verification_method_id: {retired_kid}\n        jwk_env: REGISTRY_RELAY_RETIRED_PROVENANCE_JWK\n        retired_after: {retired_after}\n"
    );
    let yaml = std::fs::read_to_string(&config_path)
        .expect("config reads")
        .replace("enabled: false", "enabled: true")
        .replace(
            "kind: software\n      jwk_env: REGISTRY_RELAY_TEST_PRIVATE_JWK\n      signing_algorithm: EdDSA",
            &format!(
                "kind: file_watch\n      path: \"{}\"\n      {retired_block}",
                active_key_path.to_string_lossy()
            ),
        );
    std::fs::write(&config_path, yaml).expect("config writes");
    let fixture = build_fixture_from_config_path_with_provenance_state(tmp, config_path, true);

    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace(&retired_block, "signing_algorithm: EdDSA\n");
    let signed = write_signed_config_tuf_fixture_with_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["signing_key_rotation"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_restart_required");
    assert_eq!(body["applied"], false);
    assert_eq!(body["restart_required"], true);

    let posture = fixture
        .server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["relay"]["provenance"]["active_kid"], active_kid);
    assert_eq!(
        posture["relay"]["provenance"]["retired_kids"],
        json!([retired_kid])
    );
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_signed_provenance_rotation_requires_previous_key_retired() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let old_key_path = tmp.path().join("provenance-old.jwk");
    let old_kid = "did:web:data.example.test#relay-public-key";
    write_ed25519_jwk(&old_key_path, old_kid);
    let yaml = std::fs::read_to_string(&config_path)
        .expect("config reads")
        .replace("enabled: false", "enabled: true")
        .replace(
            "kind: software\n      jwk_env: REGISTRY_RELAY_TEST_PRIVATE_JWK\n      signing_algorithm: EdDSA",
            &format!(
                "kind: file_watch\n      path: \"{}\"\n      signing_algorithm: EdDSA",
                old_key_path.to_string_lossy()
            ),
        );
    std::fs::write(&config_path, yaml).expect("config writes");
    let fixture = build_fixture_from_config_path_with_provenance_state(tmp, config_path, true);

    let new_key_path = fixture._tmp.path().join("provenance-new.jwk");
    let new_kid = "did:web:data.example.test#relay-public-key-2";
    write_ed25519_jwk(&new_key_path, new_kid);
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace(
            "verification_method_id: did:web:data.example.test#relay-public-key\n    signer:\n      kind: file_watch",
            "verification_method_id: did:web:data.example.test#relay-public-key-2\n    signer:\n      kind: file_watch",
        )
        .replace(
            &format!("path: \"{}\"", old_key_path.to_string_lossy()),
            &format!("path: \"{}\"", new_key_path.to_string_lossy()),
        );
    let signed = write_signed_config_tuf_fixture_with_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["signing_key_rotation"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    let body = assert_problem(
        response,
        StatusCode::BAD_REQUEST,
        "admin.config_candidate_invalid",
    )
    .await;
    assert_eq!(
        body["detail"],
        "candidate provenance rotation must publish previous active key as retired"
    );

    let posture = fixture
        .server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["relay"]["provenance"]["active_kid"], old_kid);
    assert_eq!(posture["relay"]["provenance"]["retired_kids"], json!([]));
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_signed_provenance_rotation_missing_key_fails_without_swapping() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let old_key_path = tmp.path().join("provenance-old.jwk");
    let old_kid = "did:web:data.example.test#relay-public-key";
    write_ed25519_jwk(&old_key_path, old_kid);
    let yaml = std::fs::read_to_string(&config_path)
        .expect("config reads")
        .replace("enabled: false", "enabled: true")
        .replace(
            "kind: software\n      jwk_env: REGISTRY_RELAY_TEST_PRIVATE_JWK\n      signing_algorithm: EdDSA",
            &format!(
                "kind: file_watch\n      path: \"{}\"\n      signing_algorithm: EdDSA",
                old_key_path.to_string_lossy()
            ),
        );
    std::fs::write(&config_path, yaml).expect("config writes");
    let fixture = build_fixture_from_config_path_with_provenance_state(tmp, config_path, true);

    let missing_key_path = fixture._tmp.path().join("missing-provenance-new.jwk");
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace(
            "verification_method_id: did:web:data.example.test#relay-public-key\n    signer:\n      kind: file_watch",
            "verification_method_id: did:web:data.example.test#relay-public-key-2\n    signer:\n      kind: file_watch",
        )
        .replace(
            &format!("path: \"{}\"", old_key_path.to_string_lossy()),
            &format!("path: \"{}\"", missing_key_path.to_string_lossy()),
        );
    let signed = write_signed_config_tuf_fixture_with_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["signing_key_rotation"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    let body = assert_problem(
        response,
        StatusCode::BAD_REQUEST,
        "admin.config_candidate_invalid",
    )
    .await;
    assert_eq!(body["detail"], "candidate config did not validate");

    let posture = fixture
        .server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["relay"]["provenance"]["active_kid"], old_kid);
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_signed_provenance_same_kid_different_key_fails_without_swapping() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let old_key_path = tmp.path().join("provenance-old.jwk");
    let old_kid = "did:web:data.example.test#relay-public-key";
    write_ed25519_jwk(&old_key_path, old_kid);
    let yaml = std::fs::read_to_string(&config_path)
        .expect("config reads")
        .replace("enabled: false", "enabled: true")
        .replace(
            "kind: software\n      jwk_env: REGISTRY_RELAY_TEST_PRIVATE_JWK\n      signing_algorithm: EdDSA",
            &format!(
                "kind: file_watch\n      path: \"{}\"\n      signing_algorithm: EdDSA",
                old_key_path.to_string_lossy()
            ),
        );
    std::fs::write(&config_path, yaml).expect("config writes");
    let fixture = build_fixture_from_config_path_with_provenance_state(tmp, config_path, true);

    let new_key_path = fixture._tmp.path().join("provenance-new-same-kid.jwk");
    write_ed25519_jwk(&new_key_path, old_kid);
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace(
            &format!("path: \"{}\"", old_key_path.to_string_lossy()),
            &format!("path: \"{}\"", new_key_path.to_string_lossy()),
        );
    let signed = write_signed_config_tuf_fixture_with_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["signing_key_rotation"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    let body = assert_problem(
        response,
        StatusCode::BAD_REQUEST,
        "admin.config_candidate_invalid",
    )
    .await;
    assert_eq!(
        body["detail"],
        "candidate provenance signer public key changed without a new verification method"
    );

    let posture = fixture
        .server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["relay"]["provenance"]["active_kid"], old_kid);
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_signed_provenance_enablement_is_restart_required_without_swapping() {
    let fixture = build_fixture();
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("enabled: false", "enabled: true");
    let signed = write_signed_config_tuf_fixture_with_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["signing_key_rotation"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_restart_required");
    assert_eq!(body["applied"], false);
    assert_eq!(body["restart_required"], true);

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert!(posture["relay"]["provenance"].get("active_kid").is_none());
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_signed_provenance_issuer_change_is_restart_required_without_swapping() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let key_path = tmp.path().join("provenance-active.jwk");
    let old_kid = "did:web:data.example.test#relay-public-key";
    write_ed25519_jwk(&key_path, old_kid);
    let yaml = std::fs::read_to_string(&config_path)
        .expect("config reads")
        .replace("enabled: false", "enabled: true")
        .replace(
            "kind: software\n      jwk_env: REGISTRY_RELAY_TEST_PRIVATE_JWK\n      signing_algorithm: EdDSA",
            &format!(
                "kind: file_watch\n      path: \"{}\"\n      signing_algorithm: EdDSA",
                key_path.to_string_lossy()
            ),
        );
    std::fs::write(&config_path, yaml).expect("config writes");
    let fixture = build_fixture_from_config_path_with_provenance_state(tmp, config_path, true);
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace(
            "did: did:web:data.example.test",
            "did: did:web:other.example.test",
        )
        .replace(
            "verification_method_id: did:web:data.example.test#relay-public-key",
            "verification_method_id: did:web:other.example.test#relay-public-key",
        );
    let signed = write_signed_config_tuf_fixture_with_change_classes(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
        &["signing_key_rotation"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_restart_required");
    assert_eq!(body["applied"], false);
    assert_eq!(body["restart_required"], true);

    let posture = fixture
        .server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["relay"]["provenance"]["active_kid"], old_kid);
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_signed_provenance_non_signer_fields_are_restart_required_without_swapping() {
    let cases = [
        (
            "accepted media types",
            "  accepted_media_types:\n    - application/vc+jwt",
            "  accepted_media_types:\n    - application/vc+jwt\n    - application/vc+ld+json",
        ),
        (
            "schema base URL",
            "  schema_base_url: https://data.example.test/schemas",
            "  schema_base_url: https://data.example.test/other-schemas",
        ),
        (
            "context base URL",
            "  context_base_url: https://data.example.test/contexts",
            "  context_base_url: https://data.example.test/other-contexts",
        ),
        (
            "claim validity",
            "  claim_validity:\n    aggregate_result: 10m\n    entity_record: 10m",
            "  claim_validity:\n    aggregate_result: 20m\n    entity_record: 10m",
        ),
    ];

    for (case_name, from, to) in cases {
        let tmp = TempDir::new().expect("tempdir");
        let config_path = write_config(&tmp);
        let old_key_path = tmp.path().join(format!(
            "provenance-old-{}.jwk",
            case_name.replace(' ', "-")
        ));
        let old_kid = "did:web:data.example.test#relay-public-key";
        let old_public_jwk = write_ed25519_jwk(&old_key_path, old_kid);
        let yaml = std::fs::read_to_string(&config_path)
            .expect("config reads")
            .replace("enabled: false", "enabled: true")
            .replace(
                "kind: software\n      jwk_env: REGISTRY_RELAY_TEST_PRIVATE_JWK\n      signing_algorithm: EdDSA",
                &format!(
                    "kind: file_watch\n      path: \"{}\"\n      signing_algorithm: EdDSA",
                    old_key_path.to_string_lossy()
                ),
            );
        std::fs::write(&config_path, yaml).expect("config writes");
        let fixture = build_fixture_from_config_path_with_provenance_state(tmp, config_path, true);

        let new_key_path = fixture._tmp.path().join(format!(
            "provenance-new-{}.jwk",
            case_name.replace(' ', "-")
        ));
        write_ed25519_jwk(
            &new_key_path,
            "did:web:data.example.test#relay-public-key-2",
        );
        unsafe {
            std::env::set_var(
                "REGISTRY_RELAY_RETIRED_PROVENANCE_JWK",
                serde_json::to_string(&old_public_jwk).expect("old public jwk serializes"),
            );
        }
        let mut candidate = std::fs::read_to_string(&fixture.config_path)
            .expect("config reads")
            .replace(
                "verification_method_id: did:web:data.example.test#relay-public-key\n    signer:\n      kind: file_watch",
                "verification_method_id: did:web:data.example.test#relay-public-key-2\n    signer:\n      kind: file_watch",
            )
            .replace(
                &format!("path: \"{}\"", old_key_path.to_string_lossy()),
                &format!("path: \"{}\"", new_key_path.to_string_lossy()),
            )
            .replace(
                "signing_algorithm: EdDSA\n",
                "signing_algorithm: EdDSA\n    retired_keys:\n      - verification_method_id: did:web:data.example.test#relay-public-key\n        jwk_env: REGISTRY_RELAY_RETIRED_PROVENANCE_JWK\n        retired_after: 2099-06-05T00:00:00Z\n",
            );
        candidate = candidate.replace(from, to);
        let signed = write_signed_config_tuf_fixture_with_change_classes(
            &fixture,
            &candidate,
            5,
            "relay-test-instance",
            &["kid-a", "kid-b"],
            &["signing_key_rotation"],
        )
        .await;

        let response = post_admin_config(
            &fixture,
            "/admin/v1/config/apply",
            signed_tuf_apply_request(&signed),
            ADMIN_KEY,
        )
        .await;

        response.assert_status(StatusCode::CONFLICT);
        let body: Value = response.json();
        assert_eq!(body["result"], "rejected_restart_required", "{case_name}");
        assert_eq!(body["applied"], false, "{case_name}");
        assert_eq!(body["restart_required"], true, "{case_name}");

        let record = FileAntiRollbackStore::new(&fixture.antirollback_path)
            .load(&AntiRollbackKey {
                product: "registry-relay".to_string(),
                instance_id: "relay-test-instance".to_string(),
                environment: "lab".to_string(),
                stream_id: "test-stream".to_string(),
            })
            .expect("antirollback state loads");
        assert_eq!(record.last_sequence, 0, "{case_name}");
        assert_eq!(record.last_config_hash, fixture.current_config_hash);

        let posture = fixture
            .server
            .get("/admin/v1/posture?tier=restricted")
            .add_header("Authorization", format!("Bearer {OPS_KEY}"))
            .await;
        posture.assert_status(StatusCode::OK);
        let posture: Value = posture.json();
        assert_eq!(
            posture["relay"]["provenance"]["active_kid"], old_kid,
            "{case_name}"
        );
        assert_eq!(
            posture["configuration"]["last_apply_result"],
            Value::Null,
            "{case_name}"
        );
    }
}

#[tokio::test]
async fn config_apply_signed_tuf_target_rejects_wrong_instance_without_swapping_or_leaking() {
    let fixture = build_fixture();
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("owner: Test Ministry", "owner: Wrong Instance Ministry");
    let signed = write_signed_config_tuf_fixture(
        &fixture,
        &candidate,
        5,
        "other-relay-instance",
        &["kid-a", "kid-b"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    let body = assert_problem(
        response,
        StatusCode::BAD_REQUEST,
        "admin.config_bundle_invalid",
    )
    .await;
    let rendered = body.to_string();
    assert!(!rendered.contains("Wrong Instance Ministry"));
    assert!(!rendered.contains("other-relay-instance"));
    assert!(!rendered.contains("registry-relay.yaml"));
    assert!(!rendered.contains("signed-config-5"));

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["instance"]["owner"], "Test Ministry");
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);

    let record = config_audit_record(&fixture, "/admin/v1/config/apply");
    let config_audit = &record["config"];
    assert_eq!(config_audit["action"], "apply");
    assert_eq!(config_audit["source"], "signed_bundle_file");
    assert!(config_audit.get("bundle_id").is_none());
    assert!(config_audit.get("bundle_sequence").is_none());
    assert_eq!(config_audit["product_validation_result"], "rejected");
    assert_eq!(config_audit["apply_result"], "rejected_signature");
    assert_eq!(config_audit["applied"], false);
    assert_eq!(config_audit["restart_required"], false);

    let audit_text = serde_json::to_string(&record).expect("audit record serializes");
    assert!(!audit_text.contains("Wrong Instance Ministry"));
    assert!(!audit_text.contains("other-relay-instance"));
    assert!(!audit_text.contains("registry-relay.yaml"));
    assert!(!audit_text.contains("signed-config-5"));
}

#[tokio::test]
async fn config_apply_signed_tuf_target_rejects_missing_quorum_without_swapping() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let config_yaml = std::fs::read_to_string(&config_path).expect("config reads");
    std::fs::write(
        &config_path,
        config_yaml.replace("threshold: 1", "threshold: 2"),
    )
    .expect("config writes");
    let fixture = build_fixture_from_config_path(tmp, config_path);
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("owner: Test Ministry", "owner: One Signer Ministry");
    let signed = write_signed_config_tuf_fixture(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &[TUF_TARGETS_SIGNER_KID, "kid-b"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_threshold");

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["instance"]["owner"], "Test Ministry");
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_signed_tuf_target_rejects_forged_extra_signature_without_swapping() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let config_yaml = std::fs::read_to_string(&config_path).expect("config reads");
    std::fs::write(
        &config_path,
        config_yaml
            .replace("threshold: 1", "threshold: 2")
            .replace("kid-b", FORGED_TUF_SIGNER_KID),
    )
    .expect("config writes");
    let fixture = build_fixture_from_config_path(tmp, config_path);
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("owner: Test Ministry", "owner: Forged Signer Ministry");
    let signed = write_signed_config_tuf_fixture(
        &fixture,
        &candidate,
        6,
        "relay-test-instance",
        &[TUF_TARGETS_SIGNER_KID, FORGED_TUF_SIGNER_KID],
    )
    .await;

    let real_keyid = forge_extra_targets_signature(&signed.metadata_dir);
    assert_eq!(real_keyid, TUF_TARGETS_SIGNER_KID);
    reseal_snapshot_and_timestamp(&signed.metadata_dir).await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_threshold");

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["instance"]["owner"], "Test Ministry");
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_signed_tuf_target_rejects_untrusted_tuf_root_without_swapping() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let trusted_root_hash = sha256_uri(
        &std::fs::read(tough_fixture("simple-rsa").join("root.json"))
            .expect("trusted TUF root fixture reads"),
    );
    let config_yaml = std::fs::read_to_string(&config_path).expect("config reads");
    std::fs::write(
        &config_path,
        config_yaml.replace(
            &trusted_root_hash,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
    )
    .expect("config writes");
    let fixture = build_fixture_from_config_path(tmp, config_path);
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("owner: Test Ministry", "owner: Untrusted Root Ministry");
    let signed = write_signed_config_tuf_fixture(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_threshold");

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["instance"]["owner"], "Test Ministry");
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn config_apply_signed_tuf_target_rejects_expired_local_trust_root_without_swapping() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let config_yaml = std::fs::read_to_string(&config_path).expect("config reads");
    std::fs::write(
        &config_path,
        config_yaml.replace(
            "      high_risk_change_classes: []",
            "      valid_until_unix_seconds: 1\n      high_risk_change_classes: []",
        ),
    )
    .expect("config writes");
    let fixture = build_fixture_from_config_path(tmp, config_path);
    let candidate = std::fs::read_to_string(&fixture.config_path)
        .expect("config reads")
        .replace("owner: Test Ministry", "owner: Expired Root Ministry");
    let signed = write_signed_config_tuf_fixture(
        &fixture,
        &candidate,
        5,
        "relay-test-instance",
        &["kid-a", "kid-b"],
    )
    .await;

    let response = post_admin_config(
        &fixture,
        "/admin/v1/config/apply",
        signed_tuf_apply_request(&signed),
        ADMIN_KEY,
    )
    .await;

    response.assert_status(StatusCode::CONFLICT);
    let body: Value = response.json();
    assert_eq!(body["result"], "rejected_threshold");

    let posture = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    posture.assert_status(StatusCode::OK);
    let posture: Value = posture.json();
    assert_eq!(posture["instance"]["owner"], "Test Ministry");
    assert_eq!(posture["configuration"]["last_apply_result"], Value::Null);
}

#[tokio::test]
async fn posture_uses_stable_instance_defaults_when_instance_block_is_omitted() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config_with_instance(&tmp, None);
    let fixture = build_fixture_from_config_path(tmp, config_path);

    let resp = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_matches_posture_schema(&body);
    assert_eq!(body["instance"]["id"], "registry-relay-local");
    assert_eq!(body["instance"]["environment"], "development");
    assert!(body["instance"].get("owner").is_none());
    assert!(body["instance"].get("jurisdiction").is_none());
}

#[tokio::test]
async fn posture_response_has_schema_metadata_and_redacted_public_summaries() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;

    resp.assert_status(StatusCode::OK);
    let raw = resp.text();
    assert_not_contains_any(
        &raw,
        &[
            AUDIT_SECRET_VALUE,
            NON_KEY_PLACEHOLDER_VALUE,
            "REGISTRY_RELAY_TEST_AUDIT_HASH_SECRET",
            "REGISTRY_RELAY_TEST_PRIVATE_JWK",
            "hash_secret_env",
            "api_keys",
            "fingerprint",
            "token_env",
            "jwk_env",
            "private_jwk",
            r#""d""#,
            "beneficiary_id",
            "food_subsidy",
            r#""id":1654"#,
            "social_registry.csv",
            "admin_bind",
            "cache_dir",
            "trusted_roots",
        ],
    );
    let body: Value = serde_json::from_str(&raw).expect("posture is JSON");
    assert_matches_posture_schema(&body);
    assert_eq!(body["schema"], "registry.ops.posture.v1");
    assert_eq!(body["component"], "registry-relay");
    assert_eq!(body["instance"]["id"], "relay-test-instance");
    assert_eq!(body["build"]["package"], "registry-relay");
    assert!(body["build"]["version"]
        .as_str()
        .is_some_and(|version| !version.is_empty()));
    assert!(body["build"].get("git_sha").is_none());
    assert!(body["build"].get("features").is_none());
    assert_eq!(body["runtime"]["auth_mode"], "api_key");
    assert_eq!(body["configuration"]["source"], "local_file");
    assert_eq!(body["configuration"]["dynamic_reload_supported"], false);
    assert!(body["configuration"]["last_config_hash"]
        .as_str()
        .is_some_and(|hash| hash.starts_with("sha256:")));
    assert!(body["standards_artifacts"]["metadata_index"]
        .get("url")
        .is_none());
    assert_eq!(
        body["standards_artifacts"]["bregdcat_ap"]["observed_status"],
        "configured_not_checked"
    );
    assert_eq!(body["relay"]["metadata_manifest"]["configured"], true);
    assert!(body["relay"]["provenance"]["enabled"].is_boolean());
    assert!(body["relay"]["provenance"].get("issuer").is_none());
    assert!(body["relay"]["provenance"].get("active_kid").is_none());
    assert!(body["relay"]["provenance"].get("retired_kids").is_none());
    assert!(body["relay"]["provenance"].get("jwk_env").is_none());
    assert!(body["relay"]["provenance"].get("private_jwk").is_none());
}

#[tokio::test]
async fn restricted_posture_reports_file_watch_provider_and_ready_key() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let key_path = tmp.path().join("active-file-watch.jwk");
    let kid = "did:web:data.example.test#relay-public-key";
    write_ed25519_jwk(&key_path, kid);
    let yaml = std::fs::read_to_string(&config_path)
        .expect("config reads")
        .replace("enabled: false", "enabled: true")
        .replace(
            "kind: software\n      jwk_env: REGISTRY_RELAY_TEST_PRIVATE_JWK\n      signing_algorithm: EdDSA",
            &format!(
                "kind: file_watch\n      path: \"{}\"\n      signing_algorithm: EdDSA",
                key_path.to_string_lossy()
            ),
        );
    std::fs::write(&config_path, yaml).expect("config writes");
    let fixture = build_fixture_from_config_path_with_provenance_state(tmp, config_path, true);

    let restricted = fixture
        .server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    restricted.assert_status(StatusCode::OK);
    let body: Value = restricted.json();
    assert_matches_posture_schema(&body);
    assert_eq!(body["tier"], "restricted");
    assert_eq!(body["relay"]["provenance"]["enabled"], true);
    assert_eq!(body["relay"]["provenance"]["active_provider"], "file_watch");
    assert_eq!(body["relay"]["provenance"]["key_readiness"][kid], "ready");

    std::fs::write(&key_path, "{not valid jwk").expect("write malformed key replacement");
    let degraded = fixture
        .server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    degraded.assert_status(StatusCode::OK);
    let body: Value = degraded.json();
    assert_matches_posture_schema(&body);
    assert_eq!(
        body["relay"]["provenance"]["key_readiness"][kid],
        "degraded"
    );

    let default = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    default.assert_status(StatusCode::OK);
    let body: Value = default.json();
    assert!(body["relay"]["provenance"].get("active_provider").is_none());
    assert!(body["relay"]["provenance"].get("key_readiness").is_none());
}

#[tokio::test]
async fn posture_reads_provenance_readiness_from_swapped_runtime_snapshot() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let key_path = tmp.path().join("active-file-watch.jwk");
    let kid = "did:web:data.example.test#relay-public-key";
    write_ed25519_jwk(&key_path, kid);
    let yaml = std::fs::read_to_string(&config_path)
        .expect("config reads")
        .replace("enabled: false", "enabled: true")
        .replace(
            "kind: software\n      jwk_env: REGISTRY_RELAY_TEST_PRIVATE_JWK\n      signing_algorithm: EdDSA",
            &format!(
                "kind: file_watch\n      path: \"{}\"\n      signing_algorithm: EdDSA",
                key_path.to_string_lossy()
            ),
        );
    std::fs::write(&config_path, yaml).expect("config writes");
    let fixture = build_fixture_from_config_path_with_provenance_state(tmp, config_path, true);

    let before = fixture
        .server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    before.assert_status(StatusCode::OK);
    let body: Value = before.json();
    assert_eq!(body["relay"]["provenance"]["key_readiness"][kid], "ready");

    let current = fixture.handle.load_full();
    fixture
        .handle
        .store(snapshot_with_provenance_state(&current, None));

    let after = fixture
        .server
        .get("/admin/v1/posture?tier=restricted")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    after.assert_status(StatusCode::OK);
    let body: Value = after.json();
    assert_eq!(
        body["relay"]["provenance"]["key_readiness"][kid],
        "not_ready"
    );
}

#[tokio::test]
async fn posture_warns_when_audit_checkpoint_unavailable() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_matches_posture_schema(&body);
    assert_eq!(body["posture"]["audit"]["checkpoint_status"], "unavailable");
    assert!(body["posture"]["warnings"]
        .as_array()
        .expect("warnings array")
        .iter()
        .any(|warning| warning == "relay.audit_checkpoint_unavailable"));
}

#[tokio::test]
async fn admin_routes_are_not_mounted_on_public_app() {
    let fixture = build_fixture();

    for route in ["/admin/v1/posture", "/admin/v1/capabilities"] {
        let resp = fixture
            .public_server
            .get(route)
            .add_header("Authorization", format!("Bearer {OPS_KEY}"))
            .await;

        resp.assert_status(StatusCode::NOT_FOUND);
    }

    for route in [
        "/admin/v1/config/verify",
        "/admin/v1/config/dry-run",
        "/admin/v1/config/apply",
        "/admin/v1/reload",
        "/admin/v1/datasets/social_registry/tables/beneficiaries_csv/reload",
    ] {
        let resp = fixture
            .public_server
            .post(route)
            .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
            .await;

        resp.assert_status(StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn table_reload_publishes_updated_readiness_snapshot() {
    let fixture = build_fixture();

    let before = fixture.server.get("/ready").await;
    let before_body = assert_problem(
        before,
        StatusCode::SERVICE_UNAVAILABLE,
        "schema.resource_unavailable",
    )
    .await;
    assert_eq!(before_body["not_ready_count"], 2);

    fixture
        .server
        .post("/admin/v1/datasets/social_registry/tables/beneficiaries_csv/reload")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await
        .assert_status(StatusCode::OK);

    let after = fixture.server.get("/ready").await;
    let after_body = assert_problem(
        after,
        StatusCode::SERVICE_UNAVAILABLE,
        "schema.resource_unavailable",
    )
    .await;
    assert_eq!(after_body["not_ready_count"], 1);
}

#[tokio::test]
async fn fail_closed_audit_failure_blocks_table_reload_before_mutation() {
    let fixture = build_fail_closed_fixture_with_failing_audit_sink();

    let before = fixture.server.get("/ready").await;
    let before_body = assert_problem(
        before,
        StatusCode::SERVICE_UNAVAILABLE,
        "schema.resource_unavailable",
    )
    .await;
    assert_eq!(before_body["not_ready_count"], 2);

    let response = fixture
        .server
        .post("/admin/v1/datasets/social_registry/tables/beneficiaries_csv/reload")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await;
    assert_problem(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        AUDIT_WRITE_FAILED_CODE,
    )
    .await;

    let after = fixture.server.get("/ready").await;
    let after_body = assert_problem(
        after,
        StatusCode::SERVICE_UNAVAILABLE,
        "schema.resource_unavailable",
    )
    .await;
    assert_eq!(
        after_body["not_ready_count"], 2,
        "table reload must not mutate readiness when fail-closed audit preflight fails"
    );
}

#[tokio::test]
async fn reload_all_without_credential_is_rejected() {
    let fixture = build_fixture();

    let resp = fixture.server.post("/admin/v1/reload").await;

    assert_problem(resp, StatusCode::UNAUTHORIZED, "auth.missing_credential").await;
}

#[tokio::test]
async fn reload_all_with_non_admin_key_is_rejected() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .post("/admin/v1/reload")
        .add_header("Authorization", format!("Bearer {NON_ADMIN_KEY}"))
        .await;

    let body = assert_problem(resp, StatusCode::FORBIDDEN, "auth.scope_denied").await;
    assert_eq!(body["detail"], "required scope: registry_relay:admin");
}

#[tokio::test]
async fn fail_closed_audit_failure_blocks_reload_all_before_mutation() {
    let fixture = build_fail_closed_fixture_with_failing_audit_sink();

    let before = fixture.server.get("/ready").await;
    let before_body = assert_problem(
        before,
        StatusCode::SERVICE_UNAVAILABLE,
        "schema.resource_unavailable",
    )
    .await;
    assert_eq!(before_body["not_ready_count"], 2);

    let resp = fixture
        .server
        .post("/admin/v1/reload")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await;
    assert_problem(
        resp,
        StatusCode::SERVICE_UNAVAILABLE,
        AUDIT_WRITE_FAILED_CODE,
    )
    .await;

    let after = fixture.server.get("/ready").await;
    let after_body = assert_problem(
        after,
        StatusCode::SERVICE_UNAVAILABLE,
        "schema.resource_unavailable",
    )
    .await;
    assert_eq!(
        after_body["not_ready_count"], 2,
        "reload_all must not mutate readiness when fail-closed audit preflight fails"
    );
}

#[tokio::test]
async fn reload_all_with_admin_key_reloads_every_configured_resource() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .post("/admin/v1/reload")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["counts"]["total"], 2);
    assert_eq!(body["counts"]["succeeded"], 2);
    assert_eq!(body["counts"]["failed"], 0);

    assert!(body.get("resources").is_none());
    let dump = body.to_string();
    assert!(!dump.contains("social_registry"));
    assert!(!dump.contains("beneficiaries_csv"));
    assert!(!dump.contains("beneficiaries_copy_csv"));
}

#[tokio::test]
async fn reload_all_publishes_ready_snapshot() {
    let fixture = build_fixture();

    fixture
        .server
        .post("/admin/v1/reload")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await
        .assert_status(StatusCode::OK);

    let resp = fixture.server.get("/ready").await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["checks"]["total"], 2);
    assert_eq!(body["checks"]["ok"], 2);
    assert_eq!(body["checks"]["failed"], 0);
    assert!(body.get("counts").is_none());
    assert!(body.get("resources").is_none());
}

#[tokio::test]
async fn table_reload_invalidates_public_entity_collection_etag_after_source_change() {
    let fixture = build_fixture();

    fixture
        .server
        .post("/admin/v1/reload")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await
        .assert_status(StatusCode::OK);

    let before = fixture
        .public_server
        .get("/v1/datasets/social_registry/entities/beneficiary/records?limit=1000")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await;
    before.assert_status(StatusCode::OK);
    let before_etag = before.header("etag").to_str().expect("etag").to_string();
    let before_body: Value = before.json();
    assert_eq!(program_for_beneficiary(&before_body, 1654), "food_subsidy");

    let updated_csv = "\
beneficiary_id,household_size,municipality_code,program,amount_eur,joined_date,last_updated
1654,2,AA001,emergency_cash,760.07,2020-07-03,2019-02-24
";
    std::fs::write(&fixture.source_path, updated_csv).expect("rewrite source fixture");

    fixture
        .server
        .post("/admin/v1/datasets/social_registry/tables/beneficiaries_csv/reload")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await
        .assert_status(StatusCode::OK);

    let stale_revalidation = fixture
        .public_server
        .get("/v1/datasets/social_registry/entities/beneficiary/records?limit=1000")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .add_header("if-none-match", &before_etag)
        .await;
    stale_revalidation.assert_status(StatusCode::OK);
    let after_etag = stale_revalidation
        .header("etag")
        .to_str()
        .expect("etag")
        .to_string();
    assert_ne!(after_etag, before_etag);
    let after_body: Value = stale_revalidation.json();
    assert_eq!(program_for_beneficiary(&after_body, 1654), "emergency_cash");
}

fn program_for_beneficiary(body: &Value, id: i64) -> &str {
    body["data"]
        .as_array()
        .expect("collection data is an array")
        .iter()
        .find(|row| row["id"] == id)
        .and_then(|row| row["program"].as_str())
        .expect("beneficiary row present")
}
