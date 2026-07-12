// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the config loader.
//!
//! These tests parse the canonical example verbatim, surface
//! cross-field validation errors with stable `config.*` codes, and
//! round-trip the prefix expansion helper.
//!
//! Env vars are scoped per-fixture (each test uses unique names) so
//! the suite can run with the default test runner without forcing
//! `--test-threads=1`.

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_config::{
    sha256_uri, ConfigBundleFile, ConfigBundleManifest, ConfigBundleSignature,
    ConfigBundleSignatureEnvelope, ConfigTrustAnchor, ConfigTrustAnchorSigner,
};
use registry_platform_crypto::{canonicalize_json, sign, PrivateJwk};
use registry_platform_ops::ConfigSource;
use registry_relay::config::vocabularies;
use registry_relay::config::{
    self, AccessRights, AggregateFunction, AuditFormat, AuditSinkConfig, AuthMode, FieldType,
    FilterOp, MaterializationMode, OidcAlgorithm, RefreshConfig, Sensitivity, SourceConfig,
    Suppression, UpdateFrequency,
};
use registry_relay::error::{ConfigError, Error};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const CONFIG_BUNDLE_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;

fn make_fingerprint(plaintext: &[u8]) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(plaintext)))
}

fn seed_fingerprint_env(name: &str) {
    env::set_var(name, make_fingerprint(name.as_bytes()));
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

/// Path to the canonical example shipped alongside the crate.
fn example_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/example.yaml")
}

/// Path to the OIDC variant of the canonical example.
fn example_oidc_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/example.oidc.yaml")
}

fn perf_config_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("perf/config")
        .join(name)
}

/// Path to a fixture under `tests/fixtures/config/<name>`.
fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config")
        .join(name)
}

fn write_config(tmp: &TempDir, body: &str) -> PathBuf {
    let path = tmp.path().join("config.yaml");
    std::fs::write(&path, body).expect("write config");
    path
}

struct SignedBundleFixture {
    bundle_dir: PathBuf,
    anchor_path: PathBuf,
    state_path: PathBuf,
    config_hash: String,
}

fn write_signed_relay_bundle(tmp: &TempDir) -> SignedBundleFixture {
    let bundle_dir = tmp.path().join("bundle");
    let config_dir = bundle_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("bundle config dir");
    let config = relay_bundle_runtime_config();
    std::fs::write(config_dir.join("relay.yaml"), config.as_bytes()).expect("config writes");
    let config_hash = sha256_uri(config.as_bytes());

    let private = PrivateJwk::parse(CONFIG_BUNDLE_PRIVATE_JWK).expect("private jwk");
    let public = private.public();
    let kid = public.jkt().expect("thumbprint");
    let manifest = ConfigBundleManifest {
        schema: "registry.platform.config_bundle.v1".to_string(),
        product: "registry-relay".to_string(),
        environment: "lab".to_string(),
        stream_id: "relay-loader-test".to_string(),
        instance_id: None,
        bundle_id: "relay-loader-bundle".to_string(),
        sequence: 1,
        previous_config_hash: None,
        config_hash: config_hash.clone(),
        files: vec![ConfigBundleFile {
            path: "config/relay.yaml".to_string(),
            sha256: config_hash.clone(),
        }],
        created_at: "2026-07-07T10:00:00Z".to_string(),
    };
    write_manifest_and_signature(&bundle_dir, &manifest, &private, &kid);
    let anchor = ConfigTrustAnchor {
        schema: "registry.platform.config_trust_anchor.v1".to_string(),
        product: "registry-relay".to_string(),
        environment: "lab".to_string(),
        stream_id: "relay-loader-test".to_string(),
        instance_id: "relay-lab".to_string(),
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

fn write_manifest_and_signature(
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

fn relay_bundle_runtime_config() -> String {
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

fn relay_bootstrap_config(fixture: &SignedBundleFixture) -> String {
    format!(
        r#"{}
config_trust:
  trust_anchor_path: {}
  bundle_path: {}
  antirollback_state_path: {}
"#,
        relay_bundle_runtime_config(),
        fixture.anchor_path.display(),
        fixture.bundle_dir.display(),
        fixture.state_path.display()
    )
}

fn minimal_config(dataset_body: &str) -> String {
    format!(
        r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
deployment:
  profile: local
vocabularies: {{}}
auth:
  mode: api_key
  api_keys: []
datasets:
{dataset_body}
audit:
  sink: stdout
  format: jsonl
"#
    )
}

/// Assert that `result` is a `ConfigError` carrying the requested
/// stable code. Returns the message for further inspection.
#[track_caller]
fn assert_config_code(result: Result<config::Config, Error>, expected_code: &str) -> String {
    match result {
        Ok(_) => panic!("expected config error with code {expected_code}, got Ok"),
        Err(err) => {
            assert_eq!(
                err.code(),
                expected_code,
                "wrong code: got {}, expected {}",
                err.code(),
                expected_code
            );
            err.to_string()
        }
    }
}

#[test]
fn example_config_loads_and_validates() {
    // All configured keys point at env vars; provide valid fingerprints.
    // Safe to set: env name is unique to the example.
    seed_fingerprint_env("STATS_OFFICE_API_KEY_HASH");
    seed_fingerprint_env("PROGRAM_SYSTEM_API_KEY_HASH");
    seed_fingerprint_env("VERIFICATION_SERVICE_API_KEY_HASH");
    seed_fingerprint_env("OPERATIONS_OPERATOR_API_KEY_HASH");
    let config = config::load(&example_path()).expect("example config must load");

    assert_eq!(config.instance.id, "registry-relay-local");
    assert_eq!(config.instance.environment.as_deref(), Some("development"));
    assert_eq!(
        config.instance.owner.as_deref(),
        Some("Ministry of Digital Government")
    );
    assert_eq!(
        config.instance.jurisdiction.as_deref(),
        Some("example-country")
    );
    assert_eq!(config.server.bind.to_string(), "0.0.0.0:8080");

    assert_eq!(config.catalog.title, "Internal Government Registry Relay");
    assert_eq!(config.catalog.base_url, "https://data.example.gov");
    assert_eq!(config.catalog.publisher, "Ministry of Digital Government");
    assert_eq!(
        config.catalog.participant_id.as_deref(),
        Some("did:web:data.example.gov")
    );

    assert!(matches!(config.auth.mode, AuthMode::ApiKey));
    assert_eq!(config.auth.api_keys.len(), 4);
    assert_eq!(config.auth.api_keys[0].id, "statistics_office");
    assert_eq!(
        config.auth.api_keys[0].fingerprint.name.as_deref(),
        Some("STATS_OFFICE_API_KEY_HASH")
    );
    let ops = config
        .auth
        .api_keys
        .iter()
        .find(|key| key.id == "operations_operator")
        .expect("operations operator key is configured");
    assert_eq!(
        ops.fingerprint.name.as_deref(),
        Some("OPERATIONS_OPERATOR_API_KEY_HASH")
    );
    assert_eq!(ops.scopes, ["registry_relay:ops_read"]);

    assert_eq!(config.datasets.len(), 1);
    let dataset = &config.datasets[0];
    assert_eq!(dataset.id.as_ref(), "social_registry");
    assert_eq!(dataset.title, "Social Registry");
    assert!(matches!(dataset.sensitivity, Sensitivity::Personal));
    assert!(matches!(dataset.access_rights, AccessRights::Restricted));
    assert!(matches!(dataset.update_frequency, UpdateFrequency::Monthly));
    assert_eq!(dataset.conforms_to.len(), 3);

    assert_eq!(dataset.tables.len(), 2);
    let first_table = &dataset.tables[0];
    assert_eq!(first_table.id.as_ref(), "households_table");
    assert!(matches!(
        first_table.materialization,
        Some(MaterializationMode::Snapshot)
    ));
    match &first_table.source {
        SourceConfig::File { path, format, .. } => {
            assert_eq!(path.to_string_lossy(), "./data/social_registry.xlsx");
            let xlsx = format
                .as_ref()
                .and_then(|format| format.xlsx.as_ref())
                .expect("xlsx format");
            assert_eq!(xlsx.sheet.as_deref(), Some("Households"));
        }
        other => panic!("expected source type file, got {other:?}"),
    }
    match first_table.refresh.as_ref().expect("table refresh") {
        RefreshConfig::Mtime { interval } => {
            assert_eq!(interval.as_secs(), 3600);
        }
        other => panic!("expected refresh mode mtime, got {other:?}"),
    }

    let table = &dataset.tables[1];
    assert_eq!(table.id.as_ref(), "individuals_table");
    assert!(matches!(
        table.materialization,
        Some(MaterializationMode::Snapshot)
    ));
    assert_eq!(table.format_name(), Some("xlsx"));
    assert_eq!(table.xlsx_sheet().as_deref(), Some("Individuals"));
    assert_eq!(table.primary_key.as_deref(), Some("individual_id"));
    assert!(table.schema.strict);
    assert_eq!(table.schema.fields.len(), 4);

    let payment = table
        .schema
        .fields
        .iter()
        .find(|f| f.name == "payment_amount")
        .expect("payment_amount field present");
    assert!(matches!(payment.r#type, FieldType::Number));
    assert_eq!(payment.unit.as_deref(), Some("EUR"));

    assert_eq!(dataset.entities.len(), 2);
    let individual = &dataset.entities[1];
    assert_eq!(individual.name, "individual");
    assert_eq!(individual.table.as_ref(), "individuals_table");
    assert_eq!(individual.fields.len(), 4);
    let payment_field = individual
        .fields
        .iter()
        .find(|f| f.name == "payment_amount")
        .expect("entity payment field present");
    assert_eq!(
        payment_field.concept_uri.as_deref(),
        Some("psc:properties/paymentAmount")
    );
    assert_eq!(individual.relationships.len(), 1);
    assert_eq!(individual.api.default_limit, 100);
    assert_eq!(individual.api.max_limit, 1000);
    assert!(individual.api.require_purpose_header);
    assert_eq!(individual.api.allowed_filters.len(), 3);
    let household_filter = individual
        .api
        .allowed_filters
        .iter()
        .find(|f| f.field == "household_id")
        .expect("household_id filter present");
    assert!(household_filter.ops.contains(&FilterOp::Eq));

    assert!(individual.aggregates.is_empty());
    assert_eq!(dataset.aggregates.len(), 3);
    let pay_agg = &dataset.aggregates[1];
    assert_eq!(pay_agg.id.as_ref(), "payments_by_municipality");
    assert_eq!(pay_agg.indicators.len(), 2);
    assert!(matches!(
        pay_agg.indicators[0].function,
        AggregateFunction::Sum
    ));
    assert!(matches!(
        pay_agg.indicators[1].function,
        AggregateFunction::Avg
    ));
    assert_eq!(pay_agg.disclosure_control.effective_min_cell_size(), 5);
    assert!(matches!(
        pay_agg.disclosure_control.suppression,
        Suppression::Mask
    ));

    assert!(matches!(config.audit.sink, AuditSinkConfig::Stdout {}));
    assert!(matches!(config.audit.format, AuditFormat::Jsonl));

    // CORS is default-deny: empty allowlist.
    assert!(config.server.cors.allowed_origins.is_empty());

    // Server transport limits default to bounded values.
    assert_eq!(config.server.request_timeout.as_secs(), 30);
    assert_eq!(config.server.request_body_timeout.as_secs(), 10);
    assert_eq!(config.server.http1_header_read_timeout.as_secs(), 10);
    assert_eq!(config.server.max_connections, 1024);
}

#[test]
fn signed_bundle_config_loads_with_pending_acceptance() {
    let tmp = TempDir::new().expect("tempdir");
    let fixture = write_signed_relay_bundle(&tmp);
    let config_path = write_config(&tmp, &relay_bootstrap_config(&fixture));

    let loaded = config::load_with_metadata_options(
        &config_path,
        config::LoadOptions {
            initialize_state: true,
        },
    )
    .expect("signed bundle config loads");

    assert_eq!(loaded.provenance.source, ConfigSource::SignedBundleFile);
    assert_eq!(loaded.provenance.internal_config_hash, fixture.config_hash);
    let acceptance = loaded
        .pending_bundle_acceptance
        .expect("pending acceptance");
    assert_eq!(acceptance.source, ConfigSource::SignedBundleFile);
    assert_eq!(acceptance.bundle_id.as_deref(), Some("relay-loader-bundle"));
    assert_eq!(acceptance.sequence, Some(1));
    assert_eq!(acceptance.config_hash, fixture.config_hash);
    assert!(matches!(
        acceptance.state_action,
        config::BundleStateAction::Initialize
    ));
}

#[test]
fn perf_api_key_scopes_are_explicit_lists() {
    for name in ["small.yaml", "medium.yaml", "large.yaml"] {
        let path = perf_config_path(name);
        let yaml = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        let value: serde_json::Value = serde_saphyr::from_str(&yaml)
            .unwrap_or_else(|err| panic!("{} must parse as YAML: {err}", path.display()));
        let api_keys = value
            .pointer("/auth/api_keys")
            .and_then(serde_json::Value::as_array)
            .unwrap_or_else(|| panic!("{} auth.api_keys must be a list", path.display()));
        let mut actual_ids = Vec::new();
        for key in api_keys {
            let id = key
                .get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("{} API key must have an id", path.display()));
            let scopes = key
                .get("scopes")
                .and_then(serde_json::Value::as_array)
                .unwrap_or_else(|| panic!("{} {id} scopes must be a list", path.display()));
            let actual_scopes = scopes
                .iter()
                .map(|scope| {
                    scope
                        .as_str()
                        .unwrap_or_else(|| panic!("{} {id} scope must be a string", path.display()))
                })
                .collect::<Vec<_>>();
            let expected_scopes = match id {
                "perf_rows" => vec!["clinic_capacity:rows"],
                "perf_metadata" => vec!["clinic_capacity:metadata"],
                "perf_aggregate" => vec!["clinic_capacity:aggregate"],
                "perf_no_scope" => Vec::new(),
                "perf_evidence_verification" => vec!["clinic_capacity:evidence_verification"],
                "perf_admin" => vec!["registry_relay:admin"],
                other => panic!("{} unexpected perf API key {other}", path.display()),
            };
            assert_eq!(
                actual_scopes,
                expected_scopes,
                "{} {id} scopes changed",
                path.display()
            );
            actual_ids.push(id);
        }
        assert_eq!(
            actual_ids,
            [
                "perf_rows",
                "perf_metadata",
                "perf_aggregate",
                "perf_no_scope",
                "perf_evidence_verification",
                "perf_admin"
            ],
            "{} perf API key order changed",
            path.display()
        );
    }
}

#[test]
fn unknown_field_rejected() {
    let result = config::load(&fixture_path("unknown_field.yaml"));
    assert_config_code(result, "config.parse_error");
}

#[test]
fn legacy_api_key_fingerprint_commitment_rejected() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_config(
        &tmp,
        r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
deployment:
  profile: local
vocabularies: {}
auth:
  mode: api_key
  api_keys:
    - id: old-key
      fingerprint:
        provider: env
        name: TEST_KEY_HASH_LEGACY_COMMITMENT
        commitment: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
datasets: []
audit:
  sink: stdout
  format: jsonl
"#,
    );

    assert_config_code(config::load(&path), "config.parse_error");

    let raw = std::fs::read_to_string(&path).expect("read config");
    let err = serde_saphyr::from_str::<config::Config>(&raw)
        .expect_err("legacy fingerprint commitment must fail deserialization");
    assert!(
        err.to_string()
            .contains("fingerprint.commitment was removed"),
        "unexpected error: {err}"
    );
}

#[test]
fn server_transport_limits_must_be_nonzero() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_config(
        &tmp,
        r#"
server:
  bind: 127.0.0.1:0
  request_body_timeout: 0s
  http1_header_read_timeout: 0s
  max_connections: 0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
deployment:
  profile: local
vocabularies: {}
auth:
  mode: api_key
  api_keys: []
datasets: []
audit:
  sink: stdout
  format: jsonl
"#,
    );

    assert_config_code(config::load(&path), "config.validation_error");
}

#[test]
fn removed_embedded_evidence_server_config_rejected() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_config(
        &tmp,
        r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
deployment:
  profile: local
vocabularies: {}
auth:
  mode: api_key
  api_keys: []
datasets: []
audit:
  sink: stdout
  format: jsonl
evidence:
  service_id: old-embedded-evidence-server
"#,
    );
    // `evidence:` is now an unknown field rejected at parse time.
    assert_config_code(config::load(&path), "config.parse_error");
}

#[test]
fn invalid_scope_rejected() {
    seed_fingerprint_env("TEST_KEY_HASH_SCOPE");
    let result = config::load(&fixture_path("invalid_scope.yaml"));
    let msg = assert_config_code(result, "config.validation_error");
    // No assertion on the offending scope value beyond the code; the
    // tracing log carries the full context per `error.rs` scrubbing
    // rules. We do confirm the rendered message is generic.
    assert!(msg.contains("validation"), "got: {msg}");
}

#[test]
fn missing_env_var_rejected() {
    // Be extra-safe: explicitly unset before exercising the loader.
    env::remove_var("TEST_KEY_HASH_MISSING_NOPE");
    let result = config::load(&fixture_path("missing_env.yaml"));
    assert_config_code(result, "config.missing_secret");
}

#[test]
fn duplicate_dataset_id_rejected() {
    seed_fingerprint_env("TEST_KEY_HASH_DUP");
    let result = config::load(&fixture_path("duplicate_dataset_id.yaml"));
    assert_config_code(result, "config.duplicate_id");
}

#[test]
fn duplicate_api_key_id_rejected() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(
        &tmp,
        r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
deployment:
  profile: local
vocabularies: {}
auth:
  mode: api_key
  api_keys:
    - id: duplicate_key
      fingerprint:
        provider: env
        name: TEST_KEY_HASH_DUPLICATE_ID_ONE
    - id: duplicate_key
      fingerprint:
        provider: env
        name: TEST_KEY_HASH_DUPLICATE_ID_TWO
datasets: []
audit:
  sink: stdout
  format: jsonl
"#,
    );

    assert_config_code(config::load(&config_path), "config.duplicate_id");
}

#[test]
fn unknown_vocabulary_prefix_rejected() {
    seed_fingerprint_env("TEST_KEY_HASH_VOCAB");
    let result = config::load(&fixture_path("unknown_vocab_prefix.yaml"));
    assert_config_code(result, "config.validation_error");
}

#[test]
fn invalid_authority_type_rejected() {
    seed_fingerprint_env("TEST_KEY_HASH_AUTH_TYPE");
    let result = config::load(&fixture_path("invalid_authority_type.yaml"));
    assert_config_code(result, "config.validation_error");
}

#[test]
fn invalid_publisher_iri_rejected() {
    seed_fingerprint_env("TEST_KEY_HASH_PUBLISHER_IRI");
    let result = config::load(&fixture_path("invalid_publisher_iri.yaml"));
    assert_config_code(result, "config.validation_error");
}

#[test]
fn invalid_default_spatial_coverage_rejected() {
    seed_fingerprint_env("TEST_KEY_HASH_DEF_SPATIAL");
    let result = config::load(&fixture_path("invalid_default_spatial_coverage.yaml"));
    assert_config_code(result, "config.validation_error");
}

#[test]
fn invalid_dataset_spatial_coverage_rejected() {
    seed_fingerprint_env("TEST_KEY_HASH_DS_SPATIAL");
    let result = config::load(&fixture_path("invalid_dataset_spatial_coverage.yaml"));
    assert_config_code(result, "config.validation_error");
}

#[test]
fn allowed_filter_unknown_field_rejected() {
    seed_fingerprint_env("TEST_KEY_HASH_FILTER");
    let result = config::load(&fixture_path("allowed_filter_unknown_field.yaml"));
    assert_config_code(result, "config.validation_error");
}

#[test]
fn legacy_claim_verification_config_is_rejected() {
    let tmp = TempDir::new().expect("tempdir");
    let body = minimal_config(
        r#"
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
      - id: people_table
        source:
          type: file
          path: fixtures/people.csv
        primary_key: person_id
        schema:
          strict: true
          fields:
            - name: person_id
              type: string
              nullable: false
            - name: given_name
              type: string
    entities:
      - name: person
        table: people_table
        fields:
          - name: id
            from: person_id
          - name: given_name
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
          claim_verification_scope: social_registry:claim_verification
        api:
          default_limit: 100
          max_limit: 1000
        claim_verification:
          rulesets:
            request-v1:
              mode: normalized_exact
              required_claims: [given_name]
              candidate_lookup: [given_name]
              match_fields:
                given_name: given_name
"#,
    );
    let body = body.replace(
        "auth:\n  mode: api_key\n  api_keys: []",
        r#"auth:
  mode: api_key
  api_keys: []
claim_verification:
  binding_key_id: legacy
  binding_key_env: REMOVED"#,
    );
    let config_path = write_config(&tmp, &body);

    assert_config_code(config::load(&config_path), "config.parse_error");
}

#[test]
fn relay_provenance_config_block_is_rejected() {
    let tmp = TempDir::new().expect("tempdir");
    let body = minimal_config(
        r#"
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    tables: []
    entities: []
"#,
    )
    .replace(
        "auth:\n  mode: api_key\n  api_keys: []",
        r#"auth:
  mode: api_key
  api_keys: []
provenance:
  enabled: true"#,
    );
    let config_path = write_config(&tmp, &body);

    assert_config_code(config::load(&config_path), "config.parse_error");
}

#[test]
fn relay_publicschema_entity_block_is_rejected() {
    let tmp = TempDir::new().expect("tempdir");
    let body = minimal_config(
        r#"
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    tables:
      - id: people_table
        source:
          type: file
          path: fixtures/people.csv
        primary_key: person_id
        schema:
          strict: true
          fields:
            - name: person_id
              type: string
              nullable: false
    entities:
      - name: person
        table: people_table
        publicschema:
          target: Person
          mapping_path: mappings/person.publicschema.yaml
        fields:
          - name: id
            from: person_id
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 1000
"#,
    );
    let config_path = write_config(&tmp, &body);

    assert_config_code(config::load(&config_path), "config.parse_error");
}

#[test]
fn vocab_expand_roundtrip() {
    let mut registry: BTreeMap<String, String> = BTreeMap::new();
    registry.insert("psc".to_string(), "https://publicschema.org/".to_string());

    assert_eq!(
        vocabularies::expand("psc:concepts/Person", &registry).as_deref(),
        Some("https://publicschema.org/concepts/Person")
    );

    // Absolute URI passes through unchanged.
    assert_eq!(
        vocabularies::expand("https://schema.org/Person", &registry).as_deref(),
        Some("https://schema.org/Person")
    );

    // urn: counts as absolute.
    assert_eq!(
        vocabularies::expand("urn:example:foo", &registry).as_deref(),
        Some("urn:example:foo")
    );

    // Unknown prefix returns None.
    assert!(vocabularies::expand("nope:Foo", &registry).is_none());

    // Strings without `:` or with an unknown prefix do not match.
    assert!(vocabularies::expand("BareString", &registry).is_none());
}

#[test]
fn humantime_parses_interval() {
    seed_fingerprint_env("TEST_KEY_HASH_INTERVAL");
    let config = config::load(&fixture_path("interval_refresh.yaml"))
        .expect("interval_refresh fixture must load");
    let refresh = config.datasets[0]
        .defaults
        .refresh
        .as_ref()
        .expect("dataset default refresh");
    match refresh {
        RefreshConfig::Interval { interval } => {
            assert_eq!(interval.as_secs(), 3600);
        }
        other => panic!("expected interval refresh, got {other:?}"),
    }
}

#[test]
fn table_level_file_source_and_defaults_load() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(
        &tmp,
        &minimal_config(
            r#"
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
      materialization: snapshot
    tables:
      - id: records_table
        source:
          type: file
          path: ./data/records.csv
          format:
            csv:
              delimiter: 44
        primary_key: record_id
        schema:
          strict: true
          fields:
            - name: record_id
              type: string
              nullable: false
    entities: []
"#,
        ),
    );

    let config = config::load(&config_path).expect("config loads");
    let dataset = &config.datasets[0];
    let table = &dataset.tables[0];
    assert!(matches!(
        table.effective_materialization(dataset),
        MaterializationMode::Snapshot
    ));
    assert!(matches!(
        table.effective_refresh(dataset),
        Some(RefreshConfig::Manual {})
    ));
    assert_eq!(table.format_name(), Some("csv"));
    assert_eq!(table.csv_delimiter(), Some(44));
}

#[test]
fn table_source_format_must_choose_exactly_one_format() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(
        &tmp,
        &minimal_config(
            r#"
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
      - id: records_table
        source:
          type: file
          path: ./data/records.xlsx
          format:
            csv: {}
            xlsx: {}
        primary_key: record_id
        schema:
          strict: true
          fields:
            - name: record_id
              type: string
              nullable: false
    entities: []
"#,
        ),
    );

    assert_config_code(config::load(&config_path), "config.validation_error");
}

#[test]
fn postgres_table_source_descriptor_loads_without_reading_secret() {
    let tmp = TempDir::new().expect("tempdir");
    env::remove_var("SOCIAL_REGISTRY_DATABASE_URL");
    let config_path = write_config(
        &tmp,
        &minimal_config(
            r#"
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    tables:
      - id: records_table
        materialization: snapshot
        source:
          type: postgres
          connection_env: SOCIAL_REGISTRY_DATABASE_URL
          table:
            schema: public
            name: records
          change_token_sql: "select max(updated_at)::text from public.records"
        refresh:
          mode: mtime
          interval: 5m
        primary_key: record_id
        schema:
          strict: true
          fields:
            - name: record_id
              type: string
              nullable: false
    entities: []
"#,
        ),
    );

    let config = config::load(&config_path).expect("postgres descriptor loads");
    let source = &config.datasets[0].tables[0].source;
    match source {
        SourceConfig::Postgres {
            connection_env,
            table,
            query,
            change_token_sql,
            connect_timeout,
            query_timeout,
        } => {
            assert_eq!(connection_env, "SOCIAL_REGISTRY_DATABASE_URL");
            let table = table.as_ref().expect("table descriptor");
            assert_eq!(table.schema, "public");
            assert_eq!(table.name, "records");
            assert!(query.is_none());
            assert!(change_token_sql.is_some());
            assert_eq!(*connect_timeout, std::time::Duration::from_secs(5));
            assert_eq!(*query_timeout, std::time::Duration::from_secs(30));
        }
        other => panic!("expected postgres source, got {other:?}"),
    }
}

#[test]
fn resource_row_scope_is_not_accepted_for_beta() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(
        &tmp,
        &minimal_config(
            r#"
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    tables:
      - id: records_table
        source:
          type: file
          path: ./fixtures/social_registry.csv
        primary_key: record_id
        schema:
          strict: true
          fields:
            - name: record_id
              type: string
              nullable: false
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          row_scope: social_registry:rows
    entities: []
"#,
        ),
    );

    assert_config_code(config::load(&config_path), "config.parse_error");
}

#[test]
fn postgres_query_source_descriptor_loads() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(
        &tmp,
        &minimal_config(
            r#"
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    tables:
      - id: records_table
        materialization: snapshot
        source:
          type: postgres
          connection_env: SOCIAL_REGISTRY_DATABASE_URL
          query: "select record_id from public.records"
        refresh:
          mode: interval
          interval: 5m
        primary_key: record_id
        schema:
          strict: true
          fields:
            - name: record_id
              type: string
              nullable: false
    entities: []
"#,
        ),
    );

    let config = config::load(&config_path).expect("postgres query descriptor loads");
    match &config.datasets[0].tables[0].source {
        SourceConfig::Postgres { table, query, .. } => {
            assert!(table.is_none());
            assert_eq!(
                query.as_deref(),
                Some("select record_id from public.records")
            );
        }
        other => panic!("expected postgres source, got {other:?}"),
    }
}

#[test]
fn postgres_table_and_query_are_mutually_exclusive() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(
        &tmp,
        &minimal_config(
            r#"
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    tables:
      - id: records_table
        materialization: snapshot
        source:
          type: postgres
          connection_env: SOCIAL_REGISTRY_DATABASE_URL
          table:
            schema: public
            name: records
          query: "select * from public.records"
        refresh:
          mode: interval
          interval: 5m
        schema:
          strict: false
          fields:
            - name: record_id
              type: string
    entities: []
"#,
        ),
    );

    let msg = assert_config_code(config::load(&config_path), "config.validation_error");
    assert!(!msg.contains("select *"), "query leaked in error: {msg}");
}

#[test]
fn postgres_configured_sql_rejects_semicolons() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(
        &tmp,
        &minimal_config(
            r#"
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    tables:
      - id: records_table
        materialization: snapshot
        source:
          type: postgres
          connection_env: SOCIAL_REGISTRY_DATABASE_URL
          query: "select record_id from public.records; select 1"
        refresh:
          mode: interval
          interval: 5m
        schema:
          strict: false
          fields:
            - name: record_id
              type: string
    entities: []
"#,
        ),
    );

    let msg = assert_config_code(config::load(&config_path), "config.validation_error");
    assert!(
        !msg.contains("select record_id"),
        "query leaked in error: {msg}"
    );
}

#[test]
fn postgres_configured_sql_rejects_data_modifying_cte() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(
        &tmp,
        &minimal_config(
            r#"
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    tables:
      - id: records_table
        materialization: snapshot
        source:
          type: postgres
          connection_env: SOCIAL_REGISTRY_DATABASE_URL
          query: "with changed as (update public.records set exported = true returning record_id) select record_id from changed"
        refresh:
          mode: interval
          interval: 5m
        schema:
          strict: false
          fields:
            - name: record_id
              type: string
    entities: []
"#,
        ),
    );

    let msg = assert_config_code(config::load(&config_path), "config.validation_error");
    assert!(!msg.contains("changed"), "query leaked in error: {msg}");
}

#[test]
fn postgres_configured_sql_rejects_session_state_changes() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(
        &tmp,
        &minimal_config(
            r#"
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    tables:
      - id: records_table
        materialization: snapshot
        source:
          type: postgres
          connection_env: SOCIAL_REGISTRY_DATABASE_URL
          change_token_sql: "select set_config('default_transaction_read_only', 'off', false)"
          table:
            schema: public
            name: records
        refresh:
          mode: mtime
          interval: 5m
        schema:
          strict: false
          fields:
            - name: record_id
              type: string
    entities: []
"#,
        ),
    );

    let msg = assert_config_code(config::load(&config_path), "config.validation_error");
    assert!(!msg.contains("set_config"), "query leaked in error: {msg}");
}

#[test]
fn postgres_configured_sql_rejects_quoted_session_state_functions() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(
        &tmp,
        &minimal_config(
            r#"
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    tables:
      - id: records_table
        materialization: snapshot
        source:
          type: postgres
          connection_env: SOCIAL_REGISTRY_DATABASE_URL
          change_token_sql: "select pg_catalog.\"set_config\"('default_transaction_read_only', 'off', false)"
          table:
            schema: public
            name: records
        refresh:
          mode: mtime
          interval: 5m
        schema:
          strict: false
          fields:
            - name: record_id
              type: string
    entities: []
"#,
        ),
    );

    let msg = assert_config_code(config::load(&config_path), "config.validation_error");
    assert!(!msg.contains("set_config"), "query leaked in error: {msg}");
}

#[test]
fn postgres_configured_sql_rejects_escape_string_bypass() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(
        &tmp,
        &minimal_config(
            r#"
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    tables:
      - id: records_table
        materialization: snapshot
        source:
          type: postgres
          connection_env: SOCIAL_REGISTRY_DATABASE_URL
          change_token_sql: "select E'foo\\' ' from pg_sleep(10)"
          table:
            schema: public
            name: records
        refresh:
          mode: mtime
          interval: 5m
        schema:
          strict: false
          fields:
            - name: record_id
              type: string
    entities: []
"#,
        ),
    );

    let msg = assert_config_code(config::load(&config_path), "config.validation_error");
    assert!(!msg.contains("pg_sleep"), "query leaked in error: {msg}");
}

#[test]
fn postgres_configured_sql_allows_disallowed_words_inside_strings() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(
        &tmp,
        &minimal_config(
            r#"
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    tables:
      - id: records_table
        materialization: snapshot
        source:
          type: postgres
          connection_env: SOCIAL_REGISTRY_DATABASE_URL
          query: "select 'update' as record_id from public.records"
        refresh:
          mode: interval
          interval: 5m
        primary_key: record_id
        schema:
          strict: false
          fields:
            - name: record_id
              type: string
    entities: []
"#,
        ),
    );

    config::load(&config_path).expect("quoted text does not fail read-only validation");
}

#[test]
fn live_materialization_is_rejected_at_parse_time() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(
        &tmp,
        &minimal_config(
            r#"
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    tables:
      - id: records_table
        materialization: live
        source:
          type: postgres
          connection_env: SOCIAL_REGISTRY_DATABASE_URL
          table:
            schema: public
            name: records
        refresh:
          mode: manual
        schema:
          strict: false
          fields:
            - name: record_id
              type: string
    entities: []
"#,
        ),
    );

    assert_config_code(config::load(&config_path), "config.parse_error");
}

#[test]
fn postgres_live_limit_fields_are_rejected_at_parse_time() {
    for field in ["live_max_connections", "live_max_rows"] {
        let tmp = TempDir::new().expect("tempdir");
        let config_path = write_config(
            &tmp,
            &minimal_config(&format!(
                r#"
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    tables:
      - id: records_table
        materialization: snapshot
        source:
          type: postgres
          connection_env: SOCIAL_REGISTRY_DATABASE_URL
          table:
            schema: public
            name: records
          {field}: 1
        refresh:
          mode: manual
        schema:
          strict: false
          fields:
            - name: record_id
              type: string
    entities: []
"#
            )),
        );

        assert_config_code(config::load(&config_path), "config.parse_error");
    }
}

#[test]
fn postgres_mtime_requires_change_token_sql() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(
        &tmp,
        &minimal_config(
            r#"
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    tables:
      - id: records_table
        materialization: snapshot
        source:
          type: postgres
          connection_env: SOCIAL_REGISTRY_DATABASE_URL
          table:
            schema: public
            name: records
        refresh:
          mode: mtime
          interval: 5m
        schema:
          strict: false
          fields:
            - name: record_id
              type: string
    entities: []
"#,
        ),
    );

    assert_config_code(config::load(&config_path), "config.validation_error");
}

#[test]
fn reject_invalid_api_key_fingerprint() {
    env::set_var("TEST_KEY_HASH_BAD_FINGERPRINT", "not_a_fingerprint");
    let result = config::load(&fixture_path("invalid_api_key_fingerprint.yaml"));
    assert_config_code(result, "config.validation_error");
}

/// Sanity: the on-disk error rendered for `ConfigError` is one of the
/// expected variants. Decouples the test suite from the exact `Error`
/// variant shape.
#[test]
fn config_error_codes_are_stable() {
    let codes: Vec<&'static str> = vec![
        Error::Config(ConfigError::ParseError).code(),
        Error::Config(ConfigError::ValidationError).code(),
        Error::Config(ConfigError::MissingSecret).code(),
        Error::Config(ConfigError::DuplicateId).code(),
    ];
    assert_eq!(
        codes,
        vec![
            "config.parse_error",
            "config.validation_error",
            "config.missing_secret",
            "config.duplicate_id",
        ]
    );
}

/// Confirms the loader does not bubble the source path into the
/// rendered error string. The path information lives in `tracing`
/// logs only.
#[test]
fn loader_does_not_leak_path_in_error_message() {
    let bogus = Path::new("/no/such/file/registry_relay_unit_test.yaml");
    let result = config::load(bogus);
    let msg = match result {
        Err(e) => e.detail(),
        Ok(_) => panic!("expected load of missing file to fail"),
    };
    let bogus_path = bogus.to_string_lossy();
    let bogus_path: &str = bogus_path.as_ref();
    assert!(!msg.contains(bogus_path), "msg: {msg}");
}

#[test]
fn update_frequency_termly_deserializes() {
    // Verify that the YAML value "termly" parses to UpdateFrequency::Termly.
    let freq: UpdateFrequency =
        serde_saphyr::from_str("termly").expect("termly parses to UpdateFrequency");
    assert_eq!(freq, UpdateFrequency::Termly);
}

#[test]
fn update_frequency_termly_accepted_in_dataset_config() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("termly.yaml");
    std::fs::write(
        &config_path,
        r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
deployment:
  profile: local
vocabularies: {}
auth:
  mode: api_key
  api_keys: []
datasets:
  - id: education_registry
    title: Education Registry
    description: Termly dataset
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: termly
    defaults:
      refresh:
        mode: manual
    tables: []
    entities: []
audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("write config");
    let config = config::load(&config_path).expect("config loads");
    assert!(matches!(
        config.datasets[0].update_frequency,
        UpdateFrequency::Termly
    ));
}

#[test]
fn update_frequency_as_needed_deserializes() {
    // Verify that the YAML value "as_needed" parses to UpdateFrequency::AsNeeded.
    let freq: UpdateFrequency =
        serde_saphyr::from_str("as_needed").expect("as_needed parses to UpdateFrequency");
    assert_eq!(freq, UpdateFrequency::AsNeeded);
}

#[test]
fn update_frequency_as_needed_accepted_in_dataset_config() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("as_needed.yaml");
    std::fs::write(
        &config_path,
        r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
deployment:
  profile: local
vocabularies: {}
auth:
  mode: api_key
  api_keys: []
datasets:
  - id: subject_registry
    title: Subject Registry
    description: Event-driven dataset
    owner: Test
    sensitivity: confidential
    access_rights: restricted
    update_frequency: as_needed
    defaults:
      refresh:
        mode: manual
    tables: []
    entities: []
audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("write config");
    let config = config::load(&config_path).expect("config loads");
    assert!(matches!(
        config.datasets[0].update_frequency,
        UpdateFrequency::AsNeeded
    ));
}

// ---------------------------------------------------------------------
// OIDC config surface (Stage 2). The provider implementation lands in
// a later stage; here we only assert YAML parsing and cross-field
// validation behaviour.
// ---------------------------------------------------------------------

fn oidc_config_body(extra_oidc: &str) -> String {
    format!(
        r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
deployment:
  profile: local
vocabularies: {{}}
auth:
  mode: oidc
  oidc:
    issuer: https://idp.example.test/realms/relay
    audiences:
      - registry-relay
    jwks_url: https://idp.example.test/realms/relay/protocol/openid-connect/certs
{extra_oidc}
datasets: []
audit:
  sink: stdout
  format: jsonl
"#
    )
}

#[test]
fn shared_canonical_oidc_fixture_parses() {
    let tmp = TempDir::new().expect("tempdir");
    let body = r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
deployment:
  profile: local
vocabularies: {}
auth:
  mode: oidc
  oidc:
    issuer: https://id.example.gov
    audiences:
      - registry-notary
    jwks_url: https://id.example.gov/oauth/v2/keys
    allowed_algorithms:
      - EdDSA
    allowed_token_types:
      - JWT
    leeway: 30s
datasets: []
audit:
  sink: stdout
  format: jsonl
"#;
    let path = write_config(&tmp, body);

    let config = config::load(&path).expect("shared canonical OIDC fixture loads");
    let oidc = config.auth.oidc.as_ref().expect("oidc config");

    assert_eq!(oidc.issuer, "https://id.example.gov");
    assert_eq!(oidc.audiences, vec!["registry-notary"]);
    assert_eq!(
        oidc.jwks_url.as_deref(),
        Some("https://id.example.gov/oauth/v2/keys")
    );
    assert_eq!(oidc.allowed_algorithms, vec![OidcAlgorithm::EdDsa]);
    assert_eq!(oidc.allowed_token_types, vec!["JWT"]);
    assert_eq!(oidc.leeway, Duration::from_secs(30));
}

#[test]
fn config_loader_expands_env_expressions_before_deserialization() {
    let tmp = TempDir::new().expect("tempdir");
    let env_name = "REGISTRY_RELAY_TEST_OIDC_ISSUER_URL";
    env::set_var(env_name, "https://idp.example.test/realms/relay");
    let body = oidc_config_body("").replace(
        "issuer: https://idp.example.test/realms/relay",
        "issuer: ${REGISTRY_RELAY_TEST_OIDC_ISSUER_URL:?issuer required}",
    );
    let path = write_config(&tmp, &body);

    let config = config::load(&path).expect("expanded config loads");
    assert_eq!(
        config.auth.oidc.as_ref().expect("oidc config").issuer,
        "https://idp.example.test/realms/relay"
    );
    env::remove_var(env_name);
}

#[test]
fn config_loader_rejects_deprecated_oidc_field_names() {
    for (old, replacement) in [
        (
            "audiences:\n      - registry-relay",
            "audience:\n      - registry-relay",
        ),
        (
            "allowed_algorithms:\n      - RS256",
            "algorithms:\n      - RS256",
        ),
        (
            "allowed_token_types:\n      - at+jwt",
            "token_types:\n      - at+jwt",
        ),
    ] {
        let tmp = TempDir::new().expect("tempdir");
        let body = oidc_config_body(&format!("    {old}\n")).replace(old, replacement);
        let path = write_config(&tmp, &body);

        assert_config_code(config::load(&path), "config.parse_error");
    }
}

#[test]
fn oidc_config_loads_with_defaults() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_config(&tmp, &oidc_config_body(""));
    let config = config::load(&path).expect("oidc config must load");

    assert_eq!(config.auth.mode, AuthMode::Oidc);
    assert!(config.auth.api_keys.is_empty());
    let oidc = config.auth.oidc.as_ref().expect("oidc config present");
    assert_eq!(oidc.issuer, "https://idp.example.test/realms/relay");
    assert_eq!(oidc.audiences, vec!["registry-relay".to_string()]);
    assert_eq!(
        oidc.jwks_url.as_deref(),
        Some("https://idp.example.test/realms/relay/protocol/openid-connect/certs")
    );
    assert!(oidc.discovery_url.is_none());
    assert_eq!(
        oidc.allowed_algorithms,
        vec![
            OidcAlgorithm::Rs256,
            OidcAlgorithm::Es256,
            OidcAlgorithm::EdDsa,
        ]
    );
    assert_eq!(oidc.jwks_cache_ttl.as_secs(), 600);
    assert_eq!(oidc.leeway.as_secs(), 60);
    assert_eq!(oidc.scope_claim, "scope");
    assert!(oidc.scope_map.is_empty());
    assert!(oidc.scope_object_required_keys.is_empty());
    assert!(oidc.allowed_clients.is_empty());
    assert_eq!(
        oidc.allowed_token_types,
        vec!["JWT".to_string(), "at+jwt".to_string()]
    );
}

#[test]
fn oidc_config_accepts_overrides() {
    let tmp = TempDir::new().expect("tempdir");
    let extra = r#"    allowed_algorithms:
      - RS256
      - EdDSA
    jwks_cache_ttl: 5m
    leeway: 90s
    scope_claim: scp
    scope_map:
      role/registry-reader: clinic_capacity:rows
    scope_object_required_keys:
      - orgId-123
    allowed_clients:
      - openspp-client
    allowed_token_types:
      - at+jwt
"#;
    let path = write_config(&tmp, &oidc_config_body(extra));
    let config = config::load(&path).expect("oidc override config must load");

    let oidc = config.auth.oidc.as_ref().expect("oidc present");
    assert_eq!(
        oidc.allowed_algorithms,
        vec![OidcAlgorithm::Rs256, OidcAlgorithm::EdDsa]
    );
    assert_eq!(oidc.jwks_cache_ttl.as_secs(), 300);
    assert_eq!(oidc.leeway.as_secs(), 90);
    assert_eq!(oidc.scope_claim, "scp");
    assert_eq!(
        oidc.scope_map
            .get("role/registry-reader")
            .map(String::as_str),
        Some("clinic_capacity:rows")
    );
    assert_eq!(
        oidc.scope_object_required_keys,
        vec!["orgId-123".to_string()]
    );
    assert_eq!(oidc.allowed_clients, vec!["openspp-client".to_string()]);
    assert_eq!(oidc.allowed_token_types, vec!["at+jwt".to_string()]);
}

#[test]
fn oidc_config_with_discovery_url_loads() {
    let tmp = TempDir::new().expect("tempdir");
    let body = r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
deployment:
  profile: local
vocabularies: {}
auth:
  mode: oidc
  oidc:
    issuer: https://idp.example.test
    audiences:
      - registry-relay
    discovery_url: https://idp.example.test/.well-known/openid-configuration
datasets: []
audit:
  sink: stdout
  format: jsonl
"#;
    let path = write_config(&tmp, body);
    let config = config::load(&path).expect("discovery config must load");
    let oidc = config.auth.oidc.as_ref().expect("oidc present");
    assert!(oidc.jwks_url.is_none());
    assert_eq!(
        oidc.discovery_url.as_deref(),
        Some("https://idp.example.test/.well-known/openid-configuration")
    );
}

#[test]
fn example_oidc_config_loads_and_validates() {
    let config = config::load(&example_oidc_path()).expect("oidc example config must load");

    assert_eq!(config.auth.mode, AuthMode::Oidc);
    assert!(config.auth.api_keys.is_empty());

    let oidc = config.auth.oidc.as_ref().expect("oidc block present");
    assert_eq!(oidc.issuer, "http://localhost:8080");
    assert_eq!(oidc.audiences, vec!["registry-relay".to_string()]);
    assert!(oidc.jwks_url.is_none());
    assert_eq!(
        oidc.discovery_url.as_deref(),
        Some("http://localhost:8080/.well-known/openid-configuration")
    );
    assert_eq!(oidc.allowed_algorithms, vec![OidcAlgorithm::Rs256]);
    assert_eq!(oidc.jwks_cache_ttl.as_secs(), 600);
    assert_eq!(oidc.leeway.as_secs(), 60);
    assert_eq!(oidc.scope_claim, "urn:zitadel:iam:org:project:roles");
    assert_eq!(
        oidc.scope_map
            .get("social-registry-reader")
            .map(String::as_str),
        Some("social_registry:rows"),
    );
    assert_eq!(
        oidc.scope_map
            .get("social-registry-aggregate")
            .map(String::as_str),
        Some("social_registry:aggregate"),
    );
    assert_eq!(
        oidc.scope_object_required_keys,
        vec!["orgId-123".to_string()]
    );
    assert_eq!(oidc.allowed_clients, vec!["publicschema-api".to_string()]);
    assert_eq!(
        oidc.allowed_token_types,
        vec!["JWT".to_string(), "at+jwt".to_string()]
    );
}

#[test]
fn oidc_config_rejects_unknown_algorithm() {
    let tmp = TempDir::new().expect("tempdir");
    let extra = "    allowed_algorithms:\n      - HS256\n";
    let path = write_config(&tmp, &oidc_config_body(extra));
    // Unknown enum variant fails at deserialize time, not validation.
    assert_config_code(config::load(&path), "config.parse_error");
}

#[test]
fn oidc_mode_rejects_api_keys_present() {
    let tmp = TempDir::new().expect("tempdir");
    let body = r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
deployment:
  profile: local
vocabularies: {}
auth:
  mode: oidc
  api_keys:
    - id: leftover
      fingerprint:
        provider: env
        name: SHOULD_NOT_BE_READ
      scopes: []
  oidc:
    issuer: https://idp.example.test
    audiences: [registry-relay]
    jwks_url: https://idp.example.test/jwks
datasets: []
audit:
  sink: stdout
  format: jsonl
"#;
    let path = write_config(&tmp, body);
    assert_config_code(config::load(&path), "config.validation_error");
}

#[test]
fn oidc_mode_requires_oidc_block() {
    let tmp = TempDir::new().expect("tempdir");
    let body = r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
deployment:
  profile: local
vocabularies: {}
auth:
  mode: oidc
datasets: []
audit:
  sink: stdout
  format: jsonl
"#;
    let path = write_config(&tmp, body);
    assert_config_code(config::load(&path), "config.validation_error");
}

#[test]
fn api_key_mode_rejects_oidc_block() {
    let tmp = TempDir::new().expect("tempdir");
    let body = r#"
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
  oidc:
    issuer: https://idp.example.test
    audiences: [registry-relay]
    jwks_url: https://idp.example.test/jwks
datasets: []
audit:
  sink: stdout
  format: jsonl
"#;
    let path = write_config(&tmp, body);
    assert_config_code(config::load(&path), "config.validation_error");
}

#[test]
fn oidc_config_rejects_both_jwks_and_discovery_urls() {
    let tmp = TempDir::new().expect("tempdir");
    let body = r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
vocabularies: {}
auth:
  mode: oidc
  oidc:
    issuer: https://idp.example.test
    audiences: [registry-relay]
    jwks_url: https://idp.example.test/jwks
    discovery_url: https://idp.example.test/.well-known/openid-configuration
datasets: []
audit:
  sink: stdout
  format: jsonl
"#;
    let path = write_config(&tmp, body);
    assert_config_code(config::load(&path), "config.validation_error");
}

#[test]
fn oidc_config_rejects_missing_jwks_and_discovery_urls() {
    let tmp = TempDir::new().expect("tempdir");
    let body = r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
vocabularies: {}
auth:
  mode: oidc
  oidc:
    issuer: https://idp.example.test
    audiences: [registry-relay]
datasets: []
audit:
  sink: stdout
  format: jsonl
"#;
    let path = write_config(&tmp, body);
    assert_config_code(config::load(&path), "config.validation_error");
}

#[test]
fn oidc_config_rejects_http_issuer() {
    let tmp = TempDir::new().expect("tempdir");
    let body = r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
vocabularies: {}
auth:
  mode: oidc
  oidc:
    issuer: http://idp.example.test
    audiences: [registry-relay]
    jwks_url: https://idp.example.test/jwks
datasets: []
audit:
  sink: stdout
  format: jsonl
"#;
    let path = write_config(&tmp, body);
    assert_config_code(config::load(&path), "config.validation_error");
}

#[test]
fn oidc_config_rejects_localhost_http_without_dev_opt_in() {
    let tmp = TempDir::new().expect("tempdir");
    let body = r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
vocabularies: {}
auth:
  mode: oidc
  oidc:
    issuer: http://localhost:8080/realms/relay
    audiences: [registry-relay]
    jwks_url: http://localhost:8080/realms/relay/protocol/openid-connect/certs
datasets: []
audit:
  sink: stdout
  format: jsonl
	"#;
    let path = write_config(&tmp, body);
    assert_config_code(config::load(&path), "config.validation_error");
}

#[test]
fn oidc_config_allows_localhost_http_with_dev_opt_in() {
    let tmp = TempDir::new().expect("tempdir");
    let body = r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
deployment:
  profile: local
vocabularies: {}
auth:
  mode: oidc
  oidc:
    issuer: http://localhost:8080/realms/relay
    audiences: [registry-relay]
    jwks_url: http://localhost:8080/realms/relay/protocol/openid-connect/certs
    allow_dev_insecure_fetch_urls: true
datasets: []
audit:
  sink: stdout
  format: jsonl
"#;
    let path = write_config(&tmp, body);
    let config = config::load(&path).expect("localhost dev config must load");
    let oidc = config.auth.oidc.as_ref().expect("oidc present");
    assert!(oidc.issuer.starts_with("http://localhost"));
    assert!(oidc.allow_dev_insecure_fetch_urls);
}

#[test]
fn oidc_config_rejects_empty_audience() {
    let tmp = TempDir::new().expect("tempdir");
    let extra = "    # override audience\n";
    let body =
        oidc_config_body(extra).replace("audiences:\n      - registry-relay", "audiences: []");
    let path = write_config(&tmp, &body);
    assert_config_code(config::load(&path), "config.validation_error");
}

#[test]
fn oidc_config_rejects_leeway_above_5_minutes() {
    let tmp = TempDir::new().expect("tempdir");
    let extra = "    leeway: 6m\n";
    let path = write_config(&tmp, &oidc_config_body(extra));
    assert_config_code(config::load(&path), "config.validation_error");
}

#[test]
fn oidc_config_rejects_jwks_cache_ttl_out_of_range() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_config(&tmp, &oidc_config_body("    jwks_cache_ttl: 5s\n"));
    assert_config_code(config::load(&path), "config.validation_error");

    let tmp2 = TempDir::new().expect("tempdir");
    let path2 = write_config(&tmp2, &oidc_config_body("    jwks_cache_ttl: 48h\n"));
    assert_config_code(config::load(&path2), "config.validation_error");
}

#[test]
fn oidc_config_rejects_scope_claim_with_whitespace() {
    let tmp = TempDir::new().expect("tempdir");
    let extra = "    scope_claim: \"my scope\"\n";
    let path = write_config(&tmp, &oidc_config_body(extra));
    assert_config_code(config::load(&path), "config.validation_error");
}

#[test]
fn oidc_config_rejects_audience_as_scope_claim() {
    let tmp = TempDir::new().expect("tempdir");
    let extra = "    scope_claim: aud\n";
    let path = write_config(&tmp, &oidc_config_body(extra));
    assert_config_code(config::load(&path), "config.validation_error");
}

#[test]
fn oidc_config_rejects_empty_scope_object_required_key() {
    let tmp = TempDir::new().expect("tempdir");
    let extra = "    scope_object_required_keys:\n      - \"\"\n";
    let path = write_config(&tmp, &oidc_config_body(extra));
    assert_config_code(config::load(&path), "config.validation_error");
}

#[test]
fn oidc_config_rejects_zitadel_object_claim_without_required_keys() {
    let tmp = TempDir::new().expect("tempdir");
    let extra = "    scope_claim: \"urn:zitadel:iam:org:project:roles\"\n";
    let path = write_config(&tmp, &oidc_config_body(extra));
    assert_config_code(config::load(&path), "config.validation_error");
}
