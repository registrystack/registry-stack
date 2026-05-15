// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the config loader.
//!
//! These tests cover Wave 0 Track 2 exit criteria from
//! `decisions/wave-0.md` Section 6: parse the canonical example
//! verbatim, surface cross-field validation errors with stable
//! `config.*` codes, and round-trip the prefix expansion helper.
//!
//! Env vars are scoped per-fixture (each test uses unique names) so
//! the suite can run with the default test runner without forcing
//! `--test-threads=1`.

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::Argon2;
use data_gate::config::vocabularies;
use data_gate::config::{
    self, AccessRights, AggregateFunction, AuditFormat, AuditSinkConfig, AuthMode, FieldType,
    FilterOp, RefreshConfig, Sensitivity, SourceConfig, Suppression, UpdateFrequency,
};
use data_gate::error::{ConfigError, Error};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Build a valid Argon2id PHC string. Reused by tests that need a
/// `hash_env` env var value the validator will accept. We avoid
/// `OsRng` here because the test binary does not enable the
/// `getrandom` feature on `rand_core`; a per-process monotonic
/// counter is more than sufficient for fixture salt uniqueness.
fn make_phc(plaintext: &[u8]) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    // 16 bytes of salt entropy: 8 from nanos, 8 from nonce. Encoded
    // to PHC's b64 (no padding) via SaltString::encode_b64.
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&nanos.to_le_bytes());
    bytes[8..].copy_from_slice(&nonce.to_le_bytes());
    let salt = SaltString::encode_b64(&bytes).expect("encode salt");

    let argon2 = Argon2::default();
    argon2
        .hash_password(plaintext, &salt)
        .expect("argon2 hash")
        .to_string()
}

/// Path to the canonical example shipped alongside the crate.
fn example_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/example.yaml")
}

/// Path to a fixture under `tests/fixtures/config/<name>`.
fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config")
        .join(name)
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
    // Both keys in the example point at env vars; provide valid PHCs.
    let key_a = make_phc(b"statistics-office-secret");
    let key_b = make_phc(b"program-system-secret");

    // Safe to set: env name is unique to the example.
    env::set_var("STATS_OFFICE_API_KEY_HASH", key_a);
    env::set_var("PROGRAM_SYSTEM_API_KEY_HASH", key_b);

    let config = config::load(&example_path()).expect("example config must load");

    assert_eq!(config.server.bind.to_string(), "0.0.0.0:8080");

    assert_eq!(config.catalog.title, "Internal Government Data Gateway");
    assert_eq!(config.catalog.base_url, "https://data.example.gov");
    assert_eq!(config.catalog.publisher, "Ministry of Digital Government");

    assert!(matches!(config.auth.mode, AuthMode::ApiKey));
    assert_eq!(config.auth.api_keys.len(), 2);
    assert_eq!(config.auth.api_keys[0].id, "statistics_office");
    assert_eq!(
        config.auth.api_keys[0].hash_env,
        "STATS_OFFICE_API_KEY_HASH"
    );

    assert_eq!(config.datasets.len(), 1);
    let dataset = &config.datasets[0];
    assert_eq!(dataset.id.as_ref(), "social_registry");
    assert_eq!(dataset.title, "Social Registry");
    assert!(matches!(dataset.sensitivity, Sensitivity::Personal));
    assert!(matches!(dataset.access_rights, AccessRights::Restricted));
    assert!(matches!(dataset.update_frequency, UpdateFrequency::Monthly));
    assert_eq!(dataset.conforms_to.len(), 3);

    match &dataset.source {
        SourceConfig::File {
            path,
            header_row,
            data_range,
        } => {
            assert_eq!(path.to_string_lossy(), "./data/social_registry.xlsx");
            assert_eq!(*header_row, Some(1));
            assert_eq!(data_range.as_deref(), Some("A2:E100000"));
        }
        other => panic!("expected source type file, got {other:?}"),
    }

    match &dataset.refresh {
        RefreshConfig::Mtime { interval } => {
            assert_eq!(interval.as_secs(), 3600);
        }
        other => panic!("expected refresh mode mtime, got {other:?}"),
    }

    assert_eq!(dataset.resources.len(), 1);
    let resource = &dataset.resources[0];
    assert_eq!(resource.id.as_ref(), "beneficiaries");
    assert_eq!(resource.sheet.as_deref(), Some("Beneficiaries"));
    assert_eq!(resource.primary_key.as_deref(), Some("beneficiary_id"));
    assert!(resource.schema.strict);
    assert_eq!(resource.schema.fields.len(), 5);

    let payment = resource
        .schema
        .fields
        .iter()
        .find(|f| f.name == "payment_amount")
        .expect("payment_amount field present");
    assert!(matches!(payment.r#type, FieldType::Number));
    assert_eq!(
        payment.concept_uri.as_deref(),
        Some("psc:properties/paymentAmount")
    );
    assert_eq!(payment.unit.as_deref(), Some("EUR"));

    assert_eq!(resource.api.default_limit, 100);
    assert_eq!(resource.api.max_limit, 1000);
    assert!(resource.api.require_purpose_header);
    assert_eq!(resource.api.allowed_filters.len(), 4);
    let date_filter = resource
        .api
        .allowed_filters
        .iter()
        .find(|f| f.field == "enrollment_date")
        .expect("enrollment_date filter present");
    assert!(date_filter.ops.contains(&FilterOp::Between));

    assert_eq!(resource.aggregates.len(), 2);
    let pay_agg = &resource.aggregates[1];
    assert_eq!(pay_agg.id.as_ref(), "payments_by_municipality");
    assert_eq!(pay_agg.measures.len(), 2);
    assert!(matches!(
        pay_agg.measures[0].function,
        AggregateFunction::Sum
    ));
    assert!(matches!(
        pay_agg.measures[1].function,
        AggregateFunction::Avg
    ));
    assert_eq!(pay_agg.disclosure_control.min_group_size, 5);
    assert!(matches!(
        pay_agg.disclosure_control.suppression,
        Suppression::Mask
    ));

    assert!(matches!(config.audit.sink, AuditSinkConfig::Stdout {}));
    assert!(matches!(config.audit.format, AuditFormat::Jsonl));

    // CORS is default-deny: empty allowlist.
    assert!(config.server.cors.allowed_origins.is_empty());

    // request_timeout defaults to 30s.
    assert_eq!(config.server.request_timeout.as_secs(), 30);
}

#[test]
fn unknown_field_rejected() {
    let result = config::load(&fixture_path("unknown_field.yaml"));
    assert_config_code(result, "config.parse_error");
}

#[test]
fn invalid_scope_rejected() {
    env::set_var("TEST_KEY_HASH_SCOPE", make_phc(b"scope-test"));
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
    env::set_var("TEST_KEY_HASH_DUP", make_phc(b"dup-test"));
    let result = config::load(&fixture_path("duplicate_dataset_id.yaml"));
    assert_config_code(result, "config.duplicate_id");
}

#[test]
fn unknown_vocabulary_prefix_rejected() {
    env::set_var("TEST_KEY_HASH_VOCAB", make_phc(b"vocab-test"));
    let result = config::load(&fixture_path("unknown_vocab_prefix.yaml"));
    assert_config_code(result, "config.validation_error");
}

#[test]
fn allowed_filter_unknown_field_rejected() {
    env::set_var("TEST_KEY_HASH_FILTER", make_phc(b"filter-test"));
    let result = config::load(&fixture_path("allowed_filter_unknown_field.yaml"));
    assert_config_code(result, "config.validation_error");
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
    env::set_var("TEST_KEY_HASH_INTERVAL", make_phc(b"interval-test"));
    let config = config::load(&fixture_path("interval_refresh.yaml"))
        .expect("interval_refresh fixture must load");
    let refresh = &config.datasets[0].refresh;
    match refresh {
        RefreshConfig::Interval { interval } => {
            assert_eq!(interval.as_secs(), 3600);
        }
        other => panic!("expected interval refresh, got {other:?}"),
    }
}

#[test]
fn reject_invalid_argon_phc() {
    env::set_var("TEST_KEY_HASH_BADPHC", "not_an_argon_phc");
    let result = config::load(&fixture_path("invalid_argon_phc.yaml"));
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
    let bogus = Path::new("/no/such/file/data_gate_unit_test.yaml");
    let result = config::load(bogus);
    let msg = match result {
        Err(e) => e.detail(),
        Ok(_) => panic!("expected load of missing file to fail"),
    };
    assert!(
        !msg.contains(bogus.to_string_lossy().as_ref()),
        "msg: {msg}"
    );
}
