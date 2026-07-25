// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use jsonschema::{Draft, JSONSchema};
use registry_platform_audit::{AuditChainProfile, AuditError};
use registry_relay::config::schema::{document, document_json, CONFIG_SCHEMA_ID};
use registry_relay::config::Config;
use serde_json::{json, Value};

const SCHEMA_ARTIFACT: &str = "../../schemas/registry-relay.config.schema.json";
const CONFIG_REFERENCE: &str = "docs/configuration.md";
const KEY_PATHS_START: &str = "{/* registry-relay-config-key-paths:start */}";
const KEY_PATHS_END: &str = "{/* registry-relay-config-key-paths:end */}";
const NON_PORTABLE_ENVIRONMENT_NAME: &str = "REGISTRY.RELAY-SCHEMA-RUNTIME-KEY";
const NON_PORTABLE_ENVIRONMENT_VALUE: &str = "0123456789abcdef0123456789abcdef";
const NON_PORTABLE_ENVIRONMENT_CHILD: &str = "REGISTRY_RELAY_SCHEMA_ENV_CHILD";
const WHITESPACE_AUDIT_ENVIRONMENT_CHILD: &str = "REGISTRY_RELAY_SCHEMA_WHITESPACE_AUDIT_ENV_CHILD";
const UNICODE_AUDIT_ENVIRONMENT_CHILD: &str = "REGISTRY_RELAY_SCHEMA_UNICODE_AUDIT_ENV_CHILD";
const NEXT_LINE: &str = "\u{0085}";
const ZERO_WIDTH_NO_BREAK_SPACE: &str = "\u{feff}";

fn relay_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn parse_yaml(path: &Path) -> Value {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_norway::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {} as YAML: {error}", path.display()))
}

fn compile_schema(schema: &Value) -> JSONSchema {
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(schema)
        .unwrap_or_else(|error| panic!("Relay schema must compile as Draft 2020-12: {error}"))
}

fn assert_valid(schema: &Value, instance: &Value, label: &str) {
    let compiled = compile_schema(schema);
    if let Err(errors) = compiled.validate(instance) {
        let details = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("{label} must validate against the Relay schema: {details:#?}");
    };
}

fn assert_invalid(schema: &Value, instance: &Value, label: &str) {
    assert!(
        !compile_schema(schema).is_valid(instance),
        "{label} must be rejected by the Relay schema"
    );
}

fn assert_runtime_deserializes(instance: &Value, label: &str) {
    let yaml = serde_norway::to_string(instance)
        .unwrap_or_else(|error| panic!("failed to serialize {label} as YAML: {error}"));
    serde_norway::from_str::<Config>(&yaml)
        .unwrap_or_else(|error| panic!("{label} must deserialize at runtime: {error}"));
}

fn assert_runtime_rejects(instance: &Value, label: &str) {
    let yaml = serde_norway::to_string(instance)
        .unwrap_or_else(|error| panic!("failed to serialize {label} as YAML: {error}"));
    assert!(
        serde_norway::from_str::<Config>(&yaml).is_err(),
        "{label} must be rejected during runtime deserialization"
    );
}

fn example_config() -> Value {
    parse_yaml(&relay_root().join("config/example.yaml"))
}

fn oidc_config() -> Value {
    parse_yaml(&relay_root().join("config/example.oidc.yaml"))
}

fn consultation_config() -> Value {
    parse_yaml(
        &relay_root().join("profiles/dhis2-2.41.9-enrollment-status/relay-config.example.yaml"),
    )
}

fn postgres_config() -> Value {
    let mut config = example_config();
    config["datasets"][0]["tables"][0]["source"] = json!({
        "type": "postgres",
        "connection_env": "DATABASE_URL",
        "table": {
            "schema": "public",
            "name": "individuals"
        },
        "connect_timeout": "5s",
        "query_timeout": "30s"
    });
    config
}

fn refresh_config(mode: &str) -> Value {
    let mut config = example_config();
    config["datasets"][0]["tables"][0]["refresh"] = json!({
        "mode": mode,
        "interval": "1h"
    });
    config
}

fn set_pointer(instance: &mut Value, pointer: &str, value: Value) {
    if let Some(slot) = instance.pointer_mut(pointer) {
        *slot = value;
        return;
    }
    let (parent, name) = pointer
        .rsplit_once('/')
        .unwrap_or_else(|| panic!("invalid test config pointer {pointer}"));
    instance
        .pointer_mut(parent)
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("missing test config pointer parent {parent}"))
        .insert(name.to_string(), value);
}

fn maintained_runtime_fixtures() -> Vec<PathBuf> {
    let root = relay_root();
    let mut fixtures = vec![
        root.join("config/example.yaml"),
        root.join("config/example.oidc.yaml"),
        root.join("config/spdci_disability_registry.example.yaml"),
        root.join("perf/config/small.yaml"),
        root.join("perf/config/medium.yaml"),
        root.join("perf/config/large.yaml"),
    ];

    for entry in fs::read_dir(root.join("demo/config")).expect("demo config directory exists") {
        let path = entry.expect("demo config entry is readable").path();
        if path.extension().and_then(|value| value.to_str()) == Some("yaml")
            && !path
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.ends_with(".metadata.yaml"))
        {
            fixtures.push(path);
        }
    }

    for entry in fs::read_dir(root.join("profiles")).expect("profiles directory exists") {
        let path = entry
            .expect("profile directory entry is readable")
            .path()
            .join("relay-config.example.yaml");
        if path.is_file() {
            fixtures.push(path);
        }
    }

    fixtures.sort();
    fixtures
}

#[test]
fn generated_schema_is_draft_2020_12_with_stable_id_and_no_byte_drift() {
    let generated = document();
    compile_schema(&generated);
    assert_eq!(
        generated["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(generated["$id"], CONFIG_SCHEMA_ID);

    let artifact = fs::read_to_string(relay_root().join(SCHEMA_ARTIFACT))
        .expect("committed Relay schema exists");
    assert_eq!(artifact, document_json());
    assert!(artifact.ends_with('\n'));
    assert!(!artifact.ends_with("\n\n"));
}

#[test]
fn schema_command_is_exactly_the_committed_artifact() {
    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .args(["schema", "--format", "json"])
        .output()
        .expect("schema command runs");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout,
        fs::read(relay_root().join(SCHEMA_ARTIFACT)).expect("committed Relay schema exists")
    );
}

#[test]
fn maintained_runtime_config_fixtures_validate() {
    let schema = document();
    let fixtures = maintained_runtime_fixtures();
    assert!(
        fixtures.len() >= 15,
        "fixture discovery unexpectedly narrowed"
    );
    for fixture in fixtures {
        assert_valid(
            &schema,
            &parse_yaml(&fixture),
            &fixture.display().to_string(),
        );
    }
}

#[test]
fn optional_consultation_and_empty_datasets_are_structurally_valid() {
    let schema = document();
    let mut config = example_config();
    config.as_object_mut().unwrap().remove("consultation");
    config["datasets"] = json!([]);
    assert_valid(
        &schema,
        &config,
        "config without consultation and with no datasets",
    );
}

#[test]
fn strict_nested_objects_tagged_variants_and_duration_shapes_are_enforced() {
    let schema = document();

    let mut unknown_server_key = example_config();
    unknown_server_key["server"]["not_a_relay_setting"] = json!(true);
    assert_invalid(&schema, &unknown_server_key, "unknown nested server field");

    let mut unknown_audit_key = example_config();
    unknown_audit_key["audit"]["not_a_relay_setting"] = json!(true);
    assert_invalid(&schema, &unknown_audit_key, "unknown flattened audit field");

    let mut bad_source_tag = example_config();
    bad_source_tag["datasets"][0]["tables"][0]["source"] = json!({"type": "s3"});
    assert_invalid(&schema, &bad_source_tag, "unknown source tag");

    let mut mixed_source_variant = example_config();
    mixed_source_variant["datasets"][0]["tables"][0]["source"] = json!({
        "type": "file",
        "path": "records.csv",
        "connection_env": "DATABASE_URL"
    });
    assert_invalid(&schema, &mixed_source_variant, "mixed source variants");

    let mut duration_object = example_config();
    duration_object["server"]["request_timeout"] = json!({"secs": 30, "nanos": 0});
    assert_invalid(&schema, &duration_object, "object-form duration");
}

#[test]
fn socket_addresses_match_schema_and_runtime_portable_syntax() {
    let schema = document();
    let mut ipv4 = example_config();
    ipv4["server"]["bind"] = json!("127.0.0.1:0");
    ipv4["server"]["admin_bind"] = json!("192.0.2.10:65535");
    assert_valid(&schema, &ipv4, "maintained IPv4 listener forms");
    assert_runtime_deserializes(&ipv4, "maintained IPv4 listener forms");

    let mut ipv6 = example_config();
    ipv6["server"]["bind"] = json!("[::1]:8080");
    ipv6["server"]["admin_bind"] = json!("[2001:db8::1]:8443");
    assert_valid(&schema, &ipv6, "bracketed IPv6 listener forms");
    assert_runtime_deserializes(&ipv6, "bracketed IPv6 listener forms");

    let malformed = [
        "not-a-socket",
        "127.0.0.1",
        "::1:8080",
        "256.0.0.1:8080",
        "127.0.0.1:65536",
        "127.0.0.1:08080",
        "[gggg::1]:8080",
        "[fe80::1%1]:8080",
        "[::ffff:192.0.2.1]:8080",
    ];
    for field in ["bind", "admin_bind"] {
        for value in malformed {
            let mut config = example_config();
            config["server"][field] = json!(value);
            let label = format!("malformed server.{field} value {value:?}");
            assert_invalid(&schema, &config, &label);
            assert_runtime_rejects(&config, &label);
        }
    }
}

fn duration_fields() -> Vec<(&'static str, Value, &'static str)> {
    vec![
        (
            "server.request_timeout",
            example_config(),
            "/server/request_timeout",
        ),
        (
            "server.request_body_timeout",
            example_config(),
            "/server/request_body_timeout",
        ),
        (
            "server.http1_header_read_timeout",
            example_config(),
            "/server/http1_header_read_timeout",
        ),
        (
            "auth.oidc.jwks_cache_ttl",
            oidc_config(),
            "/auth/oidc/jwks_cache_ttl",
        ),
        ("auth.oidc.leeway", oidc_config(), "/auth/oidc/leeway"),
        (
            "postgres.connect_timeout",
            postgres_config(),
            "/datasets/0/tables/0/source/connect_timeout",
        ),
        (
            "postgres.query_timeout",
            postgres_config(),
            "/datasets/0/tables/0/source/query_timeout",
        ),
        (
            "refresh.mtime.interval",
            refresh_config("mtime"),
            "/datasets/0/tables/0/refresh/interval",
        ),
        (
            "refresh.interval.interval",
            refresh_config("interval"),
            "/datasets/0/tables/0/refresh/interval",
        ),
    ]
}

#[test]
fn all_duration_fields_match_schema_and_runtime_portable_syntax() {
    let schema = document();
    let documented = [
        "30s", "10s", "2h 37m", "10m", "60s", "5s", "30s", "60s", "1h",
    ];
    for ((label, mut config, pointer), value) in duration_fields().into_iter().zip(documented) {
        set_pointer(&mut config, pointer, json!(value));
        assert_valid(&schema, &config, label);
        assert_runtime_deserializes(&config, label);
    }

    let malformed = ["not-a-duration", "30", "-1s", "1h30m", "1h  30m", "1.5s"];
    for (label, baseline, pointer) in duration_fields() {
        for value in malformed {
            let mut config = baseline.clone();
            set_pointer(&mut config, pointer, json!(value));
            let case = format!("malformed {label} value {value:?}");
            assert_invalid(&schema, &config, &case);
            assert_runtime_rejects(&config, &case);
        }
    }
}

fn has_schema_type(object: &serde_json::Map<String, Value>, expected: &str) -> bool {
    match object.get("type") {
        Some(Value::String(schema_type)) => schema_type == expected,
        Some(Value::Array(schema_types)) => schema_types
            .iter()
            .any(|schema_type| schema_type.as_str() == Some(expected)),
        _ => false,
    }
}

fn expected_integer_bounds(format: &str) -> Option<(Value, Value)> {
    match format {
        "int8" => Some((i8::MIN.into(), i8::MAX.into())),
        "int16" => Some((i16::MIN.into(), i16::MAX.into())),
        "int32" => Some((i32::MIN.into(), i32::MAX.into())),
        "int64" => Some((i64::MIN.into(), i64::MAX.into())),
        "int" => Some(((isize::MIN as i64).into(), (isize::MAX as i64).into())),
        "uint8" => Some((0.into(), u8::MAX.into())),
        "uint16" => Some((0.into(), u16::MAX.into())),
        "uint32" => Some((0.into(), u32::MAX.into())),
        "uint64" => Some((0.into(), u64::MAX.into())),
        "uint" => Some((0.into(), (usize::MAX as u64).into())),
        _ => None,
    }
}

fn collect_integer_formats(schema: &Value, formats: &mut Vec<(String, bool)>) {
    match schema {
        Value::Array(values) => {
            for value in values {
                collect_integer_formats(value, formats);
            }
        }
        Value::Object(object) => {
            if has_schema_type(object, "integer") {
                if let Some(format) = object.get("format").and_then(Value::as_str) {
                    let actual_minimum = object
                        .get("minimum")
                        .unwrap_or_else(|| panic!("{format} is missing minimum"))
                        .clone();
                    let actual_maximum = object
                        .get("maximum")
                        .unwrap_or_else(|| panic!("{format} is missing maximum"))
                        .clone();
                    let (expected_minimum, expected_maximum) = expected_integer_bounds(format)
                        .unwrap_or_else(|| panic!("unrecognized Rust integer format {format}"));
                    assert_eq!(actual_minimum, expected_minimum, "wrong {format} minimum");
                    assert_eq!(actual_maximum, expected_maximum, "wrong {format} maximum");
                    formats.push((format.to_string(), has_schema_type(object, "null")));
                }
            }
            for value in object.values() {
                collect_integer_formats(value, formats);
            }
        }
        _ => {}
    }
}

fn assert_runtime_rejects_adjacent_integer(
    mut instance: Value,
    pointer: &str,
    boundary: Value,
    adjacent_literal: &str,
    label: &str,
) {
    set_pointer(&mut instance, pointer, boundary.clone());
    let yaml = serde_norway::to_string(&instance)
        .unwrap_or_else(|error| panic!("failed to serialize {label}: {error}"));
    let field = pointer
        .rsplit('/')
        .next()
        .expect("field pointer has a name");
    let boundary = boundary.to_string();
    let needle = format!("{field}: {boundary}");
    assert!(
        yaml.contains(&needle),
        "missing boundary literal for {label}"
    );
    let yaml = yaml.replacen(&needle, &format!("{field}: {adjacent_literal}"), 1);
    assert!(
        serde_norway::from_str::<Config>(&yaml).is_err(),
        "{label} must be rejected during runtime deserialization"
    );
}

#[test]
fn rust_integer_formats_have_explicit_bounds_and_reject_adjacent_values() {
    let schema = document();
    let mut formats = Vec::new();
    collect_integer_formats(&schema, &mut formats);
    assert!(formats.iter().any(|(format, _)| format == "uint64"));
    assert!(formats.iter().any(|(format, _)| format == "int64"));
    assert!(formats
        .iter()
        .any(|(format, nullable)| format == "uint32" && *nullable));
    assert!(formats
        .iter()
        .any(|(format, nullable)| format == "int32" && *nullable));
    assert!(formats
        .iter()
        .any(|(format, nullable)| format == "uint64" && *nullable));
    assert_eq!(
        schema["$defs"]["ServerConfig"]["properties"]["xlsx_max_file_bytes"]["maximum"],
        json!(u64::MAX)
    );
    assert_eq!(
        schema["$defs"]["ConsultationStatePlaneConfig"]["properties"]["serving_fence_lock_key"]
            ["minimum"],
        json!(i64::MIN)
    );

    let mut below_u64 = example_config();
    below_u64["server"]["xlsx_max_file_bytes"] = json!(-1);
    assert_invalid(&schema, &below_u64, "u64 value one below zero");

    // serde_json::Value cannot represent the two adjacent out-of-range literals
    // exactly. The exact schema bounds above cover external JSON validators;
    // these textual YAML checks cover Relay's runtime deserializer.
    assert_runtime_rejects_adjacent_integer(
        example_config(),
        "/server/xlsx_max_file_bytes",
        json!(u64::MAX),
        "18446744073709551616",
        "u64 value one above maximum",
    );
    assert_runtime_rejects_adjacent_integer(
        consultation_config(),
        "/consultation/state_plane/serving_fence_lock_key",
        json!(i64::MIN),
        "-9223372036854775809",
        "i64 value one below minimum",
    );

    let mut above_i64 = consultation_config();
    above_i64["consultation"]["state_plane"]["serving_fence_lock_key"] =
        json!(9223372036854775808_u64);
    assert_invalid(&schema, &above_i64, "i64 value one above maximum");
}

#[test]
fn nullable_config_integers_enforce_rust_boundaries() {
    let schema = document();

    for value in [json!(0), json!(u32::MAX)] {
        let mut config = example_config();
        config["datasets"][0]["aggregates"][0]["indicators"][0]["decimals"] = value;
        assert_valid(&schema, &config, "aggregate decimals u32 boundary");
        assert_runtime_deserializes(&config, "aggregate decimals u32 boundary");
    }
    for value in [json!(-1), json!(u64::from(u32::MAX) + 1), json!(1.5)] {
        let mut config = example_config();
        config["datasets"][0]["aggregates"][0]["indicators"][0]["decimals"] = value;
        assert_invalid(&schema, &config, "aggregate decimals outside u32");
        assert_runtime_rejects(&config, "aggregate decimals outside u32");
    }

    for value in [json!(i32::MIN), json!(i32::MAX)] {
        let mut config = example_config();
        config["datasets"][0]["aggregates"][0]["indicators"][0]["unit_mult"] = value;
        assert_valid(&schema, &config, "aggregate unit_mult i32 boundary");
        assert_runtime_deserializes(&config, "aggregate unit_mult i32 boundary");
    }
    for value in [
        json!(i64::from(i32::MIN) - 1),
        json!(i64::from(i32::MAX) + 1),
    ] {
        let mut config = example_config();
        config["datasets"][0]["aggregates"][0]["indicators"][0]["unit_mult"] = value;
        assert_invalid(&schema, &config, "aggregate unit_mult outside i32");
        assert_runtime_rejects(&config, "aggregate unit_mult outside i32");
    }

    let mut audit_ack_max = example_config();
    audit_ack_max["deployment"]["evidence"] = json!({
        "audit_ack_cursor_path": "/tmp/registry-relay-audit-ack.json",
        "audit_ack_max_age_secs": u64::MAX
    });
    assert_valid(&schema, &audit_ack_max, "audit ack age u64 maximum");
    assert_runtime_deserializes(&audit_ack_max, "audit ack age u64 maximum");

    let mut audit_ack_negative = example_config();
    audit_ack_negative["deployment"]["evidence"] = json!({
        "audit_ack_cursor_path": "/tmp/registry-relay-audit-ack.json",
        "audit_ack_max_age_secs": -1
    });
    assert_invalid(&schema, &audit_ack_negative, "audit ack age below zero");
    assert_runtime_rejects(&audit_ack_negative, "audit ack age below zero");

    let mut audit_ack_boundary = example_config();
    audit_ack_boundary["deployment"]["evidence"] = json!({
        "audit_ack_cursor_path": "/tmp/registry-relay-audit-ack.json"
    });
    assert_runtime_rejects_adjacent_integer(
        audit_ack_boundary,
        "/deployment/evidence/audit_ack_max_age_secs",
        json!(u64::MAX),
        "18446744073709551616",
        "audit ack age one above u64 maximum",
    );
}

#[test]
fn constrained_identifiers_references_hashes_and_fingerprints_are_enforced() {
    let schema = document();

    let mut bad_dataset_id = example_config();
    bad_dataset_id["datasets"][0]["id"] = json!("Invalid-Dataset");
    assert_invalid(&schema, &bad_dataset_id, "malformed dataset id");

    let mut object_dataset_id = example_config();
    object_dataset_id["datasets"][0]["id"] = json!({"value": "dataset"});
    assert_invalid(
        &schema,
        &object_dataset_id,
        "object-form transparent dataset id",
    );

    let mut consultation = consultation_config();
    consultation["consultation"]["state_plane"]["database_url_env"] = json!("INVALID-ENV");
    assert_invalid(&schema, &consultation, "malformed environment reference");

    let mut consultation = consultation_config();
    consultation["consultation"]["audit_pseudonym_materials"][0]["key_id"] = json!("UPPER");
    assert_invalid(&schema, &consultation, "malformed pseudonym id");

    let mut consultation = consultation_config();
    consultation["consultation"]["source_credentials"][0]["ref"] = json!("Invalid Ref");
    assert_invalid(&schema, &consultation, "malformed credential reference");

    let mut consultation = consultation_config();
    consultation["consultation"]["source_credentials"][0]["type"] = json!("embedded_secret");
    assert_invalid(&schema, &consultation, "unknown source credential tag");

    let mut consultation = consultation_config();
    consultation["consultation"]["artifacts"]["public_contracts"][0]["sha256"] =
        json!("sha256:not-a-hash");
    assert_invalid(
        &schema,
        &consultation,
        "malformed SHA-256 artifact reference",
    );

    let mut consultation = consultation_config();
    consultation["consultation"]["artifacts"]["public_contracts"][0]["hash"] =
        json!("sha256:not-a-typed-hash");
    assert_invalid(&schema, &consultation, "malformed typed artifact hash");

    let fingerprint_cases = [
        json!({"provider": "env", "name": "FINGERPRINT", "commitment": "forbidden"}),
        json!({"provider": "env", "name": "FINGERPRINT", "path": "/tmp/fingerprint"}),
        json!({"provider": "env", "path": "/tmp/fingerprint"}),
        json!({"provider": "file", "path": "/tmp/fingerprint", "name": "FINGERPRINT"}),
        json!({"provider": "file", "name": "FINGERPRINT"}),
    ];
    for (index, fingerprint) in fingerprint_cases.into_iter().enumerate() {
        let mut config = example_config();
        config["auth"]["api_keys"][0]["fingerprint"] = fingerprint;
        assert_invalid(
            &schema,
            &config,
            &format!("invalid fingerprint shape {index}"),
        );
    }
}

#[test]
fn environment_reference_syntax_matches_each_runtime_consumer() {
    let schema = document();

    let mut os_valid_non_portable = example_config();
    os_valid_non_portable["auth"]["api_keys"][0]["fingerprint"]["name"] =
        json!(NON_PORTABLE_ENVIRONMENT_NAME);
    os_valid_non_portable["audit"]["hash_secret_env"] = json!("REGISTRY.RELAY-AUDIT-KEY");
    assert_valid(
        &schema,
        &os_valid_non_portable,
        "OS-valid non-portable environment references",
    );
    assert_runtime_deserializes(
        &os_valid_non_portable,
        "OS-valid non-portable environment references",
    );

    let mut long_postgres_name = postgres_config();
    long_postgres_name["datasets"][0]["tables"][0]["source"]["connection_env"] =
        json!(format!("A{}", "B".repeat(160)));
    assert_valid(
        &schema,
        &long_postgres_name,
        "Postgres environment name without an artificial 128-byte limit",
    );
    assert_runtime_deserializes(
        &long_postgres_name,
        "Postgres environment name without an artificial 128-byte limit",
    );

    let mut whitespace_fingerprint = example_config();
    whitespace_fingerprint["auth"]["api_keys"][0]["fingerprint"]["name"] = json!(" \t ");
    assert_valid(
        &schema,
        &whitespace_fingerprint,
        "whitespace-only fingerprint environment name accepted by its consumer",
    );
    assert_runtime_deserializes(
        &whitespace_fingerprint,
        "whitespace-only fingerprint environment name accepted by its consumer",
    );

    for value in ["", "INVALID=NAME", "INVALID\0NAME"] {
        let mut fingerprint = example_config();
        fingerprint["auth"]["api_keys"][0]["fingerprint"]["name"] = json!(value);
        assert_invalid(
            &schema,
            &fingerprint,
            &format!("OS-invalid fingerprint environment name {value:?}"),
        );

        let mut audit = example_config();
        audit["audit"]["hash_secret_env"] = json!(value);
        assert_invalid(
            &schema,
            &audit,
            &format!("OS-invalid audit environment name {value:?}"),
        );
    }

    for value in [" ", "\t", "\n", " \t\n "] {
        let mut audit = example_config();
        audit["audit"]["hash_secret_env"] = json!(value);
        assert_invalid(
            &schema,
            &audit,
            &format!("whitespace-only audit environment name {value:?}"),
        );
    }
}

#[test]
fn emitted_schema_matches_rust_unicode_whitespace_semantics() {
    let artifact = fs::read_to_string(relay_root().join(SCHEMA_ARTIFACT))
        .expect("committed Relay schema exists");
    let schema: Value =
        serde_json::from_str(&artifact).expect("committed Relay schema is valid JSON");

    let mut next_line_audit = example_config();
    next_line_audit["audit"]["hash_secret_env"] = json!(NEXT_LINE);
    assert_invalid(
        &schema,
        &next_line_audit,
        "U+0085-only audit environment name under Draft 2020-12",
    );

    let mut byte_order_mark_audit = example_config();
    byte_order_mark_audit["audit"]["hash_secret_env"] = json!(ZERO_WIDTH_NO_BREAK_SPACE);
    assert_valid(
        &schema,
        &byte_order_mark_audit,
        "U+FEFF audit environment name under Draft 2020-12",
    );

    for value in [NEXT_LINE, ZERO_WIDTH_NO_BREAK_SPACE] {
        let mut fingerprint = example_config();
        fingerprint["auth"]["api_keys"][0]["fingerprint"]["name"] = json!(value);
        assert_valid(
            &schema,
            &fingerprint,
            &format!("broader fingerprint environment name {value:?}"),
        );
    }
}

#[test]
fn runtime_loads_os_valid_non_portable_environment_name() {
    if std::env::var_os(NON_PORTABLE_ENVIRONMENT_CHILD).is_some() {
        assert_eq!(
            std::env::var(NON_PORTABLE_ENVIRONMENT_NAME).as_deref(),
            Ok(NON_PORTABLE_ENVIRONMENT_VALUE)
        );
        AuditChainProfile::registry_relay_from_env(NON_PORTABLE_ENVIRONMENT_NAME)
            .expect("audit runtime loads an OS-valid name containing dot and hyphen");
        return;
    }

    let output = Command::new(std::env::current_exe().expect("current test executable exists"))
        .args([
            "--exact",
            "runtime_loads_os_valid_non_portable_environment_name",
        ])
        .env(
            NON_PORTABLE_ENVIRONMENT_NAME,
            NON_PORTABLE_ENVIRONMENT_VALUE,
        )
        .env(NON_PORTABLE_ENVIRONMENT_CHILD, "1")
        .output()
        .expect("child test process runs");
    assert!(
        output.status.success(),
        "child environment read failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn audit_runtime_rejects_whitespace_only_environment_name() {
    if std::env::var_os(WHITESPACE_AUDIT_ENVIRONMENT_CHILD).is_some() {
        assert!(matches!(
            AuditChainProfile::registry_relay_from_env(" \t "),
            Err(AuditError::EmptyEnvVarName)
        ));
        return;
    }

    let output = Command::new(std::env::current_exe().expect("current test executable exists"))
        .args([
            "--exact",
            "audit_runtime_rejects_whitespace_only_environment_name",
        ])
        .env(WHITESPACE_AUDIT_ENVIRONMENT_CHILD, "1")
        .output()
        .expect("child audit runtime test process runs");
    assert!(
        output.status.success(),
        "child audit runtime rejection failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn audit_runtime_matches_rust_unicode_whitespace_semantics() {
    if std::env::var_os(UNICODE_AUDIT_ENVIRONMENT_CHILD).is_some() {
        assert!(matches!(
            AuditChainProfile::registry_relay_from_env(NEXT_LINE),
            Err(AuditError::EmptyEnvVarName)
        ));
        AuditChainProfile::registry_relay_from_env(ZERO_WIDTH_NO_BREAK_SPACE)
            .expect("audit runtime accepts U+FEFF as a non-whitespace Unix environment name");
        return;
    }

    let output = Command::new(std::env::current_exe().expect("current test executable exists"))
        .args([
            "--exact",
            "audit_runtime_matches_rust_unicode_whitespace_semantics",
        ])
        .env(ZERO_WIDTH_NO_BREAK_SPACE, NON_PORTABLE_ENVIRONMENT_VALUE)
        .env(UNICODE_AUDIT_ENVIRONMENT_CHILD, "1")
        .output()
        .expect("child Unicode audit runtime test process runs");
    assert!(
        output.status.success(),
        "child Unicode audit runtime parity failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn schema_command_does_not_read_config_source_environment_or_secret_values() {
    let marker = "SCHEMA_MUST_NOT_READ_OR_EMIT_THIS_SECRET_VALUE";
    let temp = tempfile::tempdir().expect("temporary working directory");
    let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .args(["schema", "--format=json"])
        .current_dir(temp.path())
        .env(
            "REGISTRY_RELAY_CONFIG",
            temp.path().join("missing-config.yaml"),
        )
        .env("REGISTRY_RELAY_SCHEMA_SECRET_SENTINEL", marker)
        .output()
        .expect("schema command runs without runtime inputs");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, document_json().as_bytes());
    assert!(!String::from_utf8(output.stdout).unwrap().contains(marker));
}

fn collect_key_paths(
    root: &Value,
    schema: &Value,
    prefix: &str,
    paths: &mut BTreeSet<String>,
    visited_refs: &mut HashSet<(String, String)>,
) {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let visit = (reference.to_string(), prefix.to_string());
        if visited_refs.insert(visit) {
            let target = root
                .pointer(reference.strip_prefix('#').expect("local schema reference"))
                .unwrap_or_else(|| panic!("unresolved schema reference {reference}"));
            collect_key_paths(root, target, prefix, paths, visited_refs);
        }
    }

    for combinator in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = schema.get(combinator).and_then(Value::as_array) {
            for branch in branches {
                collect_key_paths(root, branch, prefix, paths, visited_refs);
            }
        }
    }

    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (name, property) in properties {
            let property_path = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{prefix}.{name}")
            };
            paths.insert(property_path.clone());
            collect_key_paths(root, property, &property_path, paths, visited_refs);
        }
    }

    if let Some(items) = schema.get("items").filter(|value| value.is_object()) {
        let item_path = format!("{prefix}[]");
        paths.insert(item_path.clone());
        collect_key_paths(root, items, &item_path, paths, visited_refs);
    }

    if let Some(values) = schema
        .get("additionalProperties")
        .filter(|value| value.is_object())
    {
        let value_path = format!("{prefix}.*");
        paths.insert(value_path.clone());
        collect_key_paths(root, values, &value_path, paths, visited_refs);
    }
}

fn documented_key_paths(reference: &str) -> BTreeSet<String> {
    let Some((_, tail)) = reference.split_once(KEY_PATHS_START) else {
        return BTreeSet::new();
    };
    let (block, _) = tail
        .split_once(KEY_PATHS_END)
        .unwrap_or_else(|| panic!("missing {KEY_PATHS_END}"));
    block
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && *line != "```text" && *line != "```")
        .map(str::to_string)
        .collect()
}

#[test]
fn schema_and_configuration_reference_have_exact_bidirectional_key_path_parity() {
    let schema = document();
    let mut schema_paths = BTreeSet::new();
    collect_key_paths(&schema, &schema, "", &mut schema_paths, &mut HashSet::new());
    let reference = fs::read_to_string(relay_root().join(CONFIG_REFERENCE))
        .expect("configuration reference exists");
    let documented_paths = documented_key_paths(&reference);
    assert_eq!(
        documented_paths,
        schema_paths,
        "configuration key paths differ; generated schema paths follow:\n{}",
        schema_paths.iter().cloned().collect::<Vec<_>>().join("\n")
    );
}
