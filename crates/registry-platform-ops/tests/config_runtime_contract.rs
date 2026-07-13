use registry_platform_ops::{
    internal_config_hash, is_sha256_config_hash, posture_safe_config_hash,
    posture_safe_runtime_config_hash, registry_runtime_config_sensitivity, ConfigProvenance,
    ConfigSource, ConfigValueSensitivity,
};
use serde_json::{json, Value};

fn classify(path: &[&str], _value: &Value) -> ConfigValueSensitivity {
    match path {
        ["auth", "token"]
        | ["database_url"]
        | ["signing", "private_jwk"]
        | ["nested", "secret_env"] => ConfigValueSensitivity::Secret,
        _ => ConfigValueSensitivity::Public,
    }
}

#[test]
fn internal_hash_tracks_exact_source_bytes() {
    let first = internal_config_hash(b"issuer: example\nsecret: one\n");
    let second = internal_config_hash(b"issuer: example\nsecret: two\n");

    assert_ne!(first, second);
    assert!(first.starts_with("sha256:"));
    assert_eq!(first.len(), "sha256:".len() + 64);
}

#[test]
fn config_hash_format_requires_sha256_prefix_and_lowercase_hex_digest() {
    assert!(is_sha256_config_hash(
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ));
    assert!(!is_sha256_config_hash(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ));
    assert!(!is_sha256_config_hash("sha256:not-a-digest"));
    assert!(!is_sha256_config_hash(
        "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"
    ));
    assert!(!is_sha256_config_hash(
        "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    ));
}

#[test]
fn posture_safe_hash_ignores_secret_value_changes() {
    let first = json!({
        "issuer": "did:web:notary.example",
        "auth": {
            "token": "secret-one"
        },
        "nested": {
            "secret_env": "REGISTRY_NOTARY_TOKEN"
        }
    });
    let second = json!({
        "issuer": "did:web:notary.example",
        "auth": {
            "token": "secret-two"
        },
        "nested": {
            "secret_env": "OTHER_TOKEN"
        }
    });

    assert_eq!(
        posture_safe_config_hash(&first, classify),
        posture_safe_config_hash(&second, classify)
    );
}

#[test]
fn posture_safe_hash_tracks_public_value_changes() {
    let first = json!({
        "issuer": "did:web:notary.example",
        "auth": {
            "token": "secret"
        }
    });
    let second = json!({
        "issuer": "did:web:other.example",
        "auth": {
            "token": "secret"
        }
    });

    assert_ne!(
        posture_safe_config_hash(&first, classify),
        posture_safe_config_hash(&second, classify)
    );
}

#[test]
fn shared_runtime_classifier_ignores_secret_and_topology_changes() {
    let first = json!({
        "instance": {
            "id": "registry-a",
            "environment": "production",
            "owner": "ops"
        },
        "server": {
            "bind": "127.0.0.1:8080",
            "admin_bind": "127.0.0.1:9090",
            "cache_dir": "/var/lib/registry-a"
        },
        "auth": {
            "mode": "api_key",
            "api_keys": [{ "key_id": "ops", "hash_env": "OPS_HASH_A" }]
        },
        "audit": {
            "sink": "file",
            "hash_secret_env": "AUDIT_SECRET_A"
        },
        "evidence": {
            "api_base_url": "https://notary-a.example.test",
            "relay": {
                "base_url": "https://relay-a.internal",
                "token_file": "/run/secrets/relay-token-a"
            }
        }
    });
    let mut second = first.clone();
    second["server"]["bind"] = json!("10.0.0.5:8080");
    second["server"]["cache_dir"] = json!("/srv/registry-b");
    second["auth"]["api_keys"][0]["hash_env"] = json!("OPS_HASH_B");
    second["audit"]["hash_secret_env"] = json!("AUDIT_SECRET_B");
    second["evidence"]["api_base_url"] = json!("https://notary-b.example.test");
    second["evidence"]["relay"]["base_url"] = json!("https://relay-b.internal");
    second["evidence"]["relay"]["token_file"] = json!("/run/secrets/relay-token-b");

    assert_eq!(
        posture_safe_runtime_config_hash(&first),
        posture_safe_runtime_config_hash(&second)
    );
}

#[test]
fn shared_runtime_classifier_tracks_public_posture_fields() {
    let first = json!({
        "instance": {
            "id": "registry-a",
            "environment": "production",
            "owner": "ops"
        },
        "auth": {
            "mode": "api_key",
            "api_keys": [{ "key_id": "ops", "hash_env": "OPS_HASH" }]
        },
        "catalog": {
            "base_url": "https://relay-a.example.test",
            "publisher": "Internal Publisher"
        }
    });
    let mut second = first.clone();
    second["instance"]["owner"] = json!("data-office");

    assert_ne!(
        posture_safe_runtime_config_hash(&first),
        posture_safe_runtime_config_hash(&second)
    );

    let mut third = first.clone();
    third["catalog"]["base_url"] = json!("https://relay-b.example.test");
    assert_ne!(
        posture_safe_runtime_config_hash(&first),
        posture_safe_runtime_config_hash(&third)
    );
}

#[test]
fn shared_runtime_classifier_defaults_unknown_fields_to_secret() {
    let first = json!({
        "instance": {
            "id": "registry-a",
            "undocumented_endpoint": "https://private-a.example.test"
        }
    });
    let mut second = first.clone();
    second["instance"]["undocumented_endpoint"] = json!("https://private-b.example.test");

    assert_eq!(
        posture_safe_runtime_config_hash(&first),
        posture_safe_runtime_config_hash(&second)
    );
    assert_eq!(
        registry_runtime_config_sensitivity(
            &["instance", "undocumented_endpoint"],
            &first["instance"]["undocumented_endpoint"]
        ),
        ConfigValueSensitivity::Secret
    );
}

#[test]
fn posture_safe_runtime_hash_differs_from_internal_source_hash() {
    let value = json!({
        "instance": {
            "id": "registry-a",
            "owner": "ops"
        },
        "auth": {
            "mode": "api_key",
            "api_keys": [{ "key_id": "ops", "hash_env": "OPS_HASH" }]
        }
    });
    let source_bytes = br#"
instance:
  id: registry-a
  owner: ops
auth:
  mode: api_key
  api_keys:
    - key_id: ops
      hash_env: OPS_HASH
"#;

    assert_ne!(
        posture_safe_runtime_config_hash(&value),
        internal_config_hash(source_bytes)
    );
}

#[test]
fn local_provenance_uses_existing_posture_vocabulary() {
    let provenance = ConfigProvenance::local_file(
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        false,
    );

    assert_eq!(provenance.source, ConfigSource::LocalFile);
    assert_eq!(provenance.posture_source(), "local_file");
    assert!(!provenance.dynamic_reload_supported);
    assert_eq!(provenance.last_bundle_id, None);
    assert_eq!(provenance.last_bundle_sequence, None);
    assert!(provenance.last_bundle_signer_kids.is_empty());
    assert_eq!(provenance.override_pin, None);
    assert_eq!(provenance.last_apply_result, None);
    assert_eq!(provenance.last_apply_at, None);
    assert!(!provenance.restart_required);
}

#[test]
fn config_source_labels_match_posture_schema_vocabulary() {
    let labels = [
        ConfigSource::LocalFile.as_posture_str(),
        ConfigSource::SignedBundleFile.as_posture_str(),
        ConfigSource::SignedBundleEndpoint.as_posture_str(),
        ConfigSource::Unknown.as_posture_str(),
    ];

    assert_eq!(
        labels,
        [
            "local_file",
            "signed_bundle_file",
            "signed_bundle_endpoint",
            "unknown",
        ]
    );
}
