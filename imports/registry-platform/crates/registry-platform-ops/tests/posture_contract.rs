use serde_json::{json, Value};

fn parse(input: &str) -> Value {
    serde_json::from_str(input).expect("fixture parses as JSON")
}

fn posture_validator() -> jsonschema::Validator {
    let schema = parse(registry_platform_ops::POSTURE_SCHEMA_V1);
    jsonschema::validator_for(&schema).expect("posture schema compiles")
}

fn assert_valid(validator: &jsonschema::Validator, instance: &Value) {
    let errors: Vec<_> = validator.iter_errors(instance).collect();
    assert!(
        errors.is_empty(),
        "expected valid posture, got errors: {errors:?}"
    );
}

fn assert_invalid(validator: &jsonschema::Validator, instance: &Value) {
    assert!(
        !validator.is_valid(instance),
        "expected invalid posture: {instance:#}"
    );
}

fn collect_leaf_pointers(value: &Value) -> Vec<String> {
    let mut pointers = Vec::new();
    collect_leaf_pointers_at(value, "", &mut pointers);
    pointers
}

fn collect_leaf_pointers_at(value: &Value, base: &str, pointers: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if map.is_empty() {
                pointers.push(base.to_string());
            }
            for (key, child) in map {
                collect_leaf_pointers_at(
                    child,
                    &format!("{base}/{}", escape_pointer(key)),
                    pointers,
                );
            }
        }
        Value::Array(items) => {
            if items.is_empty() {
                pointers.push(base.to_string());
            }
            for child in items {
                collect_leaf_pointers_at(child, &format!("{base}/*"), pointers);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            pointers.push(base.to_string());
        }
    }
}

fn escape_pointer(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

#[test]
fn posture_examples_and_redaction_fixtures_validate() {
    let validator = posture_validator();
    for fixture in [
        registry_platform_ops::RELAY_POSTURE_EXAMPLE_V1,
        registry_platform_ops::NOTARY_POSTURE_EXAMPLE_V1,
        registry_platform_ops::DEFAULT_REDACTED_POSTURE_FIXTURE_V1,
        registry_platform_ops::RESTRICTED_POSTURE_FIXTURE_V1,
    ] {
        assert_valid(&validator, &parse(fixture));
    }
}

#[test]
fn malformed_posture_documents_fail_validation() {
    let validator = posture_validator();

    let mut missing_required = parse(registry_platform_ops::RELAY_POSTURE_EXAMPLE_V1);
    missing_required
        .as_object_mut()
        .expect("posture is object")
        .remove("configuration");
    assert_invalid(&validator, &missing_required);

    let mut missing_audit = parse(registry_platform_ops::RELAY_POSTURE_EXAMPLE_V1);
    missing_audit["posture"]
        .as_object_mut()
        .expect("posture summary is object")
        .remove("audit");
    assert_invalid(&validator, &missing_audit);

    let mut wrong_component_extension = parse(registry_platform_ops::RELAY_POSTURE_EXAMPLE_V1);
    let relay = wrong_component_extension
        .as_object_mut()
        .expect("posture is object")
        .remove("relay")
        .expect("relay section exists");
    wrong_component_extension["notary"] = relay;
    assert_invalid(&validator, &wrong_component_extension);

    let mut invalid_severity = parse(registry_platform_ops::DEFAULT_REDACTED_POSTURE_FIXTURE_V1);
    invalid_severity["posture"]["findings"][0]["severity"] = json!("severe");
    assert_invalid(&validator, &invalid_severity);

    let mut invalid_artifact_hash =
        parse(registry_platform_ops::DEFAULT_REDACTED_POSTURE_FIXTURE_V1);
    invalid_artifact_hash["standards_artifacts"]["jwks"]["sha256"] =
        json!("sha256:not-a-hex-digest");
    assert_invalid(&validator, &invalid_artifact_hash);

    let mut uppercase_artifact_hash =
        parse(registry_platform_ops::DEFAULT_REDACTED_POSTURE_FIXTURE_V1);
    uppercase_artifact_hash["standards_artifacts"]["jwks"]["sha256"] =
        json!("sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert_valid(&validator, &uppercase_artifact_hash);

    let mut secret_passthrough = parse(registry_platform_ops::DEFAULT_REDACTED_POSTURE_FIXTURE_V1);
    secret_passthrough["configuration"]["database_url"] =
        json!("postgres://registry:secret@private-db.internal/registry");
    assert_invalid(&validator, &secret_passthrough);
}

#[test]
fn redaction_fixture_default_posture_is_allowlist_projection() {
    let allowlist = parse(registry_platform_ops::DEFAULT_POSTURE_ALLOWLIST_FIXTURE_V1);
    let allowed = allowlist["allowed_json_pointers"]
        .as_array()
        .expect("allowlist pointers are array")
        .iter()
        .map(|value| value.as_str().expect("pointer is string"))
        .collect::<Vec<_>>();
    let restricted = allowlist["restricted_json_pointers_excluded_by_default"]
        .as_array()
        .expect("restricted pointers are array")
        .iter()
        .map(|value| value.as_str().expect("pointer is string"))
        .collect::<Vec<_>>();

    for pointer in &restricted {
        assert!(
            !allowed.contains(pointer),
            "restricted pointer appears in default allowlist: {pointer}"
        );
    }

    let sensitive_input = parse(registry_platform_ops::REDACTION_INPUT_SENSITIVE_FIXTURE_V1);
    let safe_projection = &sensitive_input["source_runtime_state"]["safe_posture_projection"];
    let default_posture = parse(registry_platform_ops::DEFAULT_REDACTED_POSTURE_FIXTURE_V1);
    assert_eq!(
        safe_projection, &default_posture,
        "default redacted fixture must match the explicitly allowlisted projection"
    );

    for pointer in collect_leaf_pointers(&default_posture) {
        assert!(
            pointer_is_allowed(&pointer, &allowed),
            "default posture contains a leaf outside the default allowlist: {pointer}"
        );
    }
}

fn pointer_is_allowed(pointer: &str, allowed: &[&str]) -> bool {
    allowed.iter().any(|pattern| {
        pointer_segments_match(pointer, pattern)
            || pointer
                .strip_suffix("/*")
                .is_some_and(|parent| pointer_segments_match(parent, pattern))
    })
}

fn pointer_segments_match(pointer: &str, pattern: &str) -> bool {
    let pointer_segments = pointer
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    let pattern_segments = pattern
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    pointer_segments.len() == pattern_segments.len()
        && pointer_segments
            .iter()
            .zip(pattern_segments)
            .all(|(segment, pattern)| pattern == "*" || *segment == pattern)
}

#[test]
fn posture_tier_fixtures_preserve_restricted_field_boundary() {
    let default_posture = parse(registry_platform_ops::DEFAULT_REDACTED_POSTURE_FIXTURE_V1);
    let restricted_posture = parse(registry_platform_ops::RESTRICTED_POSTURE_FIXTURE_V1);

    assert_eq!(default_posture["tier"], "default");
    assert_eq!(restricted_posture["tier"], "restricted");

    for restricted_pointer in [
        "/instance/public_base_url",
        "/build/git_sha",
        "/build/features",
        "/configuration/trusted_roots",
        "/standards_artifacts/jwks/url",
        "/notary/signing_keys",
        "/notary/federation/node_id",
        "/notary/federation/issuer",
        "/notary/federation/peers",
    ] {
        assert!(
            default_posture.pointer(restricted_pointer).is_none(),
            "default posture included restricted pointer: {restricted_pointer}"
        );
        assert!(
            restricted_posture.pointer(restricted_pointer).is_some(),
            "restricted posture fixture did not include restricted pointer: {restricted_pointer}"
        );
    }
}

#[test]
fn default_posture_excludes_sensitive_runtime_material() {
    let default_posture = parse(registry_platform_ops::DEFAULT_REDACTED_POSTURE_FIXTURE_V1);
    let rendered = serde_json::to_string(&default_posture).expect("posture renders");

    for forbidden in [
        "super-secret-db-password",
        "eyJsecret.source.token",
        "oauth-client-secret-value",
        "redis-secret",
        "audit-hmac-secret-value",
        "did:example:person:123",
        "national-id-123456789",
        "\"raw_rows\"",
        "\"income\"",
        "42000",
        "WyJzYWx0IiwiaW5jb21lIiw0MjAwMF0",
        "tokenhash000000000000000000000000000000000000000000000000000000",
        "private-ed25519-seed-value",
        "\"d\"",
        "https://source.internal.example.gov/api/people",
        "https://admin.internal.example.gov",
        "did:web:peer-a.internal.example.gov",
        "root-private-2026",
        "did:web:ops.internal.example.gov#root-signer",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "default posture leaked forbidden sensitive material: {forbidden}"
        );
    }
}
