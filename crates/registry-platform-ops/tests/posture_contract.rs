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
fn posture_audit_shipping_state_fields_round_trip() {
    let validator = posture_validator();
    for fixture in [
        registry_platform_ops::RELAY_POSTURE_EXAMPLE_V1,
        registry_platform_ops::NOTARY_POSTURE_EXAMPLE_V1,
    ] {
        let posture = parse(fixture);
        assert_valid(&validator, &posture);
        let audit = &posture["posture"]["audit"];
        assert!(audit["shipping_target_configured"].is_boolean());
        assert!(audit["shipping_target"].is_string());

        let rendered = serde_json::to_string(&posture).expect("posture renders");
        let reparsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("rendered posture parses");
        assert_eq!(
            reparsed["posture"]["audit"], posture["posture"]["audit"],
            "shipping-state posture fields must round-trip unchanged"
        );
    }

    let mut missing_shipping_state = parse(registry_platform_ops::RELAY_POSTURE_EXAMPLE_V1);
    missing_shipping_state["posture"]["audit"]
        .as_object_mut()
        .expect("posture audit is object")
        .remove("shipping_target_configured");
    assert_invalid(&validator, &missing_shipping_state);
}

#[test]
fn posture_audit_shipping_health_fields_are_required_and_enumerated() {
    let validator = posture_validator();

    // Canonical examples and fixtures carry the observed shipping-health fields.
    for fixture in [
        registry_platform_ops::RELAY_POSTURE_EXAMPLE_V1,
        registry_platform_ops::NOTARY_POSTURE_EXAMPLE_V1,
        registry_platform_ops::DEFAULT_REDACTED_POSTURE_FIXTURE_V1,
        registry_platform_ops::RESTRICTED_POSTURE_FIXTURE_V1,
    ] {
        let posture = parse(fixture);
        assert_valid(&validator, &posture);
        let audit = &posture["posture"]["audit"];
        assert!(
            audit.get("shipping_health").is_some(),
            "shipping_health must be present"
        );
        assert!(
            audit.get("shipping_observed_at").is_some(),
            "shipping_observed_at must be present"
        );
    }

    // An invalid shipping_health value is rejected.
    let mut bad_health = parse(registry_platform_ops::RELAY_POSTURE_EXAMPLE_V1);
    bad_health["posture"]["audit"]["shipping_health"] = json!("healthy");
    assert_invalid(&validator, &bad_health);

    // Both new fields are required: absence fails validation.
    let mut missing_health = parse(registry_platform_ops::RELAY_POSTURE_EXAMPLE_V1);
    missing_health["posture"]["audit"]
        .as_object_mut()
        .expect("posture audit is object")
        .remove("shipping_health");
    assert_invalid(&validator, &missing_health);

    let mut missing_observed = parse(registry_platform_ops::RELAY_POSTURE_EXAMPLE_V1);
    missing_observed["posture"]["audit"]
        .as_object_mut()
        .expect("posture audit is object")
        .remove("shipping_observed_at");
    assert_invalid(&validator, &missing_observed);

    // shipping_health is null exactly when no shipping target is configured.
    let mut null_health = parse(registry_platform_ops::DEFAULT_REDACTED_POSTURE_FIXTURE_V1);
    null_health["posture"]["audit"]["shipping_health"] = json!(null);
    null_health["posture"]["audit"]["shipping_observed_at"] = json!(null);
    assert_invalid(&validator, &null_health);

    null_health["posture"]["audit"]["shipping_target_configured"] = json!(false);
    null_health["posture"]["audit"]["shipping_target"] = json!("none");
    assert_valid(&validator, &null_health);

    null_health["posture"]["audit"]["shipping_health"] = json!("unverified");
    assert_invalid(&validator, &null_health);
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
fn posture_schema_accepts_default_safe_emergency_configuration_block() {
    let validator = posture_validator();
    let mut posture = parse(registry_platform_ops::RELAY_POSTURE_EXAMPLE_V1);
    posture["configuration"]["emergency"] = json!({
        "last_apply_emergency": true,
        "last_emergency_change_class": "config.emergency",
        "last_emergency_at": "2026-06-13T01:02:03Z",
        "exception_window_open": true,
        "exception_window_expires_at": "2026-06-13T02:02:03Z",
        "open_exception_count": 1
    });
    assert_valid(&validator, &posture);

    let mut invalid_change_class = posture.clone();
    invalid_change_class["configuration"]["emergency"]["last_emergency_change_class"] =
        json!("Config Emergency");
    assert_invalid(&validator, &invalid_change_class);

    let mut leaked_reason = posture.clone();
    leaked_reason["configuration"]["emergency"]["reason"] = json!("operator free text");
    assert_invalid(&validator, &leaked_reason);

    let mut leaked_approver = posture;
    leaked_approver["configuration"]["emergency"]["approved_by"] = json!("did:example:operator");
    assert_invalid(&validator, &leaked_approver);
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

#[test]
fn default_filter_preserves_emergency_configuration_block() {
    let validator = posture_validator();
    let mut posture = parse(registry_platform_ops::RELAY_POSTURE_EXAMPLE_V1);
    posture["configuration"]["emergency"] = json!({
        "last_apply_emergency": true,
        "last_emergency_change_class": "config.emergency",
        "last_emergency_at": "2026-06-13T01:02:03Z",
        "exception_window_open": true,
        "exception_window_expires_at": "2026-06-13T02:02:03Z",
        "open_exception_count": 1
    });

    let filtered = registry_platform_ops::filter_posture_for_tier(
        posture,
        registry_platform_ops::PostureTier::Default,
    )
    .expect("default posture filters");

    assert_valid(&validator, &filtered);
    assert_eq!(
        filtered["configuration"]["emergency"],
        json!({
            "last_apply_emergency": true,
            "last_emergency_change_class": "config.emergency",
            "last_emergency_at": "2026-06-13T01:02:03Z",
            "exception_window_open": true,
            "exception_window_expires_at": "2026-06-13T02:02:03Z",
            "open_exception_count": 1
        })
    );
}

#[test]
fn default_examples_are_allowlist_projections() {
    let allowlist = parse(registry_platform_ops::DEFAULT_POSTURE_ALLOWLIST_FIXTURE_V1);
    let allowed = allowlist["allowed_json_pointers"]
        .as_array()
        .expect("allowlist pointers are array")
        .iter()
        .map(|value| value.as_str().expect("pointer is string"))
        .collect::<Vec<_>>();

    for example in [
        registry_platform_ops::RELAY_POSTURE_EXAMPLE_V1,
        registry_platform_ops::NOTARY_POSTURE_EXAMPLE_V1,
    ] {
        let posture = parse(example);
        assert_eq!(posture["tier"], "default");
        for pointer in collect_leaf_pointers(&posture) {
            assert!(
                pointer_is_allowed(&pointer, &allowed),
                "default example contains a leaf outside the default allowlist: {pointer}"
            );
        }
    }
}

#[test]
fn shared_filter_enforces_default_tier_allowlist() {
    let validator = posture_validator();
    let restricted_posture = parse(registry_platform_ops::RESTRICTED_POSTURE_FIXTURE_V1);
    let filtered = registry_platform_ops::filter_posture_for_tier(
        restricted_posture,
        registry_platform_ops::PostureTier::Default,
    )
    .expect("default posture filters");

    assert_valid(&validator, &filtered);
    assert_eq!(filtered["tier"], "default");
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
            filtered.pointer(restricted_pointer).is_none(),
            "default filter retained restricted pointer: {restricted_pointer}"
        );
    }
}

#[test]
fn default_filter_does_not_clone_composite_values_at_allowlisted_scalar_paths() {
    let mut posture = parse(registry_platform_ops::DEFAULT_REDACTED_POSTURE_FIXTURE_V1);
    posture["posture"]["findings"][0]["evidence"][0]["value"] = json!({
        "secret": "nested-sensitive-diagnostic",
        "details": ["private-node-a", "private-node-b"]
    });
    posture["posture"]["warnings"] = json!([
        "ordinary warning",
        { "secret": "nested-warning-sensitive-diagnostic" }
    ]);

    let filtered = registry_platform_ops::filter_posture_for_tier(
        posture,
        registry_platform_ops::PostureTier::Default,
    )
    .expect("default posture filters");
    let rendered = serde_json::to_string(&filtered).expect("filtered posture renders");

    assert!(!rendered.contains("nested-sensitive-diagnostic"));
    assert!(!rendered.contains("private-node-a"));
    assert!(!rendered.contains("nested-warning-sensitive-diagnostic"));
    assert!(filtered["posture"]["findings"][0]["evidence"][0]["value"].is_null());
    assert_eq!(filtered["posture"]["warnings"], json!(["ordinary warning"]));
}

#[test]
fn default_filter_drops_nonempty_dynamic_containers_without_allowed_children() {
    let mut posture = parse(registry_platform_ops::DEFAULT_REDACTED_POSTURE_FIXTURE_V1);
    posture["standards_artifacts"]["hidden_artifact"] = json!({
        "url": "https://internal.example.gov/private/spec",
        "diagnostics": {
            "secret": "hidden-artifact-sensitive-diagnostic"
        }
    });

    let filtered = registry_platform_ops::filter_posture_for_tier(
        posture,
        registry_platform_ops::PostureTier::Default,
    )
    .expect("default posture filters");
    let rendered = serde_json::to_string(&filtered).expect("filtered posture renders");

    assert!(filtered["standards_artifacts"]["hidden_artifact"].is_null());
    assert!(!rendered.contains("hidden-artifact-sensitive-diagnostic"));
    assert!(!rendered.contains("https://internal.example.gov/private/spec"));
}

#[test]
fn shared_filter_preserves_restricted_tier() {
    let restricted_posture = parse(registry_platform_ops::RESTRICTED_POSTURE_FIXTURE_V1);
    let filtered = registry_platform_ops::filter_posture_for_tier(
        restricted_posture.clone(),
        registry_platform_ops::PostureTier::Restricted,
    )
    .expect("restricted posture filters");

    assert_eq!(filtered["tier"], "restricted");
    assert_eq!(filtered, restricted_posture);
}

fn pointer_is_allowed(pointer: &str, allowed: &[&str]) -> bool {
    allowed.iter().any(|pattern| {
        pointer_segments_match(pointer, pattern)
            || pointer_is_allowed_container(pointer, pattern)
            || pointer
                .strip_suffix("/*")
                .is_some_and(|parent| pointer_segments_match(parent, pattern))
    })
}

fn pointer_is_allowed_container(pointer: &str, pattern: &str) -> bool {
    let pointer_segments = pointer
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    let pattern_segments = pattern
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    pattern_segments.len() > pointer_segments.len()
        && pattern_segments
            .iter()
            .zip(pointer_segments)
            .all(|(pattern, segment)| *pattern == "*" || *pattern == segment)
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
