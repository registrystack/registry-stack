// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "registry-notary-cel")]
#[test]
fn cel_root_bindings_redact_dependent_object_claim_values() {
    let mut dependency = test_claim("dependency", Vec::new(), false);
    dependency.value.value_type = "object".to_string();
    let selected = test_claim("selected", vec!["dependency"], false);
    let evidence = EvidenceConfig {
        enabled: true,
        service_id: "runtime.test".to_string(),
        claims: vec![selected.clone(), dependency],
        ..EvidenceConfig::default()
    };
    let bindings = CelBindingsConfig {
        claims: BTreeMap::from([(
            "prior".to_string(),
            registry_notary_core::ClaimBindingConfig {
                claim: "dependency".to_string(),
                binding_type: None,
            },
        )]),
        vars: BTreeMap::new(),
    };
    let claims = BTreeMap::from([(
        "dependency".to_string(),
        test_claim_result(
            "dependency",
            json!({
                "name": "Ada",
                "ssn": "123-45-6789"
            }),
            BTreeSet::from(["ssn".to_string()]),
        ),
    )]);
    let sources = BTreeMap::new();
    let target = EvidenceEntity::new("Person");
    let config = RegistryNotaryCelConfig::default();

    let root = cel_root_bindings(&CelEvaluationContext {
        evidence: &evidence,
        claim: &selected,
        expression: "claims.prior.value.ssn",
        bindings: &bindings,
        claims: &claims,
        consultation_outputs: &sources,
        variables: &Default::default(),
        subject: None,
        target: &target,
        purpose: "benefits",
        today: "2026-06-18".to_string(),
        worker: None,
        config: &config,
    })
    .expect("CEL root bindings build");
    let prior = &root["claims"]["prior"];

    assert_eq!(prior["value"], json!({"name": "Ada"}));
    assert!(prior["value"].get("ssn").is_none());
    assert_eq!(prior["satisfied"], Value::Null);
}

#[tokio::test]
async fn self_attestation_batch_is_denied_before_evaluation() {
    let evidence = test_evidence(vec![test_claim("selected", Vec::new(), true)]);
    let store = EvidenceStore::default();
    let request = BatchEvaluateRequest {
        items: vec![registry_notary_core::BatchEvaluateItemRequest::from(
            registry_notary_core::BatchSubjectRequest {
                id: "person-1".to_string(),
                id_type: None,
                purpose: None,
            },
        )],
        claims: vec![ClaimRef::from("selected")],
        disclosure: Some("value".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("test".to_string()),
    };

    let err = RegistryNotaryRuntime::new()
        .batch_evaluate(
            evidence,
            &store,
            &self_attestation_principal(),
            request,
            BatchEvaluateOptions::default(),
        )
        .await
        .expect_err("self-attestation batch is not supported");

    assert!(matches!(
        err,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::BatchDenied
        }
    ));
}

#[cfg(feature = "registry-notary-cel")]
#[test]
fn cel_binding_limits_reject_large_strings_and_lists() {
    let config = RegistryNotaryCelConfig {
        max_string_bytes: 4,
        max_list_items: 2,
        ..RegistryNotaryCelConfig::default()
    };

    assert!(validate_cel_binding_limits(&json!({ "value": "abcd" }), &config).is_ok());
    assert!(matches!(
        validate_cel_binding_limits(&json!({ "value": "abcde" }), &config),
        Err(EvidenceError::RuleEvaluationFailed)
    ));
    assert!(matches!(
        validate_cel_binding_limits(&json!({ "items": [1, 2, 3] }), &config),
        Err(EvidenceError::RuleEvaluationFailed)
    ));
}

#[cfg(feature = "registry-notary-cel")]
#[test]
fn cel_policy_validation_rejects_invalid_alias_and_unlisted_dependency() {
    let claim = test_claim("cel-claim", vec!["dependency"], false);
    let invalid_alias = CelBindingsConfig {
        claims: BTreeMap::from([(
            "not-valid-alias".to_string(),
            registry_notary_core::ClaimBindingConfig {
                claim: "dependency".to_string(),
                binding_type: None,
            },
        )]),
        vars: BTreeMap::new(),
    };
    assert!(matches!(
        validate_cel_policy(
            "true",
            &invalid_alias,
            &claim,
            &RegistryNotaryCelConfig::default()
        ),
        Err(EvidenceError::InvalidRequest)
    ));

    let unlisted_dependency = CelBindingsConfig {
        claims: BTreeMap::from([(
            "dep".to_string(),
            registry_notary_core::ClaimBindingConfig {
                claim: "other".to_string(),
                binding_type: None,
            },
        )]),
        vars: BTreeMap::new(),
    };
    assert!(matches!(
        validate_cel_policy(
            "true",
            &unlisted_dependency,
            &claim,
            &RegistryNotaryCelConfig::default()
        ),
        Err(EvidenceError::InvalidRequest)
    ));
}

#[cfg(feature = "registry-notary-cel")]
#[test]
fn registry_cel_startup_is_limited_to_one_output_root_and_declared_variables() {
    let mut claim = typed_registry_claim(
            "age-band",
            RuleConfig::Cel {
                expression: "enrollment.matched && enrollment.date_of_birth != null ? date.age_on(enrollment.date_of_birth, as_of_date) : null".to_string(),
                bindings: Default::default(),
            },
            "integer",
        );
    let mut evidence = EvidenceConfig {
        enabled: true,
        service_id: "runtime.test".to_string(),
        claims: vec![claim.clone()],
        ..EvidenceConfig::default()
    };
    evidence.variables.insert(
        "as_of_date".to_string(),
        registry_notary_core::RequestVariableConfig {
            from: "request.variables.as_of_date".to_string(),
            value_type: registry_notary_core::RequestVariableType::Date,
        },
    );
    validate_cel_claims_for_startup(&evidence, &RegistryNotaryCelConfig::default())
        .expect("OpenCRVS-style full-date derivation preflights");

    for expression in [
        "caller.scopes.contains('admin')",
        "capability == 'snapshot_exact'",
        "purpose == 'other-purpose'",
        "format == 'application/dc+sd-jwt'",
        "disclosure == 'value'",
        "consultation == 'other-profile'",
        "enrollment.secret == 'x'",
        "enrollment['date_of_birth'] != null",
        "date.age_on(enrollment.date_of_birth, as_of_date)",
    ] {
        claim.rule = RuleConfig::Cel {
            expression: expression.to_string(),
            bindings: Default::default(),
        };
        evidence.claims[0] = claim.clone();
        assert!(matches!(
            validate_cel_claims_for_startup(&evidence, &RegistryNotaryCelConfig::default()),
            Err(EvidenceError::InvalidRequest)
        ));
    }
}

#[cfg(feature = "registry-notary-cel")]
#[test]
fn cel_startup_validation_rejects_unknown_roots_and_regex_usage() {
    assert!(validate_cel_expression_roots(
        "source.farmer.total_farmed_area < 4 && claims.prior.satisfied"
    )
    .is_ok());
    assert!(matches!(
        validate_cel_expression_roots("credential.level == 'gold'"),
        Err(EvidenceError::InvalidRequest)
    ));
    assert!(cel_expression_uses_regex(
        "source.person.name.matches('^A')"
    ));
    assert!(cel_expression_uses_regex(
        "text.regex_replace(source.person.name, '^A', 'B')"
    ));
    assert!(cel_expression_uses_regex(
        "text . regex_replace(source.person.name, '^A', 'B')"
    ));
    assert!(cel_expression_uses_regex(
        "text. regex_extract(source.person.name, '^(.+)$', 1)"
    ));
    assert!(cel_expression_uses_regex(
        "text_regex_extract(source.person.name, '^(.+)$', 1)"
    ));
    assert!(cel_expression_uses_regex(
        "validate.matches(source.person.name, '^A', 'bad')"
    ));
    assert!(!cel_expression_uses_regex(
        "'text.regex_replace(source.person.name, pattern)'"
    ));
}

#[test]
fn claim_value_type_validation_matches_declared_json_shape() {
    assert!(validate_claim_value_type(&json!(true), "boolean").is_ok());
    assert!(validate_claim_value_type(&json!(1.5), "number").is_ok());
    assert!(validate_claim_value_type(&json!(1), "integer").is_ok());
    assert!(validate_claim_value_type(&json!("value"), "string").is_ok());
    assert!(validate_claim_value_type(&json!("2026-06-03"), "date").is_ok());
    assert!(validate_claim_value_type(&json!([1]), "array").is_ok());
    assert!(validate_claim_value_type(&json!({ "k": "v" }), "object").is_ok());
    assert!(validate_claim_value_type(&Value::Null, "null").is_ok());
    assert!(validate_claim_value_type(&json!("value"), "").is_ok());

    assert!(matches!(
        validate_claim_value_type(&json!("value"), "boolean"),
        Err(EvidenceError::RuleEvaluationFailed)
    ));
    assert!(matches!(
        validate_claim_value_type(&json!(1.5), "integer"),
        Err(EvidenceError::RuleEvaluationFailed)
    ));
    assert!(matches!(
        validate_claim_value_type(&json!(9_007_199_254_740_992_i64), "integer"),
        Err(EvidenceError::RuleEvaluationFailed)
    ));
    assert!(matches!(
        validate_claim_value_type(&json!("2026-02-30"), "date"),
        Err(EvidenceError::RuleEvaluationFailed)
    ));
    assert!(matches!(
        validate_claim_value_type(&json!(true), "unsupported"),
        Err(EvidenceError::InvalidRequest)
    ));
}

#[cfg(feature = "registry-notary-cel")]
#[test]
fn cel_binding_limits_reject_deep_json_without_recursive_walk() {
    let config = RegistryNotaryCelConfig::default();
    let mut value = json!(true);
    for _ in 0..=config.max_object_depth {
        value = json!({ "nested": value });
    }

    assert!(matches!(
        validate_cel_binding_limits(&value, &config),
        Err(EvidenceError::RuleEvaluationFailed)
    ));
}

#[cfg(feature = "registry-notary-cel")]
#[test]
fn cel_result_limits_reject_oversized_serialized_output() {
    let config = RegistryNotaryCelConfig {
        max_result_json_bytes: 4,
        ..RegistryNotaryCelConfig::default()
    };

    assert!(matches!(
        validate_cel_result_limits(&json!("12345"), &config),
        Err(EvidenceError::RuleEvaluationFailed)
    ));
}

#[cfg(feature = "registry-notary-cel")]
#[test]
fn cel_result_limits_reject_deep_worker_output_without_recursive_walk() {
    let config = RegistryNotaryCelConfig::default();
    let mut value = json!(true);
    for _ in 0..=config.max_object_depth {
        value = json!({ "nested": value });
    }

    assert!(matches!(
        validate_cel_result_limits(&value, &config),
        Err(EvidenceError::RuleEvaluationFailed)
    ));
}
