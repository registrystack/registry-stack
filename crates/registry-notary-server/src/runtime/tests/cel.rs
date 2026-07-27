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
async fn subject_access_batch_is_denied_before_evaluation() {
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
            &subject_access_principal(),
            request,
            BatchEvaluateOptions::default(),
        )
        .await
        .expect_err("subject-access batch is not supported");

    assert!(matches!(
        err,
        EvidenceError::SubjectAccessDenied {
            reason: SubjectAccessDenialCode::BatchDenied
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
fn source_free_cel_startup_accepts_a_bounded_string_dependency_below_nine_bytes() {
    let mut dependency = test_claim("dependency", Vec::new(), false);
    dependency.value.value_type = "string".to_string();
    dependency.value.max_bytes = Some(1);
    let mut selected = test_claim("selected", vec!["dependency"], false);
    selected.value.value_type = "string".to_string();
    selected.value.max_bytes = Some(1);
    selected.rule = RuleConfig::Cel {
        expression: "claims.prior.value".to_string(),
        bindings: CelBindingsConfig {
            claims: BTreeMap::from([(
                "prior".to_string(),
                registry_notary_core::ClaimBindingConfig {
                    claim: "dependency".to_string(),
                    binding_type: None,
                },
            )]),
            vars: BTreeMap::new(),
        },
    };
    let evidence = EvidenceConfig {
        enabled: true,
        service_id: "runtime.test".to_string(),
        claims: vec![dependency, selected.clone()],
        ..EvidenceConfig::default()
    };

    validate_cel_claims_for_startup(&evidence, &RegistryNotaryCelConfig::default())
        .expect("a type-correct one-byte dependency preview satisfies the claim bound");
    assert!(matches!(
        validate_claim_value_config(&json!("xx"), &selected.value),
        Err(EvidenceError::RuleEvaluationFailed)
    ));
}

#[cfg(feature = "registry-notary-cel")]
#[test]
fn registry_cel_startup_accepts_a_bounded_string_output_below_nine_bytes() {
    let mut claim = registry_claim(
        "short-code",
        RuleConfig::Cel {
            expression: "enrollment.registration_status".to_string(),
            bindings: CelBindingsConfig::default(),
        },
        "string",
    );
    claim.value.max_bytes = Some(1);
    let ClaimEvidenceMode::RegistryBacked { consultations } = &mut claim.evidence_mode else {
        panic!("registry-backed claim")
    };
    consultations
        .get_mut("enrollment")
        .expect("consultation exists")
        .outputs
        .insert(
            "registration_status".to_string(),
            registry_notary_core::RelayOutputContract::String {
                nullable: false,
                max_bytes: 1,
            },
        );
    let evidence = EvidenceConfig {
        enabled: true,
        service_id: "runtime.test".to_string(),
        claims: vec![claim],
        ..EvidenceConfig::default()
    };

    validate_cel_claims_for_startup(&evidence, &RegistryNotaryCelConfig::default())
        .expect("a type-correct one-byte Relay preview satisfies the claim bound");
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

#[test]
fn claim_value_max_bytes_enforces_utf8_bytes_and_preserves_null_and_absence() {
    let config = |max_bytes, nullable| registry_notary_core::ClaimValueConfig {
        value_type: "string".to_string(),
        nullable,
        max_bytes,
        unit: None,
    };

    assert!(validate_claim_value_config(&json!("ABCD"), &config(Some(4), false)).is_ok());
    assert!(matches!(
        validate_claim_value_config(&json!("ABCDE"), &config(Some(4), false)),
        Err(EvidenceError::RuleEvaluationFailed)
    ));
    assert!(
        validate_claim_value_config(&json!("éé"), &config(Some(4), false)).is_ok(),
        "two two-byte UTF-8 scalars exactly meet a four-byte bound"
    );
    assert!(matches!(
        validate_claim_value_config(&json!("éé"), &config(Some(3), false)),
        Err(EvidenceError::RuleEvaluationFailed)
    ));

    let unbounded = "s".repeat(
        usize::try_from(registry_notary_core::MAX_CLAIM_VALUE_STRING_BYTES_V1)
            .expect("claim byte ceiling fits usize")
            + 1,
    );
    assert!(validate_claim_value_config(&json!(unbounded), &config(None, false)).is_ok());
    assert!(validate_claim_value_config(&Value::Null, &config(Some(1), true)).is_ok());
    assert!(matches!(
        validate_claim_value_config(&Value::Null, &config(Some(1), false)),
        Err(EvidenceError::RuleEvaluationFailed)
    ));
}

#[test]
fn claim_value_max_bytes_failure_classification_does_not_retain_the_value() {
    let sensitive = "DO-NOT-EXPOSE";
    let config = registry_notary_core::ClaimValueConfig {
        value_type: "string".to_string(),
        nullable: false,
        max_bytes: Some(1),
        unit: None,
    };
    let error = validate_claim_value_config(&json!(sensitive), &config)
        .expect_err("over-bound value must fail");

    assert!(matches!(error, EvidenceError::RuleEvaluationFailed));
    assert!(!format!("{error:?}").contains(sensitive));
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

#[cfg(feature = "registry-notary-cel")]
#[test]
fn configured_cel_worker_failures_are_server_side_rule_failures() {
    assert!(matches!(
        cel_worker_error(CelWorkerError::Compile),
        EvidenceError::RuleEvaluationFailed
    ));
    assert!(matches!(
        cel_worker_error(CelWorkerError::Protocol),
        EvidenceError::RuleEvaluationFailed
    ));
}
