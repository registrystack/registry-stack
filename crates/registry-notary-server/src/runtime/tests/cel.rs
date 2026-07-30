// SPDX-License-Identifier: Apache-2.0

#[tokio::test]
async fn subject_access_batch_is_denied_before_evaluation() {
    let evidence = test_evidence(vec![test_claim("selected", Vec::new())]);
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
fn cel_reference_scanners_ignore_literal_and_comment_decoys() {
    for literal in [
        "'enrollment.parents'",
        "\"enrollment.parents\"",
        "'''enrollment.parents'''",
        r###""""enrollment.parents "" decoy""""###,
        r"r'enrollment.parents \x'",
        "r\"enrollment.parents ' decoy\"",
        "r'''enrollment.parents ' decoy'''",
        r###"r"""enrollment.parents " decoy""""###,
        "b'enrollment.parents'",
        "br'''enrollment.parents ' decoy'''",
        r###"br"""enrollment.parents " decoy""""###,
    ] {
        let expression = format!("{literal} == {literal} && enrollment.matched");
        assert_eq!(
            cel_first_level_member_references(&expression, "enrollment"),
            BTreeSet::from(["matched".to_string()]),
            "first-level scanner must ignore decoys in {literal}"
        );
        assert_eq!(
            cel_root_references(&expression),
            BTreeSet::from(["enrollment".to_string()]),
            "root scanner must ignore decoys in {literal}"
        );
        assert!(
            !contains_unquoted_bracket(&format!("{literal} == {literal}")),
            "bracket scanner must ignore brackets in {literal}"
        );
    }

    let after_raw_triple =
        r#"r"""embedded " quote""" != "x" || enrollment.parents.size() > 0"#;
    assert!(
        cel_first_level_member_references(after_raw_triple, "enrollment").contains("parents"),
        "raw triple literals with embedded quotes must not hide later composite references"
    );
    let after_triple = r#""""embedded " quote""" != "x" || enrollment.parents.size() > 0"#;
    assert!(
        cel_first_level_member_references(after_triple, "enrollment").contains("parents"),
        "triple literals with embedded quotes must not hide later composite references"
    );
    let comment_separated = "enrollment // hidden trivia\n . parents.size() > 0";
    assert!(
        cel_first_level_member_references(comment_separated, "enrollment").contains("parents"),
        "line comments between root, dot, and member are trivia"
    );
    assert_eq!(
        registry_cel_required_variables(
            "r'''as_of_date''' == 'x' || as_of_date < ctx.today",
            ["as_of_date"]
        ),
        BTreeSet::from(["as_of_date".to_string()]),
        "bare identifier scanner must ignore raw string decoys"
    );
    assert!(
        contains_unquoted_bracket("r'''[not real]''' == 'x' || enrollment[0]"),
        "bracket scanner must ignore literal brackets and catch real brackets"
    );
    let separated_by_punctuation = "(enrollment).date_of_birth";
    let preview = MappingRuntime::new(RuntimeOptions::default()).preview_cel_expression_with_input(
        separated_by_punctuation,
        StandaloneExpressionInput::new(
            BTreeMap::from([(
                "enrollment".to_string(),
                json!({ "date_of_birth": "2000-01-01" }),
            )])
            .into_iter()
            .collect(),
        ),
    );
    assert!(
        !preview
            .issues
            .iter()
            .any(|issue| issue.severity == ErrorSeverity::Error),
        "control expression must compile as CEL"
    );
    assert!(
        !cel_first_level_member_references(separated_by_punctuation, "enrollment")
            .contains("date_of_birth"),
        "punctuation must prevent synthetic root.member matches"
    );
}

#[cfg(feature = "registry-notary-cel")]
#[test]
fn registry_cel_startup_is_limited_to_one_output_root_and_declared_variables() {
    let mut claim = typed_registry_claim(
        "age-band",
        RuleConfig::Cel {
            expression: "enrollment.matched && enrollment.date_of_birth != null ? date.age_on(enrollment.date_of_birth, as_of_date) : null".to_string(),
        },
        "integer",
    );
    let ClaimEvidenceMode::RegistryBacked { consultations } = &mut claim.evidence_mode else {
        panic!("registry-backed claim");
    };
    consultations
        .get_mut("enrollment")
        .expect("consultation exists")
        .outputs
        .insert(
            "parents".to_string(),
            registry_notary_core::RelayOutputContract::Array {
                nullable: false,
                max_bytes: 4_096,
                max_items: 4,
                items: Box::new(registry_notary_core::RelayOutputContract::Object {
                    nullable: false,
                    max_bytes: 1_024,
                    fields: BTreeMap::from([(
                        "name".to_string(),
                        registry_notary_core::RelayOutputObjectFieldContract {
                            required: true,
                            schema: Box::new(
                                registry_notary_core::RelayOutputContract::String {
                                    nullable: false,
                                    max_bytes: 128,
                                },
                            ),
                        },
                    )]),
                }),
            },
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
    let projected = registry_cel_scalar_consultation_outputs(
        &claim,
        &BTreeMap::from([(
            "enrollment".to_string(),
            json!({
                "matched": true,
                "outcome": "match",
                "date_of_birth": "2000-01-01",
                "parents": [{"name": "Ada"}]
            }),
        )]),
    )
    .expect("scalar CEL view projects");
    assert_eq!(projected["enrollment"]["date_of_birth"], "2000-01-01");
    assert!(
        projected["enrollment"].get("parents").is_none(),
        "composite outputs never enter the CEL binding surface"
    );

    for expression in [
        "enrollment.matched && 'enrollment.parents' == 'enrollment.parents' ? 1 : 0",
        "enrollment.matched && \"enrollment.parents\" == \"enrollment.parents\" ? 1 : 0",
        "enrollment.matched && '''enrollment.parents''' == '''enrollment.parents''' ? 1 : 0",
        r#"enrollment.matched && """enrollment.parents""" == """enrollment.parents""" ? 1 : 0"#,
        r"enrollment.matched && r'enrollment.parents \x' == r'enrollment.parents \x' ? 1 : 0",
        "enrollment.matched && r\"enrollment.parents ' decoy\" == r\"enrollment.parents ' decoy\" ? 1 : 0",
        "enrollment.matched && b'enrollment.parents' == b'enrollment.parents' ? 1 : 0",
    ] {
        claim.rule = RuleConfig::Cel {
            expression: expression.to_string(),
        };
        evidence.claims[0] = claim.clone();
        validate_cel_claims_for_startup(&evidence, &RegistryNotaryCelConfig::default())
            .unwrap_or_else(|error| {
                panic!("literal decoy references must not trip registry CEL validation: {expression}: {error:?}")
            });
    }

    for expression in [
        "caller.scopes.contains('admin')",
        "capability == 'snapshot_exact'",
        "purpose == 'other-purpose'",
        "format == 'application/dc+sd-jwt'",
        "disclosure == 'value'",
        "consultation == 'other-profile'",
        "enrollment.secret == 'x'",
        "enrollment.parents.size() > 0",
        "enrollment['date_of_birth'] != null",
        "date.age_on(enrollment.date_of_birth, as_of_date)",
        r#""""embedded " quote""" != "x" || enrollment.parents.size() > 0 ? 1 : 0"#,
        r#"r"""embedded " quote""" != "x" || enrollment.parents.size() > 0 ? 1 : 0"#,
        "'''embedded ' quote''' != \"x\" || enrollment.parents.size() > 0 ? 1 : 0",
        "r'''embedded ' quote''' != \"x\" || enrollment.parents.size() > 0 ? 1 : 0",
        "enrollment // comment hides trivia\n . parents.size() > 0 ? 1 : 0",
    ] {
        claim.rule = RuleConfig::Cel {
            expression: expression.to_string(),
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
fn registry_cel_startup_accepts_a_bounded_string_output_below_nine_bytes() {
    let mut claim = registry_claim(
        "short-code",
        RuleConfig::Cel {
            expression: "enrollment.registration_status".to_string(),
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
fn cel_regex_usage_scanner_ignores_literal_decoys() {
    assert!(cel_expression_uses_regex(
        "enrollment.name.matches('^A')"
    ));
    assert!(cel_expression_uses_regex(
        "text.regex_replace(enrollment.name, '^A', 'B')"
    ));
    assert!(cel_expression_uses_regex(
        "text . regex_replace(enrollment.name, '^A', 'B')"
    ));
    assert!(cel_expression_uses_regex(
        "text. regex_extract(enrollment.name, '^(.+)$', 1)"
    ));
    assert!(cel_expression_uses_regex(
        "text_regex_extract(enrollment.name, '^(.+)$', 1)"
    ));
    assert!(cel_expression_uses_regex(
        "validate.matches(enrollment.name, '^A', 'bad')"
    ));
    assert!(!cel_expression_uses_regex(
        "'text.regex_replace(enrollment.name, pattern)'"
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
