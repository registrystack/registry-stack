// SPDX-License-Identifier: Apache-2.0

    #[test]
    fn matching_pdp_decision_uses_shared_contract() {
        let mut binding = test_source_binding();
        binding.matching.allowed_purposes = vec!["benefits".to_string(), "appeals".to_string()];
        binding.matching.allowed_assurance = vec!["substantial".to_string()];
        let mut context = EvidenceRequestContext {
            requester: None,
            target: EvidenceEntity {
                entity_type: "Person".to_string(),
                id: Some("person-1".to_string()),
                identifiers: Vec::new(),
                attributes: BTreeMap::new(),
                assurance: Some(registry_notary_core::EvidenceAssurance {
                    method: None,
                    level_scheme: None,
                    level: Some("substantial".to_string()),
                    verified_at: None,
                    issuer: None,
                    evidence: Vec::new(),
                }),
                profile: None,
            },
            relationship: None,
            on_behalf_of: None,
        };

        let default_trusted_policy = TrustedPolicyContext::default();
        let evidence = EvidenceConfig::default();
        expect_pdp_denial(
            matching_pdp_decision(
                &evidence,
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &default_trusted_policy,
                &[],
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_CLAIM_RESULT_JSON,
                None,
                false,
            ),
            registry_platform_pdp::ASSURANCE_INSUFFICIENT,
        );
        expect_pdp_denial(
            matching_pdp_decision(
                &evidence,
                &binding,
                &machine_capability(&[]),
                &context,
                "marketing",
                &default_trusted_policy,
                &[],
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_CLAIM_RESULT_JSON,
                None,
                false,
            ),
            registry_platform_pdp::PURPOSE_NOT_PERMITTED,
        );
        context.target.assurance.as_mut().expect("assurance").level =
            Some("substantial".to_string());
        expect_pdp_denial(
            matching_pdp_decision(
                &evidence,
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &default_trusted_policy,
                &[],
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_CLAIM_RESULT_JSON,
                None,
                false,
            ),
            registry_platform_pdp::ASSURANCE_INSUFFICIENT,
        );
        let trusted_policy = TrustedPolicyContext {
            assurance_level: Some("substantial".to_string()),
            ..TrustedPolicyContext::default()
        };
        let effect = expect_pdp_permit(matching_pdp_decision(
            &evidence,
            &binding,
            &machine_capability(&[]),
            &context,
            "benefits",
            &trusted_policy,
            &[],
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            None,
            false,
        ));
        assert_eq!(
            effect,
            BindingPolicyEffect {
                redaction_fields: BTreeSet::new(),
                audit: Some(PdpDecisionAudit {
                    policy_id: matching_purpose_policy_id(&binding),
                    policy_hash: matching_purpose_policy_hash(&binding),
                    evaluated_rule_ids: matching_gate_rule_ids(
                        &["pdp.purpose", "pdp.assurance_allowed_set"],
                        false,
                    ),
                    route_identity: Some("registry-notary.evaluate".to_string()),
                    source_binding: Some("default:people:person".to_string()),
                    trust_provenance: BTreeSet::from(["asserted_assurance".to_string()]),
                    ..PdpDecisionAudit::default()
                })
            }
        );

        binding.matching.permitted_jurisdictions = vec!["RW".to_string()];
        binding.matching.require_legal_basis = true;
        binding.matching.require_consent = true;
        binding.matching.redaction_fields = vec!["value".to_string()];
        let trusted_policy = TrustedPolicyContext {
            legal_basis_ref: Some("legal-basis:benefits".to_string()),
            consent_ref: Some("consent:person-1".to_string()),
            jurisdiction: Some("RW".to_string()),
            assurance_level: Some("substantial".to_string()),
            ..TrustedPolicyContext::default()
        };
        let effect = expect_pdp_permit(matching_pdp_decision(
            &evidence,
            &binding,
            &machine_capability(&[]),
            &context,
            "benefits",
            &trusted_policy,
            &[],
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            None,
            false,
        ));
        assert_eq!(
            effect,
            BindingPolicyEffect {
                redaction_fields: BTreeSet::from(["value".to_string()]),
                audit: Some(PdpDecisionAudit {
                    policy_id: matching_purpose_policy_id(&binding),
                    policy_hash: matching_purpose_policy_hash(&binding),
                    evaluated_rule_ids: matching_gate_rule_ids(
                        &[
                            "pdp.purpose",
                            "pdp.jurisdiction",
                            "pdp.assurance_allowed_set",
                            "pdp.legal_basis_required",
                            "pdp.consent_required",
                        ],
                        true,
                    ),
                    route_identity: Some("registry-notary.evaluate".to_string()),
                    source_binding: Some("default:people:person".to_string()),
                    trust_provenance: BTreeSet::from([
                        "asserted_assurance".to_string(),
                        "consent_ref".to_string(),
                        "jurisdiction".to_string(),
                        "legal_basis_ref".to_string(),
                    ]),
                    ..PdpDecisionAudit::default()
                })
            }
        );
        assert!(matching_purpose_policy_hash(&binding).starts_with("sha256:"));

        binding.matching.allowed_legal_basis_refs = vec!["legal-basis:other".to_string()];
        expect_pdp_denial(
            matching_pdp_decision(
                &evidence,
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &trusted_policy,
                &[],
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_CLAIM_RESULT_JSON,
                None,
                false,
            ),
            registry_platform_pdp::LEGAL_BASIS_REQUIRED,
        );

        binding.matching.allowed_legal_basis_refs = vec!["legal-basis:benefits".to_string()];
        binding.matching.allowed_consent_refs = vec!["consent:other".to_string()];
        expect_pdp_denial(
            matching_pdp_decision(
                &evidence,
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &trusted_policy,
                &[],
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_CLAIM_RESULT_JSON,
                None,
                false,
            ),
            registry_platform_pdp::CONSENT_REQUIRED,
        );

        binding.matching.allowed_consent_refs = vec!["consent:person-1".to_string()];
        let effect = expect_pdp_permit(matching_pdp_decision(
            &evidence,
            &binding,
            &machine_capability(&[]),
            &context,
            "benefits",
            &trusted_policy,
            &[],
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            None,
            false,
        ));
        assert_eq!(
            effect.audit.expect("permit audit").evaluated_rule_ids,
            matching_gate_rule_ids(
                &[
                    "pdp.purpose",
                    "pdp.jurisdiction",
                    "pdp.assurance_allowed_set",
                    "pdp.legal_basis_required",
                    "pdp.consent_required",
                    "pdp.legal_basis_allowed_set",
                    "pdp.consent_allowed_set",
                ],
                true,
            )
        );
    }

    #[test]
    fn default_matching_pdp_decision_records_permit_audit() {
        let binding = test_source_binding();
        let purpose_constraints = test_purpose_constraints("benefits");
        let context = EvidenceRequestContext {
            requester: None,
            target: EvidenceEntity::new("Person"),
            relationship: None,
            on_behalf_of: None,
        };

        let effect = expect_pdp_permit(matching_pdp_decision(
            &EvidenceConfig::default(),
            &binding,
            &machine_capability(&[]),
            &context,
            "benefits",
            &TrustedPolicyContext::default(),
            &purpose_constraints,
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            None,
            false,
        ));
        assert_eq!(
            effect,
            BindingPolicyEffect {
                redaction_fields: BTreeSet::new(),
                audit: Some(PdpDecisionAudit {
                    policy_id: matching_purpose_policy_id(&binding),
                    policy_hash: matching_purpose_policy_hash(&binding),
                    evaluated_rule_ids: matching_gate_rule_ids(&["pdp.purpose"], false),
                    route_identity: Some("registry-notary.evaluate".to_string()),
                    source_binding: Some("default:people:person".to_string()),
                    ..PdpDecisionAudit::default()
                })
            }
        );
    }

    #[test]
    fn self_attestation_matching_pdp_uses_source_capability_instead_of_machine_scope() {
        let mut binding = test_source_binding();
        binding.required_scope = Some("people:evidence_verification".to_string());
        let purpose_constraints = test_purpose_constraints("benefits");
        let context = EvidenceRequestContext {
            requester: None,
            target: EvidenceEntity::new("Person"),
            relationship: None,
            on_behalf_of: None,
        };

        expect_pdp_denial(
            matching_pdp_decision(
                &EvidenceConfig::default(),
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &TrustedPolicyContext::default(),
                &purpose_constraints,
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_CLAIM_RESULT_JSON,
                None,
                false,
            ),
            registry_platform_pdp::CHECKED_SCOPE_REQUIRED,
        );

        let trusted_policy = TrustedPolicyContext {
            checked_scopes: BTreeSet::from(["people:evidence_verification".to_string()]),
            ..TrustedPolicyContext::default()
        };
        let machine_effect = expect_pdp_permit(matching_pdp_decision(
            &EvidenceConfig::default(),
            &binding,
            &machine_capability(&["people:evidence_verification"]),
            &context,
            "benefits",
            &trusted_policy,
            &purpose_constraints,
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            None,
            false,
        ));
        assert!(machine_effect
            .audit
            .expect("machine permit carries PDP audit")
            .evaluated_rule_ids
            .contains(&"source-binding-policy:person.checked_scope".to_string()));

        let self_attestation_effect = expect_pdp_permit(matching_pdp_decision(
            &EvidenceConfig::default(),
            &binding,
            &self_attestation_capability("person-is-alive"),
            &context,
            "benefits",
            &TrustedPolicyContext::default(),
            &purpose_constraints,
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            None,
            false,
        ));
        assert!(!self_attestation_effect
            .audit
            .expect("self-attestation permit carries PDP audit")
            .evaluated_rule_ids
            .contains(&"source-binding-policy:person.checked_scope".to_string()));
    }

    #[test]
    fn matching_pdp_decision_enforces_requested_disclosure_and_format() {
        let binding = test_source_binding();
        let purpose_constraints = test_purpose_constraints("benefits");
        let context = EvidenceRequestContext {
            requester: None,
            target: EvidenceEntity::new("Person"),
            relationship: None,
            on_behalf_of: None,
        };

        expect_pdp_denial(
            matching_pdp_decision(
                &EvidenceConfig::default(),
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &TrustedPolicyContext::default(),
                &purpose_constraints,
                &["value".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Predicate,
                FORMAT_CLAIM_RESULT_JSON,
                None,
                false,
            ),
            registry_platform_pdp::DISCLOSURE_NOT_PERMITTED,
        );
        expect_pdp_denial(
            matching_pdp_decision(
                &EvidenceConfig::default(),
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &TrustedPolicyContext::default(),
                &purpose_constraints,
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_SD_JWT_VC,
                None,
                false,
            ),
            registry_platform_pdp::CREDENTIAL_FORMAT_NOT_PERMITTED,
        );
    }

    #[test]
    fn matching_pdp_decision_enforces_source_freshness_only_when_requested() {
        let mut binding = test_source_binding();
        binding.matching.max_source_age_seconds = Some(60);
        let purpose_constraints = test_purpose_constraints("benefits");
        let context = EvidenceRequestContext {
            requester: None,
            target: EvidenceEntity::new("Person"),
            relationship: None,
            on_behalf_of: None,
        };

        let effect = expect_pdp_permit(matching_pdp_decision(
            &EvidenceConfig::default(),
            &binding,
            &machine_capability(&[]),
            &context,
            "benefits",
            &TrustedPolicyContext::default(),
            &purpose_constraints,
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            None,
            false,
        ));
        assert_eq!(
            effect,
            BindingPolicyEffect {
                redaction_fields: BTreeSet::new(),
                audit: Some(PdpDecisionAudit {
                    policy_id: matching_purpose_policy_id(&binding),
                    policy_hash: matching_purpose_policy_hash(&binding),
                    evaluated_rule_ids: matching_gate_rule_ids(&["pdp.purpose"], false),
                    route_identity: Some("registry-notary.evaluate".to_string()),
                    source_binding: Some("default:people:person".to_string()),
                    ..PdpDecisionAudit::default()
                })
            }
        );
        expect_pdp_denial(
            matching_pdp_decision(
                &EvidenceConfig::default(),
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &TrustedPolicyContext::default(),
                &purpose_constraints,
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_CLAIM_RESULT_JSON,
                None,
                true,
            ),
            registry_platform_pdp::EVIDENCE_STALE,
        );
        expect_pdp_denial(
            matching_pdp_decision(
                &EvidenceConfig::default(),
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &TrustedPolicyContext::default(),
                &purpose_constraints,
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_CLAIM_RESULT_JSON,
                Some(61),
                true,
            ),
            registry_platform_pdp::EVIDENCE_STALE,
        );
        let mut evidence = EvidenceConfig::default();
        evidence.ecosystem_bindings.insert(
            "oots-birth-evidence/v1".to_string(),
            registry_notary_core::EvidenceEcosystemBindingConfig {
                profile: Some("registry-notary/source-policy/v1".to_string()),
                policy_id: "lab.oots-birth-evidence.governed-evidence.v1".to_string(),
                policy_hash:
                    "sha256:6666666666666666666666666666666666666666666666666666666666666666"
                        .to_string(),
                unsupported_odrl_terms: Vec::new(),
            },
        );
        binding.matching.ecosystem_binding =
            Some(registry_notary_core::EcosystemBindingSelectorConfig {
                id: Some("oots-birth-evidence/v1".to_string()),
                pack_id: Some("oots-birth-evidence/v1".to_string()),
                pack_version: Some("v1".to_string()),
                ..registry_notary_core::EcosystemBindingSelectorConfig::default()
            });
        let stale = matching_pdp_decision(
            &evidence,
            &binding,
            &machine_capability(&[]),
            &context,
            "benefits",
            &TrustedPolicyContext::default(),
            &purpose_constraints,
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            Some(61),
            true,
        )
        .expect_err("stale source denies with selected pack policy");
        let EvidenceError::PolicyDenied {
            code,
            policy_id: Some(policy_id),
            policy_hash: Some(policy_hash),
            ..
        } = stale
        else {
            panic!("expected pack-backed stale PolicyDenied");
        };
        assert_eq!(code, registry_platform_pdp::EVIDENCE_STALE);
        assert_eq!(policy_id, "lab.oots-birth-evidence.governed-evidence.v1");
        assert_eq!(
            policy_hash,
            "sha256:6666666666666666666666666666666666666666666666666666666666666666"
        );
        assert!(matching_pdp_decision(
            &EvidenceConfig::default(),
            &binding,
            &machine_capability(&[]),
            &context,
            "benefits",
            &TrustedPolicyContext::default(),
            &purpose_constraints,
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            Some(60),
            true
        )
        .is_ok());
    }

    #[test]
    fn matching_policy_validation_preserves_stable_pdp_denials() {
        let mut binding = test_source_binding();
        binding.matching.allowed_purposes = vec!["benefits".to_string()];
        let context = EvidenceRequestContext {
            requester: None,
            target: EvidenceEntity::new("Person"),
            relationship: None,
            on_behalf_of: None,
        };
        let default_trusted_policy = TrustedPolicyContext::default();

        let error = validate_matching_policy(
            &EvidenceConfig::default(),
            &machine_capability(&[]),
            &[],
            &binding,
            &context,
            "marketing",
            &default_trusted_policy,
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
        )
        .expect_err("wrong purpose must be a stable PDP denial");
        assert!(matches!(
            error,
            EvidenceError::PolicyDenied {
                code: registry_platform_pdp::PURPOSE_NOT_PERMITTED,
                ..
            }
        ));

        binding.matching.allowed_assurance = vec!["substantial".to_string()];
        let error = validate_matching_policy(
            &EvidenceConfig::default(),
            &machine_capability(&[]),
            &[],
            &binding,
            &context,
            "benefits",
            &default_trusted_policy,
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
        )
        .expect_err("insufficient assurance must be a stable PDP denial");
        assert!(matches!(
            error,
            EvidenceError::PolicyDenied {
                code: registry_platform_pdp::ASSURANCE_INSUFFICIENT,
                ..
            }
        ));

        binding.matching.max_source_age_seconds = Some(60);
        let error = validate_matching_freshness_policy(
            &EvidenceConfig::default(),
            &binding,
            &machine_capability(&[]),
            &context,
            "benefits",
            &TrustedPolicyContext {
                assurance_level: Some("substantial".to_string()),
                ..TrustedPolicyContext::default()
            },
            &[],
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            None,
        )
        .expect_err("missing source observation age must be a stable PDP denial");
        assert!(matches!(
            error,
            EvidenceError::PolicyDenied {
                code: registry_platform_pdp::EVIDENCE_STALE,
                ..
            }
        ));

        binding.matching.collapse_matching_errors = true;
        assert!(matches!(
            collapse_matching_error(
                &binding,
                EvidenceError::PolicyDenied {
                    code: registry_platform_pdp::EVIDENCE_STALE,
                    policy_id: None,
                    policy_hash: None,
                    evaluated_rule_ids: Vec::new(),
                },
            ),
            EvidenceError::PolicyDenied {
                code: registry_platform_pdp::EVIDENCE_STALE,
                ..
            }
        ));
    }

    #[test]
    fn matching_pdp_decision_uses_selected_evidence_pack_identity() {
        let mut evidence = EvidenceConfig::default();
        evidence.ecosystem_bindings.insert(
            "civil-pack/v1".to_string(),
            registry_notary_core::EvidenceEcosystemBindingConfig {
                profile: Some("registry-notary/source-policy/v1".to_string()),
                policy_id: "evidence-pack-policy".to_string(),
                policy_hash:
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
                unsupported_odrl_terms: Vec::new(),
            },
        );
        let mut binding = test_source_binding();
        binding.matching.ecosystem_binding =
            Some(registry_notary_core::EcosystemBindingSelectorConfig {
                id: Some("civil-pack/v1".to_string()),
                pack_id: Some("oots-birth-evidence/v1".to_string()),
                pack_version: Some("v1".to_string()),
                ..registry_notary_core::EcosystemBindingSelectorConfig::default()
            });
        let context = EvidenceRequestContext {
            requester: None,
            target: EvidenceEntity::new("Person"),
            relationship: None,
            on_behalf_of: None,
        };
        let purpose_constraints = test_purpose_constraints("benefits");

        let selected =
            selected_evidence_pack_policy(&evidence, &binding).expect("selected policy resolves");
        assert_eq!(selected.policy_id, "evidence-pack-policy");
        assert_eq!(selected.pack_id.as_deref(), Some("oots-birth-evidence/v1"));
        assert_eq!(selected.pack_version.as_deref(), Some("v1"));
        assert_eq!(
            selected.policy_hash,
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        let effect = expect_pdp_permit(matching_pdp_decision(
            &evidence,
            &binding,
            &machine_capability(&[]),
            &context,
            "benefits",
            &TrustedPolicyContext::default(),
            &purpose_constraints,
            &["value".to_string(), "predicate".to_string()],
            &[FORMAT_CLAIM_RESULT_JSON.to_string()],
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
            None,
            false,
        ));
        assert_eq!(
            effect,
            BindingPolicyEffect {
                redaction_fields: BTreeSet::new(),
                audit: Some(PdpDecisionAudit {
                    policy_id: "evidence-pack-policy".to_string(),
                    policy_hash:
                        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                            .to_string(),
                    evaluated_rule_ids: matching_gate_rule_ids(&["pdp.purpose"], false),
                    ecosystem_binding_id: Some("civil-pack/v1".to_string()),
                    ecosystem_binding_version: Some("v1".to_string()),
                    route_identity: Some("registry-notary.evaluate".to_string()),
                    source_binding: Some("default:people:person".to_string()),
                    ..PdpDecisionAudit::default()
                })
            }
        );
        let identity = matching_policy_audit_identity(&evidence, &binding);
        assert_eq!(identity.pack_id.as_deref(), Some("oots-birth-evidence/v1"));
        assert_eq!(identity.pack_version.as_deref(), Some("v1"));

        evidence
            .ecosystem_bindings
            .get_mut("civil-pack/v1")
            .expect("binding exists")
            .unsupported_odrl_terms = vec!["odrl:targetPolicy".to_string()];
        expect_pdp_denial(
            matching_pdp_decision(
                &evidence,
                &binding,
                &machine_capability(&[]),
                &context,
                "benefits",
                &TrustedPolicyContext::default(),
                &purpose_constraints,
                &["value".to_string(), "predicate".to_string()],
                &[FORMAT_CLAIM_RESULT_JSON.to_string()],
                DisclosureProfile::Value,
                FORMAT_CLAIM_RESULT_JSON,
                None,
                false,
            ),
            registry_platform_pdp::UNSUPPORTED_POLICY_TERM,
        );
    }
