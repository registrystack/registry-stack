// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;

    fn run_code_owned_project_conformance(project: &Path) -> Result<Vec<FixtureReport>> {
        let loaded = load_registry_project(project, None)?;
        run_code_owned_loaded_project_conformance(&loaded)
    }

    fn run_code_owned_loaded_project_conformance(
        loaded: &LoadedRegistryProject,
    ) -> Result<Vec<FixtureReport>> {
        let offline_environment = offline_fixture_environment(loaded)?;
        let compiled = compile_project_for_environment(
            loaded,
            "offline-fixture",
            &offline_environment,
            None,
        )?;
        let relay_config = compiled
            .relay_private
            .get(Path::new("config/relay.yaml"))
            .ok_or_else(|| anyhow!("generated Relay config is absent"))?;
        // This structural compiler bypass is selected only by this cfg(test)
        // harness. No authored field, CLI flag, environment variable, startup
        // path, or runtime API can request it.
        compile_generated_relay_fixture(relay_config, &compiled.relay_private).map(drop)?;
        validate_generated_notary(&compiled)?;
        let reports = execute_all_fixtures(loaded, &compiled)?;
        require_passing_fixtures(&reports)?;
        Ok(reports)
    }

    fn project_golden(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/project-authoring")
            .join(name)
    }

    #[test]
    fn code_owned_rhai_conformance_matches_http_and_is_deterministic() {
        let bounded = run_code_owned_project_conformance(&project_golden("dhis2-tracker"))
            .expect("bounded DHIS2 conformance passes");
        let rhai_project = project_golden("dhis2-sandboxed-rhai");
        let rhai = run_code_owned_project_conformance(&rhai_project)
            .expect("Rhai DHIS2 conformance passes");
        let repeated = run_code_owned_project_conformance(&rhai_project)
            .expect("repeated Rhai DHIS2 conformance passes");
        let mut unknown_product =
            load_registry_project(&rhai_project, None).expect("Rhai golden loads");
        unknown_product
            .integrations
            .get_mut("health-record")
            .expect("Rhai integration exists")
            .document
            .source
            .product = "previously-unknown-source-system".to_string();
        let unknown_product_report = run_code_owned_loaded_project_conformance(&unknown_product)
            .expect("unknown product uses the same Rhai authoring contract");
        assert_eq!(
            serde_json::to_value(&unknown_product_report)
                .expect("unknown-product report serializes"),
            serde_json::to_value(&rhai).expect("Rhai report serializes"),
            "source.product may alter provenance but not Rhai fixture behavior"
        );
        assert_eq!(
            serde_json::to_value(&rhai).expect("first Rhai report serializes"),
            serde_json::to_value(&repeated).expect("repeated Rhai report serializes"),
            "fresh one-shot workers must produce deterministic fixture reports"
        );

        let rhai_by_name = rhai
            .iter()
            .map(|fixture| (fixture.fixture.as_str(), fixture))
            .collect::<BTreeMap<_, _>>();
        for expected in &bounded {
            let actual = rhai_by_name
                .get(expected.fixture.as_str())
                .unwrap_or_else(|| panic!("Rhai omitted fixture {}", expected.fixture));
            assert_eq!(
                actual.inputs, expected.inputs,
                "{} inputs",
                expected.fixture
            );
            assert_eq!(actual.calls, expected.calls, "{} calls", expected.fixture);
            assert_eq!(actual.outputs, expected.outputs, "{} outputs", expected.fixture);
            assert_eq!(
                actual.claims, expected.claims,
                "{} claims",
                expected.fixture
            );
            assert_eq!(
                actual.outcome, expected.outcome,
                "{} outcome",
                expected.fixture
            );
            assert_eq!(
                actual.passed, expected.passed,
                "{} result",
                expected.fixture
            );
        }
    }

    #[test]
    fn generated_relay_rejects_independent_raw_and_typed_binding_tampering() {
        let project = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/project-authoring/custom-system");
        let loaded = load_registry_project(&project, Some("local")).expect("golden project loads");
        let compiled = compile_project(&loaded, None).expect("golden project compiles");
        let relay = compiled
            .relay_private
            .get(Path::new("config/relay.yaml"))
            .expect("Relay config exists");
        let original: Value = serde_yaml::from_slice(relay).expect("Relay config parses");

        for field in ["sha256", "hash"] {
            let mut tampered = original.clone();
            tampered["consultation"]["artifacts"]["private_bindings"][0][field] =
                Value::String(format!("sha256:{}", "0".repeat(64)));
            let bytes = serde_yaml::to_string(&tampered).expect("tampered config serializes");
            let error = validate_generated_relay(bytes.as_bytes(), &compiled.relay_private)
                .expect_err("tampered binding pin must fail closed");
            let diagnostic = format!("{error:#}");
            assert!(
                diagnostic.contains("binding")
                    || diagnostic.contains("generated Relay config failed production loading"),
                "unexpected {field} diagnostic: {diagnostic}"
            );
        }
    }

    #[test]
    fn governed_live_result_requires_exact_disclosure_and_source_provenance() {
        let claims = vec!["eligible".to_string()];
        let expected = json!({ "claims": { "eligible": { "satisfied": true } } });
        let response = json!({
            "results": [{
                "claim_id": "eligible",
                "satisfied": true,
                "provenance": { "used": { "source_count": 1 } },
            }],
        });
        assert_eq!(
            validate_live_response(&response, &claims, &expected).expect("exact result passes"),
            claims
        );

        let mut missing_provenance = response;
        missing_provenance["results"][0]["provenance"]["used"]["source_count"] = json!(0);
        assert!(
            validate_live_response(&missing_provenance, &claims, &expected)
                .expect_err("source-free result must fail")
                .to_string()
                .contains("source-backed provenance")
        );
    }

    #[test]
    fn cel_consultation_roots_ignore_string_literals() {
        assert_eq!(
            cel_member_roots("'decoy.exists' == 'x' && person.exists").expect("CEL roots parse"),
            BTreeSet::from(["person".to_string()])
        );
        assert!(cel_member_roots("person.exists && 'unterminated").is_err());
    }

    #[test]
    fn secret_descriptor_includes_named_environment_providers() {
        let descriptor = secret_consumer_descriptor(
            "registry-notary",
            &json!({
                "authentication": {
                    "fingerprint": { "provider": "env", "name": "CALLER_TOKEN_HASH" },
                },
                "audit": {
                    "source": {
                        "provider": "environment",
                        "name": "AUDIT_PSEUDONYM_EPOCH_1",
                    },
                },
            }),
        );
        let consumers = descriptor["consumers"]
            .as_array()
            .expect("descriptor consumers are present");
        assert!(consumers.iter().any(|consumer| {
            consumer["locator"] == "CALLER_TOKEN_HASH"
                && consumer["config_pointer"] == "/authentication/fingerprint/name"
        }));
        assert!(consumers.iter().any(|consumer| {
            consumer["locator"] == "AUDIT_PSEUDONYM_EPOCH_1"
                && consumer["config_pointer"] == "/audit/source/name"
        }));
    }

    #[test]
    fn released_rhai_capability_identity_is_not_a_source_product() {
        assert!(is_script_runtime_released(
            ReleasedScriptRuntime::RhaiV1
        ));
        assert!(!is_script_runtime_released_in(
            ReleasedScriptRuntime::RhaiV1,
            &[]
        ));
    }

    #[test]
    fn live_request_resolves_claims_across_services_with_the_same_purpose() {
        let project = project_golden("custom-system");
        let mut loaded = load_registry_project(&project, None).expect("golden project loads");
        let original_id = "household-eligibility";
        let mut second: ServiceDeclaration = serde_json::from_value(
            serde_json::to_value(&loaded.project.services[original_id])
                .expect("service serializes"),
        )
        .expect("service clones through its strict model");
        let second_claim = second
            .claims
            .remove("household-category")
            .expect("second service claim exists");
        second.claims.clear();
        second
            .claims
            .insert("household-category".to_string(), second_claim);
        loaded
            .project
            .services
            .get_mut(original_id)
            .expect("original service exists")
            .claims
            .remove("household-category");
        loaded
            .project
            .services
            .insert("zz-secondary-service".to_string(), second);
        for service_id in [original_id, "zz-secondary-service"] {
            let service = loaded
                .project
                .services
                .get_mut(service_id)
                .expect("split service exists");
            let claims = service.claims.keys().cloned().collect::<BTreeSet<_>>();
            for credential in service.credentials.values_mut() {
                credential.claims.retain(|claim| claims.contains(claim));
            }
        }
        validate_project_shape(&loaded.project).expect("split service project remains valid");
        let offline_environment =
            offline_fixture_environment(&loaded).expect("offline environment compiles");
        let compiled = compile_project_for_environment(
            &loaded,
            "offline-fixture",
            &offline_environment,
            None,
        )
        .expect("split service project compiles");
        validate_generated_notary(&compiled).expect("split service Notary config activates");

        let claims = validate_live_request(
            &loaded,
            &json!({
                "purpose": "household-support-screening",
                "claims": ["household-category", "household-eligible"],
            }),
        )
        .expect("claims from both same-purpose services are valid");
        assert_eq!(claims, ["household-category", "household-eligible"]);
    }

    #[test]
    fn duplicate_project_claim_ids_fail_before_generation() {
        let project = project_golden("custom-system");
        let mut loaded = load_registry_project(&project, None).expect("golden project loads");
        let duplicate: ServiceDeclaration = serde_json::from_value(
            serde_json::to_value(&loaded.project.services["household-eligibility"])
                .expect("service serializes"),
        )
        .expect("service clones through its strict model");
        loaded
            .project
            .services
            .insert("duplicate-service".to_string(), duplicate);
        let error = validate_project_shape(&loaded.project)
            .expect_err("duplicate project claim ids must fail closed");
        assert!(error
            .to_string()
            .contains("claim ids must be unique across project services"));
    }

    #[test]
    fn disclosure_review_classes_are_directional() {
        let loaded = load_registry_project(&project_golden("custom-system"), None)
            .expect("golden project loads");
        let original = disclosure_review_profiles(&loaded.project);
        let baseline = json!({ "disclosure_profiles": original });

        let mut narrowed = disclosure_review_profiles(&loaded.project);
        narrowed
            .get_mut("household-eligibility")
            .expect("service profile exists")
            .insert(
                "household-category".to_string(),
                DisclosureReviewProfile {
                    default: DisclosureMode::Redacted,
                    allowed: BTreeSet::from([DisclosureMode::Redacted]),
                },
            );
        assert_eq!(
            disclosure_change_classes(&narrowed, Some(&baseline)),
            (true, false)
        );

        let mut widened = disclosure_review_profiles(&loaded.project);
        widened
            .get_mut("household-eligibility")
            .expect("service profile exists")
            .insert(
                "household-record-exists".to_string(),
                DisclosureReviewProfile {
                    default: DisclosureMode::Value,
                    allowed: BTreeSet::from([DisclosureMode::Value, DisclosureMode::Redacted]),
                },
            );
        assert_eq!(
            disclosure_change_classes(&widened, Some(&baseline)),
            (false, true)
        );

        let mut mixed = narrowed;
        mixed
            .get_mut("household-eligibility")
            .expect("service profile exists")
            .insert(
                "household-record-exists".to_string(),
                DisclosureReviewProfile {
                    default: DisclosureMode::Value,
                    allowed: BTreeSet::from([
                        DisclosureMode::Value,
                        DisclosureMode::Redacted,
                    ]),
                },
            );
        assert_eq!(
            disclosure_change_classes(&mixed, Some(&baseline)),
            (true, true)
        );
    }

    #[test]
    fn signed_review_record_validation_rejects_legacy_and_inconsistent_evidence() {
        let loaded = load_registry_project(&project_golden("custom-system"), Some("local"))
            .expect("golden project loads");
        let review = compile_project(&loaded, None)
            .expect("golden project compiles")
            .review;
        validate_signed_review_record(&review).expect("current review record is valid");

        let mut legacy = review.clone();
        legacy
            .as_object_mut()
            .expect("review is an object")
            .remove("review_digests");
        assert!(validate_signed_review_record(&legacy)
            .expect_err("legacy record without review evidence must fail")
            .to_string()
            .contains("missing or unknown fields"));

        let mut malformed = review.clone();
        malformed["review_digests"] = json!([]);
        assert!(validate_signed_review_record(&malformed)
            .expect_err("malformed review evidence must fail")
            .to_string()
            .contains("must be an object"));

        let mut missing_required = review.clone();
        missing_required["review_digests"]["claim"] = Value::Null;
        assert!(validate_signed_review_record(&missing_required)
            .expect_err("required review without a digest must fail")
            .to_string()
            .contains("do not match required_reviews"));

        let mut mismatched_review_digest = review.clone();
        mismatched_review_digest["review_digests"]["claim"] =
            Value::String(format!("sha256:{}", "0".repeat(64)));
        assert!(validate_signed_review_record(&mismatched_review_digest)
            .expect_err("review evidence must bind its signed inputs")
            .to_string()
            .contains("does not match its signed review inputs"));

        let mut malformed_nested_baseline = review.clone();
        malformed_nested_baseline["baseline"] = json!({});
        assert!(validate_signed_review_record(&malformed_nested_baseline)
            .expect_err("nested baseline summary must remain closed")
            .to_string()
            .contains("missing or unknown fields"));

        let mut mismatched_disclosure = review;
        mismatched_disclosure["disclosure_digest"] =
            Value::String(format!("sha256:{}", "0".repeat(64)));
        assert!(validate_signed_review_record(&mismatched_disclosure)
            .expect_err("disclosure profiles and digest must stay bound")
            .to_string()
            .contains("does not match its profiles"));
    }
}
