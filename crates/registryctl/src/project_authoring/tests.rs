// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_starter_provenance_matches_authored_content() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let starters = [
            ("http", manifest_dir.join("assets/project-starters/bounded-http")),
            (
                "dhis2-tracker",
                manifest_dir.join("tests/fixtures/project-authoring/dhis2-tracker"),
            ),
            (
                "opencrvs-dci",
                manifest_dir.join("tests/fixtures/project-authoring/opencrvs"),
            ),
            (
                "fhir-r4",
                manifest_dir.join(
                    "tests/fixtures/project-authoring/fhir-r4-coverage-active",
                ),
            ),
            (
                "snapshot",
                manifest_dir.join("tests/fixtures/project-authoring/snapshot-exact"),
            ),
        ];
        let mut mismatches = Vec::new();
        for (expected_id, path) in starters {
            let loaded = load_registry_project(&path, None).expect("starter loads");
            let provenance = loaded.project.starter.as_ref().expect("starter provenance");
            assert_eq!(provenance.id, expected_id);
            if provenance.content_digest != loaded.project_content_digest {
                mismatches.push(format!(
                    "{expected_id}: expected {}, calculated {}",
                    provenance.content_digest, loaded.project_content_digest
                ));
            }
        }
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }

    #[test]
    fn corrected_http_authoring_lowers_to_one_product_neutral_request() {
        let authored: AuthoredIntegrationDocument = serde_yaml::from_str(
            r#"
version: 1
id: person-status
revision: 1
source:
  product: previously-unknown-registry
  versions: { unverified: [deployment-api-7] }
  auth: { type: none }
input:
  person_id:
    role: selector
    type: string
    maxLength: 64
capability:
  http:
    request:
      method: GET
      path: /people/{input.person_id}
    response:
      no_match: [404]
outputs:
  active:
    type: boolean
    x-registry-source: /active
"#,
        )
        .expect("corrected http authoring parses");
        let lowered =
            lower_authored_integration(&authored).expect("corrected http authoring lowers");
        let CapabilityDeclaration::Http { http } = lowered.capability else {
            panic!("http capability remains http");
        };
        assert_eq!(http.operations.len(), 1);
        let operation = &http.operations["request"];
        let request = &operation.request;
        assert_eq!(request.path, "/people/{person_id}");
        assert_eq!(operation.response.max_bytes, 512 * 1024);
        assert!(matches!(
            operation.response.schema,
            SchemaNode::Object {
                additional_fields: AdditionalFields::Ignore,
                ..
            }
        ));
        assert_eq!(
            lowered.source.product.as_deref(),
            Some("previously-unknown-registry")
        );
        assert_eq!(lowered.outputs.len(), 1);
    }

    #[test]
    fn date_outputs_keep_the_typed_contract_without_a_string_bound() {
        let entity_field: EntityFieldSchema = serde_yaml::from_str(
            r#"type: string
format: date
maxLength: 10
"#,
        )
        .expect("date entity field parses");
        let (output_type, nullable, max_bytes) =
            entity_output_contract("birth_date", &entity_field).expect("date field lowers");
        assert_eq!(output_type, OutputType::Date);
        assert!(!nullable);
        assert_eq!(max_bytes, None);
        validate_snapshot_output(
            "birth_date",
            &OutputDeclaration {
                output_type,
                nullable,
                max_bytes,
                minimum: None,
                maximum: None,
                from: Some("snapshot.record.birth_date".to_string()),
                source_pointer: None,
            },
        )
        .expect("typed snapshot date validates");

        let authored: AuthoredIntegrationDocument = serde_yaml::from_str(
            r#"
version: 1
id: person-birth-date
revision: 1
source: { auth: { type: none } }
input:
  person_id: { role: selector, type: string, maxLength: 64 }
capability:
  http:
    request: { method: GET, path: '/people/{input.person_id}' }
outputs:
  birth_date:
    type: string
    format: date
    maxLength: 10
    x-registry-source: /birth_date
"#,
        )
        .expect("date HTTP authoring parses");
        let lowered = lower_authored_integration(&authored).expect("date HTTP authoring lowers");
        let output = &lowered.outputs["birth_date"];
        assert_eq!(output.output_type, OutputType::Date);
        assert_eq!(output.max_bytes, None);
        validate_output(output, integration_operations(&lowered))
            .expect("typed HTTP date validates");
    }

    #[test]
    fn corrected_authoring_rejects_the_superseded_operation_graph() {
        serde_yaml::from_str::<AuthoredIntegrationDocument>(
            r#"
version: 1
id: obsolete-flow
revision: 1
source:
  auth: { type: none }
input:
  person_id: { role: selector, type: string, maxLength: 64 }
capability:
  http:
    operations: {}
outputs:
  active: { type: boolean, x-registry-source: /active }
"#,
        )
        .expect_err("operation graph has no authoring alias");
    }

    #[test]
    fn typed_authoring_preserves_roles_scalar_contracts_and_conservative_bounds() {
        let authored: AuthoredIntegrationDocument = serde_yaml::from_str(
            r#"
version: 1
id: typed-person-status
revision: 3
source:
  product: generic-registry
  versions: { unverified: [api-1] }
  auth: { type: none }
input:
  person_id:
    role: selector
    type: string
    minLength: 4
    maxLength: 64
    pattern: '^[A-Z0-9]+$'
    enum: [ABCD, ABCD1234]
    const: ABCD1234
  as_of:
    role: selector
    type: string
    format: date
    minLength: 10
    maxLength: 10
  include_archived:
    role: parameter
    type: [boolean, "null"]
    enum: [true, false, null]
  page:
    role: parameter
    type: integer
    minimum: 1
    maximum: 9007199254740991
capability:
  http:
    request: { method: GET, path: '/people/{input.person_id}' }
outputs:
  active: { type: boolean, x-registry-source: /active }
"#,
        )
        .expect("typed authoring parses");
        let lowered = lower_authored_integration(&authored).expect("typed authoring lowers");
        let person_id = &lowered.input["person_id"];
        assert_eq!(person_id.role, AuthoredInputRole::Selector);
        assert_eq!(person_id.input_type, InputType::String);
        assert!(!person_id.nullable);
        assert_eq!(person_id.min_length, Some(4));
        assert_eq!(person_id.max_length, Some(64));
        assert_eq!(person_id.bytes, 256);
        assert_eq!(person_id.enum_values.as_ref().map(Vec::len), Some(2));
        assert_eq!(person_id.const_value, Some(json!("ABCD1234")));

        let as_of = &lowered.input["as_of"];
        assert_eq!(as_of.input_type, InputType::FullDate);
        assert_eq!(
            as_of.bytes, 10,
            "date uses its encoded bound, not maxLength * 4"
        );

        let boolean = &lowered.input["include_archived"];
        assert_eq!(boolean.role, AuthoredInputRole::Parameter);
        assert_eq!(boolean.input_type, InputType::Boolean);
        assert!(boolean.nullable);
        assert_eq!(boolean.bytes, 5);

        let integer = &lowered.input["page"];
        assert_eq!(integer.input_type, InputType::Integer);
        assert_eq!(integer.minimum, Some(1));
        assert_eq!(integer.maximum, Some(9_007_199_254_740_991));
        assert_eq!(integer.bytes, 16);
    }

    #[test]
    fn generated_input_slots_use_the_relay_closed_typed_shape() {
        let parameter = InputDeclaration {
            role: AuthoredInputRole::Parameter,
            input_type: InputType::Integer,
            nullable: true,
            max_length: None,
            min_length: None,
            bytes: 4,
            pattern: None,
            enum_values: None,
            const_value: None,
            canonicalization: Canonicalization::Identity,
            minimum: Some(-10),
            maximum: Some(20),
        };
        assert_eq!(
            relay_input_slot(&parameter).expect("typed Relay input slot lowers"),
            json!({
                "role": "parameter",
                "type": ["integer", "null"],
                "x-registry-canonicalization": "identity",
                "minimum": -10,
                "maximum": 20,
            })
        );
    }

    #[test]
    fn typed_input_limits_fail_closed() {
        let base = r#"
version: 1
id: bounded-inputs
revision: 1
source: { auth: { type: none } }
input:
  subject: { role: selector, type: string, maxLength: 64 }
capability:
  http:
    request: { method: GET, path: '/people/{input.subject}' }
outputs:
  active: { type: boolean, x-registry-source: /active }
"#;
        let nullable_selector = base.replace(
            "type: string, maxLength: 64",
            "type: [string, \"null\"], maxLength: 64",
        );
        let authored: AuthoredIntegrationDocument =
            serde_yaml::from_str(&nullable_selector).expect("nullable selector parses");
        assert!(lower_authored_integration(&authored)
            .expect_err("nullable selector rejects")
            .to_string()
            .contains("selector inputs cannot be nullable"));

        let unsafe_integer = base.replace(
            "type: string, maxLength: 64",
            "type: integer, minimum: -9007199254740992, maximum: 1",
        );
        let authored: AuthoredIntegrationDocument =
            serde_yaml::from_str(&unsafe_integer).expect("unsafe integer parses");
        assert!(lower_authored_integration(&authored)
            .expect_err("unsafe integer rejects")
            .to_string()
            .contains("Integer schema has incompatible constraints"));

        let oversized_selector = base.replace("maxLength: 64", "maxLength: 1025");
        let authored: AuthoredIntegrationDocument =
            serde_yaml::from_str(&oversized_selector).expect("oversized selector parses");
        assert!(lower_authored_integration(&authored)
            .expect_err("aggregate selector bytes reject")
            .to_string()
            .contains("exceeds 4096 bytes"));
    }

    #[test]
    fn typed_input_cardinality_accepts_sixteen_total_and_eight_selectors() {
        fn authored_with_inputs(selectors: usize, parameters: usize) -> String {
            let mut input = String::new();
            for index in 0..selectors {
                input.push_str(&format!(
                    "  selector_{index}: {{ role: selector, type: string, maxLength: 8 }}\n"
                ));
            }
            for index in 0..parameters {
                input.push_str(&format!(
                    "  parameter_{index}: {{ role: parameter, type: [boolean, \"null\"] }}\n"
                ));
            }
            format!(
                r#"
version: 1
id: composite-selector
revision: 1
source: {{ auth: {{ type: none }} }}
input:
{input}capability:
  http:
    request: {{ method: GET, path: /people }}
outputs:
  active: {{ type: boolean, x-registry-source: /active }}
"#
            )
        }

        let authored: AuthoredIntegrationDocument =
            serde_yaml::from_str(&authored_with_inputs(8, 8))
                .expect("maximum typed input map parses");
        assert_eq!(
            lower_authored_integration(&authored)
                .expect("eight selectors plus eight parameters lower")
                .input
                .len(),
            16
        );

        let authored: AuthoredIntegrationDocument =
            serde_yaml::from_str(&authored_with_inputs(9, 0)).expect("nine-selector map parses");
        assert!(lower_authored_integration(&authored)
            .expect_err("nine selectors reject")
            .to_string()
            .contains("between one and eight selectors"));

        let authored: AuthoredIntegrationDocument =
            serde_yaml::from_str(&authored_with_inputs(8, 9)).expect("seventeen-input map parses");
        assert!(lower_authored_integration(&authored)
            .expect_err("seventeen inputs reject")
            .to_string()
            .contains("between one and sixteen entries"));
    }

    fn run_code_owned_project_conformance(project: &Path) -> Result<Vec<FixtureReport>> {
        let loaded = load_registry_project(project, None)?;
        run_code_owned_loaded_project_conformance(&loaded)
    }

    fn run_code_owned_loaded_project_conformance(
        loaded: &LoadedRegistryProject,
    ) -> Result<Vec<FixtureReport>> {
        let offline_environment = offline_fixture_environment(loaded)?;
        let compiled =
            compile_project_for_environment(loaded, "offline-fixture", &offline_environment, None)?;
        let relay_config = compiled
            .relay_private
            .get(Path::new("config/relay.yaml"))
            .ok_or_else(|| anyhow!("generated Relay config is absent"))?;
        // This structural compiler bypass is selected only by this cfg(test)
        // harness. No authored field, CLI flag, environment variable, startup
        // path, or runtime API can request it.
        compile_generated_relay_fixture(relay_config, &compiled.relay_private).map(drop)?;
        validate_generated_notary(&compiled)?;
        let reports = execute_all_fixtures(loaded, &compiled, None, None, false)?;
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
        let rhai_project = project_golden("dhis2-script");
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
            .product = Some("previously-unknown-source-system".to_string());
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
            assert_eq!(
                actual.outputs, expected.outputs,
                "{} outputs",
                expected.fixture
            );
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
                "provenance": { "used": { "relay_consultation_count": 1 } },
            }],
        });
        assert_eq!(
            validate_live_response(&response, &claims, &expected).expect("exact result passes"),
            claims
        );

        let mut missing_provenance = response;
        missing_provenance["results"][0]["provenance"]["used"]["relay_consultation_count"] =
            json!(0);
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
        assert!(is_script_runtime_released(ReleasedScriptRuntime::RhaiV1));
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
            for credential in service.credential_profiles.values_mut() {
                credential.claims.retain(|claim| claims.contains(claim));
            }
        }
        validate_project_shape(&loaded.project).expect("split service project remains valid");
        let offline_environment =
            offline_fixture_environment(&loaded).expect("offline environment compiles");
        let compiled =
            compile_project_for_environment(&loaded, "offline-fixture", &offline_environment, None)
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
                    allowed: BTreeSet::from([DisclosureMode::Value, DisclosureMode::Redacted]),
                },
            );
        assert_eq!(
            disclosure_change_classes(&mixed, Some(&baseline)),
            (true, true)
        );
    }

    #[test]
    fn compiler_upgrade_is_reported_independently_of_authored_semantic_changes() {
        let loaded = load_registry_project(&project_golden("custom-system"), None)
            .expect("golden project loads");
        let disclosure_digest = format!("sha256:{}", "a".repeat(64));
        let baseline = json!({
            "compiler_version": "0.0.0",
            "semantic_digests": {
                "claim": format!("sha256:{}", "0".repeat(64)),
                "integration": loaded.semantic_digests.integration.as_str(),
                "service_policy": loaded.semantic_digests.service_policy.as_str(),
                "operator_security": loaded.semantic_digests.operator_security.as_str(),
            },
            "disclosure_digest": disclosure_digest,
        });
        assert_eq!(
            semantic_change_records(&loaded, Some(&baseline), &disclosure_digest)
                .into_iter()
                .map(|change| change.dimension)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["claim", "compiler"]),
        );
    }

    #[test]
    fn signed_review_and_approval_state_validation_are_closed_and_separate() {
        let loaded = load_registry_project(&project_golden("custom-system"), Some("local"))
            .expect("golden project loads");
        let compiled = compile_project(&loaded, None).expect("golden project compiles");
        let review = compiled.review;
        let approval_state = compiled.approval_state;
        validate_signed_review_record(&review).expect("current review record is valid");
        validate_signed_approval_state(&approval_state).expect("current approval state is valid");

        let mut leaked_digest = review.clone();
        leaked_digest
            .as_object_mut()
            .expect("review is an object")
            .insert(
                "semantic_digest".to_string(),
                Value::String(format!("sha256:{}", "0".repeat(64))),
            );
        assert!(validate_signed_review_record(&leaked_digest)
            .expect_err("public review with a lower-level digest must fail")
            .to_string()
            .contains("missing or unknown fields"));

        let mut nested_leak = review.clone();
        nested_leak["entity_materializations"]["leak"] = json!({
            "provider_hash": format!("sha256:{}", "0".repeat(64)),
        });
        assert!(validate_signed_review_record(&nested_leak)
            .expect_err("nested lower-level public hash must fail")
            .to_string()
            .contains("exposes lower-level hash or digest"));

        let mut missing_state = approval_state.clone();
        missing_state
            .as_object_mut()
            .expect("approval state is an object")
            .remove("semantic_digests");
        assert!(validate_signed_approval_state(&missing_state)
            .expect_err("approval state without semantic digests must fail")
            .to_string()
            .contains("missing or unknown fields"));

        let mut malformed_state = approval_state.clone();
        malformed_state["report_digest"] = Value::String("sha256:not-a-digest".to_string());
        assert!(validate_signed_approval_state(&malformed_state)
            .expect_err("malformed internal digest must fail")
            .to_string()
            .contains("must be a SHA-256 digest"));

        let mut malformed_nested_baseline = approval_state;
        malformed_nested_baseline["baseline"] = json!({});
        assert!(validate_signed_approval_state(&malformed_nested_baseline)
            .expect_err("nested baseline summary must remain closed")
            .to_string()
            .contains("missing or unknown fields"));
    }
}

#[test]
fn fixture_input_validation_uses_typed_values_and_explicit_null() {
    let boolean = InputDeclaration {
        role: AuthoredInputRole::Parameter,
        input_type: InputType::Boolean,
        nullable: true,
        max_length: None,
        min_length: None,
        bytes: 5,
        pattern: None,
        enum_values: Some(vec![json!(true), Value::Null]),
        const_value: None,
        canonicalization: Canonicalization::Identity,
        minimum: None,
        maximum: None,
    };
    validate_fixture_input_value("include_archived", &boolean, &json!(true))
        .expect("Boolean fixture value validates");
    validate_fixture_input_value("include_archived", &boolean, &Value::Null)
        .expect("explicit nullable parameter validates");
    assert!(validate_fixture_input_value("include_archived", &boolean, &json!(false)).is_err());
    assert!(validate_fixture_input_value("include_archived", &boolean, &json!("true")).is_err());

    let integer = InputDeclaration {
        role: AuthoredInputRole::Selector,
        input_type: InputType::Integer,
        nullable: false,
        max_length: None,
        min_length: None,
        bytes: 2,
        pattern: None,
        enum_values: None,
        const_value: None,
        canonicalization: Canonicalization::Identity,
        minimum: Some(-5),
        maximum: Some(10),
    };
    validate_fixture_input_value("sequence", &integer, &json!(10))
        .expect("bounded Integer fixture value validates");
    assert!(validate_fixture_input_value("sequence", &integer, &json!(11)).is_err());
    assert!(validate_fixture_input_value("sequence", &integer, &Value::Null).is_err());
}

#[test]
fn oauth_authoring_lowers_host_owned_form_exchange_with_expiry_cache() {
    let authored: AuthoredIntegrationDocument = serde_yaml::from_str(
        r#"
version: 1
id: generic-status
revision: 1
source:
  auth:
    type: oauth2_client_credentials
    request: form
    response_profile: oauth2_bearer
    scope: records.read registry.read
    audience: https://registry.invalid
    refresh_skew: 20s
input:
  person_id: { role: selector, type: string, maxLength: 64 }
capability:
  http:
    request: { method: GET, path: '/people/{input.person_id}' }
outputs:
  active: { type: boolean, x-registry-source: /active }
"#,
    )
    .expect("OAuth integration parses");
    let lowered = lower_authored_integration(&authored).expect("OAuth integration lowers");
    let operations = integration_operations(&lowered);
    let oauth = operations.get("oauth").expect("host-owned OAuth operation");
    assert_eq!(oauth.role, OperationRole::Credential);
    assert_eq!(oauth.request.path, "/");
    assert_eq!(
        oauth.request.codec.as_deref(),
        Some("oauth2_client_credentials_form_v1")
    );
    assert_eq!(
        operations["request"].depends_on,
        vec!["oauth".to_string()]
    );
}

#[test]
fn environment_source_binding_has_no_legacy_destination_or_credential_type_aliases() {
    let source: EnvironmentIntegration = serde_yaml::from_str(
        r#"
source:
  origin: https://registry.invalid
  allowed_private_cidrs: [10.42.0.0/16]
  credential:
    client_id: { secret: REGISTRY_CLIENT_ID }
    client_secret: { secret: REGISTRY_CLIENT_SECRET }
    generation: 7
  oauth:
    origin: https://identity.invalid
    path: /oauth/token
    generation: 3
  jwks:
    origin: https://trust.invalid
    path: /.well-known/jwks.json
    generation: 4
  concurrency: 4
  timeout: 10s
"#,
    )
    .expect("simple source binding parses");
    assert_eq!(source.source.oauth.as_ref().map(|endpoint| endpoint.generation), Some(3));
    assert_eq!(source.source.jwks.as_ref().map(|endpoint| endpoint.generation), Some(4));

    for legacy in [
        "data_destination: { origin: https://registry.invalid }",
        "source: { origin: https://registry.invalid, advanced_capabilities: {} }",
        "source: { origin: https://registry.invalid, credential: { type: basic, generation: 1 } }",
    ] {
        assert!(serde_yaml::from_str::<EnvironmentIntegration>(legacy).is_err());
    }
}
