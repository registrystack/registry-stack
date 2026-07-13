// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use registryctl::{
    add_config_anchor_key, build_country_project, check_country_project, init_config_anchor,
    init_country_project, sign_config_bundle, test_country_project, verify_config_bundle_cli,
    BundleSignOptions, CountryBuildOptions, CountryCheckOptions, CountryInitOptions,
    CountryStarter, CountryTestOptions, ReviewClass,
};
use sha2::{Digest as _, Sha256};

const TEST_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;
const TEST_PUBLIC_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;

fn golden(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/country-authoring")
        .join(name)
}

#[test]
fn every_country_golden_passes_the_offline_journey() {
    for project in [
        "custom-system",
        "dhis2-tracker",
        "fhir-r4-coverage-active",
        "opencrvs",
        "opencrvs-country-variant",
        "openspp-exact",
        "snapshot-exact",
    ] {
        let report = test_country_project(&CountryTestOptions {
            project_directory: golden(project),
            environment: None,
            live: false,
        })
        .unwrap_or_else(|error| panic!("{project} offline journey failed: {error:#}"));
        assert_eq!(report.status, "passed", "{project}");
        assert!(!report.fixtures.is_empty(), "{project}");
        assert!(
            report.fixtures.iter().all(|fixture| fixture.passed),
            "{project}"
        );
    }
}

#[test]
fn fhir_r4_coverage_active_passes_the_closed_bundle_matrix() {
    let report = test_country_project(&CountryTestOptions {
        project_directory: golden("fhir-r4-coverage-active"),
        environment: None,
        live: false,
    })
    .expect("FHIR R4 Coverage-active golden passes");
    assert_eq!(report.status, "passed");
    assert_eq!(report.fixtures.len(), 13);
    assert!(report.fixtures.iter().all(|fixture| fixture.passed));
}

#[test]
fn approved_opencrvs_and_dhis2_claim_sets_execute_offline() {
    for project in ["opencrvs", "opencrvs-country-variant", "dhis2-tracker"] {
        let report = test_country_project(&CountryTestOptions {
            project_directory: golden(project),
            environment: None,
            live: false,
        })
        .unwrap_or_else(|error| panic!("{project} approved claims failed: {error:#}"));
        assert!(report.fixtures.iter().all(|fixture| fixture.passed));
    }
}

#[test]
fn successful_negative_fixtures_report_the_closed_denial_assertion() {
    let report = test_country_project(&CountryTestOptions {
        project_directory: golden("custom-system"),
        environment: None,
        live: false,
    })
    .expect("custom system golden passes");
    let serialized = serde_json::to_string(&report).expect("fixture report serializes");
    assert!(!serialized.contains("HH-AB12CD34"));
    assert!(!serialized.contains("synthetic-key-1"));

    let denied_before_access = report
        .fixtures
        .iter()
        .find(|fixture| fixture.fixture == "wrong-purpose-denied-before-source")
        .expect("wrong-purpose fixture report");
    assert!(denied_before_access.passed);
    assert_eq!(
        denied_before_access.expected_error.as_deref(),
        Some("authorization.purpose_denied")
    );
    assert_eq!(denied_before_access.source_access, Some(false));

    let denied_after_access = report
        .fixtures
        .iter()
        .find(|fixture| fixture.fixture == "custom-malformed-response")
        .expect("malformed-response fixture report");
    assert!(denied_after_access.passed);
    assert_eq!(
        denied_after_access.expected_error.as_deref(),
        Some("source.response_malformed")
    );
    assert_eq!(denied_after_access.source_access, Some(true));

    let successful = report
        .fixtures
        .iter()
        .find(|fixture| fixture.fixture == "eligible-household")
        .expect("eligible fixture report");
    assert_eq!(successful.expected_error, None);
    assert_eq!(successful.source_access, None);
}

#[test]
fn authored_rhai_script_compiles_under_the_production_surface() {
    let script = std::fs::read_to_string(
        golden("dhis2-sandboxed-rhai").join("integrations/health-record/orchestration.rhai"),
    )
    .expect("authored Rhai script");
    registry_relay::rhai_worker::probe_script(
        &script,
        "consult",
        registry_relay::rhai_worker::WorkerLimits {
            max_call_levels: 16,
            max_expr_depth: 16,
            max_memory_bytes: 64 * 1024 * 1024,
            wall_time_ms: 5_000,
            ..registry_relay::rhai_worker::WorkerLimits::default()
        },
    )
    .expect("authored Rhai script compiles under the production language surface");
}

#[cfg(target_os = "linux")]
#[test]
fn public_rhai_commands_accept_the_released_contract_for_an_unknown_product() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("dhis2-sandboxed-rhai", temporary.path());
    replace_in_file(
        &project.join("integrations/health-record/integration.yaml"),
        "product: dhis2",
        "product: fictional-health-registry",
    );
    replace_in_file(
        &project.join("integrations/health-record/integration.yaml"),
        "versions: { tested: [2.41.9] }",
        "versions: { unverified: [7.3] }",
    );
    replace_in_file(
        &project.join("environments/local.yaml"),
        "source_version: 2.41.9",
        "source_version: 7.3",
    );

    let test_report = test_country_project(&CountryTestOptions {
        project_directory: project.clone(),
        environment: None,
        live: false,
    })
    .expect("released Rhai contract accepts an unknown product");
    assert_eq!(test_report.status, "passed");

    let check_report = check_country_project(&CountryCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect("unknown-product Rhai project checks");
    assert_eq!(check_report.status, "passed");

    let build_report = build_country_project(&CountryBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("unknown-product Rhai project builds");
    assert_eq!(build_report.status, "built");
    assert!(project.join(".registry-stack/build/local").exists());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn public_rhai_commands_enforce_the_production_platform_gate() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("dhis2-sandboxed-rhai", temporary.path());

    let test_error = test_country_project(&CountryTestOptions {
        project_directory: project.clone(),
        environment: None,
        live: false,
    })
    .expect_err("public test must enforce the Rhai platform gate");
    assert!(
        format!("{test_error:#}").contains("consultation service plan is unsupported"),
        "{test_error:#}"
    );

    for error in [
        check_country_project(&CountryCheckOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            explain: false,
            against: None,
            anchor: None,
        })
        .expect_err("public check must enforce the Rhai platform gate"),
        build_country_project(&CountryBuildOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            against: None,
            anchor: None,
        })
        .expect_err("public build must enforce the Rhai platform gate"),
    ] {
        assert!(
            format!("{error:#}").contains("consultation service plan is unsupported"),
            "{error:#}"
        );
    }
    assert!(!project.join(".registry-stack/build/local").exists());
}

#[test]
fn rhai_conformance_controls_are_code_only_and_deny_ambient_capabilities() {
    let limits = registry_relay::rhai_worker::WorkerLimits {
        max_call_levels: 16,
        max_expr_depth: 16,
        max_memory_bytes: 128 * 1024 * 1024,
        wall_time_ms: 5_000,
        ..registry_relay::rhai_worker::WorkerLimits::default()
    };
    let worker =
        registry_relay::rhai_worker::WorkerProcess::with_program(env!("CARGO_BIN_EXE_registryctl"));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime builds");
    for script in [
        "fn consult(input, prior) { http_get(\"https://example.invalid\") }",
        "fn consult(input, prior) { read_file(\"/etc/passwd\") }",
        "fn consult(input, prior) { exec(\"id\") }",
        "fn consult(input, prior) { env_var(\"HOME\") }",
        "fn consult(input, prior) { timestamp() }",
    ] {
        let request = registry_relay::rhai_worker::WorkerRequest::v1(script, "consult", limits);
        assert_eq!(
            runtime.block_on(worker.evaluate(&request)),
            Err(registry_relay::rhai_worker::WorkerError::ScriptRejected)
        );
    }

    let request = registry_relay::rhai_worker::WorkerRequest::v1(
        "fn consult(input, prior) { #{ operations: [], facts: #{} } }",
        "consult",
        limits,
    );
    let serialized = serde_json::to_value(request).expect("worker request serializes");
    for forbidden in [
        "caller",
        "scopes",
        "purpose",
        "disclosure",
        "credential",
        "provenance",
    ] {
        assert!(serialized.get(forbidden).is_none());
    }
}

#[test]
fn production_cel_worker_evaluates_country_date_policy() {
    let mut config =
        registry_notary_server::cel_worker::CelWorkerConfig::for_current_exe_subcommand();
    config.command = env!("CARGO_BIN_EXE_registryctl").into();
    config.command_args = vec!["__registryctl-cel-worker-v1".into()];
    config.request_timeout = std::time::Duration::from_secs(10);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime builds");
    let worker = registry_notary_server::cel_worker::CelWorker::lazy(config);
    let value = runtime
        .block_on(worker.evaluate(
            "health.exists && health.date_of_birth != null\n  ? date.age_on(health.date_of_birth, as_of_date)\n  : null",
            serde_json::json!({
                "health": {
                    "exists": true,
                    "first_name": "Nia",
                    "last_name": "Example",
                    "date_of_birth": "2017-06-15",
                    "child_program_active": true,
                    "programme_code": "CHILD",
                    "reconciliation_reference": "REF-0001",
                    "maternal_postnatal_active": true,
                    "child_health_visit_recorded": true,
                    "tb_program_active": false
                },
                "as_of_date": "2026-01-01"
            }),
        ))
        .expect("production CEL worker evaluates the country date policy");
    assert_eq!(value, serde_json::json!(8));

    let age_band = runtime
        .block_on(worker.evaluate(
            "health.exists && health.date_of_birth != null\n  ? (date.age_on(health.date_of_birth, as_of_date) < 5\n      ? \"0-4\"\n      : (date.age_on(health.date_of_birth, as_of_date) < 18 ? \"5-17\" : \"18+\"))\n  : null",
            serde_json::json!({
                "health": {
                    "exists": true,
                    "date_of_birth": "2017-06-15"
                },
                "as_of_date": "2026-01-01"
            }),
        ))
        .expect("production CEL worker evaluates the approved age band");
    assert_eq!(age_band, serde_json::json!("5-17"));

    let absent = runtime
        .block_on(worker.evaluate(
            "health.exists && health.date_of_birth != null\n  ? date.age_on(health.date_of_birth, as_of_date)\n  : null",
            serde_json::json!({
                "health": { "exists": false, "date_of_birth": null },
                "as_of_date": "2026-01-01"
            }),
        ))
        .expect("production CEL worker preserves a successful null result");
    assert_eq!(absent, serde_json::Value::Null);
}

#[test]
fn all_advertised_starters_initialize_and_test_without_source_access() {
    for starter in [
        CountryStarter::BoundedHttp,
        CountryStarter::Dhis2Tracker,
        CountryStarter::Opencrvs,
        CountryStarter::Openspp,
    ] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = temporary.path().join("country");
        let initialized = init_country_project(&CountryInitOptions {
            starter,
            directory: project.clone(),
        })
        .expect("starter initializes");
        assert_eq!(initialized.status, "initialized");
        let tested = test_country_project(&CountryTestOptions {
            project_directory: project,
            environment: None,
            live: false,
        })
        .expect("initialized starter passes offline tests");
        assert_eq!(tested.status, "passed");
    }
}

#[test]
fn bounded_http_starter_adapts_to_a_structurally_different_country_api() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("adapted-country-api");
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/country-starters/bounded-http"),
        &project,
    );
    let integration = project.join("integrations/person-record/integration.yaml");
    std::fs::write(
        &integration,
        r#"version: 1
id: fictional-two-step-person-record
source:
  product: unanticipated-municipal-api
  versions: { unverified: [municipal-contract-v3] }
input:
  person_id: { type: string, bytes: 24, pattern: "^[A-Z]{2}-[0-9]{6}$", canonicalization: identity }
capability:
  bounded_http:
    credential: { type: static_bearer }
    operations:
      resolve:
        request:
          method: POST
          destination: data
          path: /lookup/resolve
          codec: strict_json_v1
          body:
            subject: { input: person_id }
            projection: { value: key }
            limit: { value: 2 }
        response:
          statuses: [200]
          max_bytes: 8192
          schema:
            type: object
            additional_fields: reject
            fields:
              matches:
                required: true
                type: array
                max_items: 2
                items:
                  type: object
                  additional_fields: reject
                  fields: { key: { required: true, type: string, max_bytes: 32 } }
          cardinality: { records: matches, mode: probe_two }
      status:
        depends_on: [resolve]
        request:
          method: GET
          destination: data
          path: /lookup/status
          query: { key: { prior: resolve.key } }
        response:
          statuses: [200]
          max_bytes: 8192
          schema:
            type: object
            additional_fields: reject
            fields: { status: { required: true, type: string, max_bytes: 24 } }
          cardinality: { mode: singleton }
facts:
  exists: { type: presence, from: resolve.presence }
  status: { type: string, nullable: true, max_bytes: 24, from: status.status }
bounds: { calls: 2, source_bytes: 16384, request_bytes: 2048, deadline: 5s, concurrency: 4 }
fixtures: fixtures/
"#,
    )
    .expect("adapted integration writes");
    let fixture_directory = project.join("integrations/person-record/fixtures");
    for entry in std::fs::read_dir(&fixture_directory).expect("starter fixtures") {
        let path = entry.expect("fixture entry").path();
        if path.file_name().and_then(|name| name.to_str()) != Some("active.yaml") {
            std::fs::remove_file(path).expect("unused fixture removes");
        }
    }
    std::fs::write(
        fixture_directory.join("active.yaml"),
        r#"name: adapted-active-person
input: { person_id: AB-123456 }
source:
  resolve: { status: 200, body: { matches: [{ key: municipal-key-1 }] } }
  status: { status: 200, body: { status: ACTIVE } }
expect:
  facts: { exists: true, status: ACTIVE }
  claims: { person-record-exists: true, person-status: ACTIVE }
"#,
    )
    .expect("adapted fixture writes");
    replace_in_file(
        &project.join("environments/local.yaml"),
        "country-fixture-v1",
        "municipal-contract-v3",
    );
    let project_file = project.join("registry-stack.yaml");
    let mut project_document = read_yaml(&project_file);
    let service = &mut project_document["services"]["person-verification"];
    service["purpose"] = serde_yaml::Value::String("municipal-benefit-screening".to_string());
    service["claims"]
        .as_mapping_mut()
        .expect("starter claims")
        .remove(serde_yaml::Value::String("person-active".to_string()));
    service["credentials"]["person-status"]["claims"]
        .as_sequence_mut()
        .expect("starter credential claims")
        .retain(|claim| claim.as_str() != Some("person-active"));
    write_yaml(&project_file, &project_document);

    let report = check_country_project(&CountryCheckOptions {
        project_directory: project,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect("structurally adapted starter compiles and executes");
    assert!(report.required_reviews.contains(&ReviewClass::Integration));
    assert!(report
        .required_reviews
        .contains(&ReviewClass::CountryPolicy));
}

#[test]
fn source_product_is_metadata_not_runtime_dispatch() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    for (name, integration, product) in [
        (
            "fhir-r4-coverage-active",
            "integrations/coverage/integration.yaml",
            "country-fhir-server",
        ),
        (
            "opencrvs",
            "integrations/birth-record/integration.yaml",
            "opencrvs",
        ),
        (
            "snapshot-exact",
            "integrations/person-snapshot/integration.yaml",
            "population-snapshot",
        ),
    ] {
        let case_root = temporary.path().join(format!("case-{name}"));
        std::fs::create_dir(&case_root).expect("case root creates");
        let case = copy_project(name, &case_root);
        replace_in_file(
            &case.join(integration),
            &format!("product: {product}"),
            "product: previously-unknown-country-system",
        );
        let report = test_country_project(&CountryTestOptions {
            project_directory: case,
            environment: None,
            live: false,
        })
        .unwrap_or_else(|error| panic!("{name} selected behavior by product id: {error:#}"));
        assert_eq!(report.status, "passed", "{name}");
    }

    let project = copy_project("custom-system", temporary.path());
    replace_in_file(
        &project.join("integrations/eligibility/integration.yaml"),
        "product: aurora-household-service",
        "product: previously-unknown-country-system",
    );
    replace_in_file(
        &project.join("integrations/eligibility/integration.yaml"),
        "unverified: [fixture-contract-v2]",
        "unverified: [country-contract-99]",
    );
    replace_in_file(
        &project.join("environments/local.yaml"),
        "source_version: fixture-contract-v2",
        "source_version: country-contract-99",
    );

    let offline = test_country_project(&CountryTestOptions {
        project_directory: project.clone(),
        environment: None,
        live: false,
    })
    .expect("unknown product uses the generic bounded HTTP executor");
    assert_eq!(offline.status, "passed");

    let check = check_country_project(&CountryCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: true,
        against: None,
        anchor: None,
    })
    .expect("unknown product compiles through the generic authoring contract");
    assert_eq!(check.status, "valid");

    let build = build_country_project(&CountryBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("unknown product builds generic Relay and Notary inputs");
    assert_eq!(build.status, "built");
}

#[test]
fn init_accepts_an_existing_empty_directory_and_rejects_authored_content() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let empty = temporary.path().join("empty");
    std::fs::create_dir(&empty).expect("empty destination creates");
    init_country_project(&CountryInitOptions {
        starter: CountryStarter::BoundedHttp,
        directory: empty,
    })
    .expect("empty destination initializes");

    let occupied = temporary.path().join("occupied");
    std::fs::create_dir(&occupied).expect("occupied destination creates");
    std::fs::write(occupied.join("owned.txt"), b"user content").expect("user content writes");
    let error = init_country_project(&CountryInitOptions {
        starter: CountryStarter::BoundedHttp,
        directory: occupied,
    })
    .expect_err("occupied destination must be preserved");
    assert!(error
        .to_string()
        .contains("absent or an empty real directory"));
}

#[test]
fn authored_unknown_fields_and_traversal_fail_closed() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let unknown = temporary.path().join("unknown");
    init_country_project(&CountryInitOptions {
        starter: CountryStarter::BoundedHttp,
        directory: unknown.clone(),
    })
    .expect("starter initializes");
    let project_path = unknown.join("registry-stack.yaml");
    let mut project = std::fs::read_to_string(&project_path).expect("project reads");
    project.push_str("unexpected_authority: true\n");
    std::fs::write(&project_path, project).expect("invalid project writes");
    let error = test_country_project(&CountryTestOptions {
        project_directory: unknown,
        environment: None,
        live: false,
    })
    .expect_err("unknown field must fail");
    assert!(format!("{error:#}").contains("unknown field"));

    let conformance_escape = copy_project("dhis2-sandboxed-rhai", temporary.path());
    let fixture_path = conformance_escape.join("integrations/health-record/fixtures/match.yaml");
    let fixture = std::fs::read_to_string(&fixture_path)
        .expect("Rhai fixture reads")
        .replace("source:\n", "worker_probe: network\nsource:\n");
    std::fs::write(&fixture_path, fixture).expect("hostile Rhai fixture writes");
    let error = test_country_project(&CountryTestOptions {
        project_directory: conformance_escape,
        environment: None,
        live: false,
    })
    .expect_err("implementation conformance mode must not be authored");
    assert!(format!("{error:#}").contains("worker_probe"));

    let traversal = temporary.path().join("traversal");
    init_country_project(&CountryInitOptions {
        starter: CountryStarter::BoundedHttp,
        directory: traversal.clone(),
    })
    .expect("starter initializes");
    let project_path = traversal.join("registry-stack.yaml");
    let project = std::fs::read_to_string(&project_path)
        .expect("project reads")
        .replace(
            "integrations/person-record/integration.yaml",
            "../outside/integration.yaml",
        );
    std::fs::write(&project_path, project).expect("traversal project writes");
    let error = test_country_project(&CountryTestOptions {
        project_directory: traversal,
        environment: None,
        live: false,
    })
    .expect_err("path traversal must fail");
    assert!(format!("{error:#}").contains("cannot traverse"));
}

#[test]
fn fixture_failure_reports_safe_actual_error_code() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let fixture_path = project.join("integrations/eligibility/fixtures/eligible.yaml");
    replace_in_file(&fixture_path, "HH-AB12CD34", "invalid-reference");

    let error = test_country_project(&CountryTestOptions {
        project_directory: project,
        environment: None,
        live: false,
    })
    .expect_err("invalid positive fixture must fail");
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("eligibility.eligible-household"));
    assert!(diagnostic.contains("integrations/eligibility/fixtures/eligible.yaml"));
    assert!(diagnostic.contains("field=input.household_reference"));
    assert!(diagnostic.contains("actual=input.pattern_mismatch"));
    assert!(!diagnostic.contains("invalid-reference"));
}

#[cfg(unix)]
#[test]
fn authored_fixture_symlinks_fail_closed() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("country");
    init_country_project(&CountryInitOptions {
        starter: CountryStarter::BoundedHttp,
        directory: project.clone(),
    })
    .expect("starter initializes");
    let fixtures = project.join("integrations/person-record/fixtures");
    let fixture = std::fs::read_dir(&fixtures)
        .expect("fixtures read")
        .next()
        .expect("fixture exists")
        .expect("fixture entry")
        .path();
    let external = temporary.path().join("external.yaml");
    std::fs::rename(&fixture, &external).expect("fixture moves");
    symlink(&external, &fixture).expect("fixture symlink creates");
    let error = test_country_project(&CountryTestOptions {
        project_directory: project,
        environment: None,
        live: false,
    })
    .expect_err("fixture symlink must fail");
    assert!(format!("{error:#}").contains("regular YAML files"));
}

#[cfg(unix)]
#[test]
fn generated_build_refuses_a_symlinked_private_output_ancestor() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let outside = temporary.path().join("outside");
    std::fs::create_dir(&outside).expect("outside directory creates");
    symlink(&outside, project.join(".registry-stack")).expect("output ancestor symlink creates");
    let error = build_country_project(&CountryBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect_err("symlinked private output ancestor must fail");
    assert!(format!("{error:#}").contains("symlink"));
    assert!(std::fs::read_dir(outside)
        .expect("outside directory reads")
        .next()
        .is_none());
}

#[test]
fn live_testing_requires_an_explicit_environment_before_reading_credentials() {
    let error = test_country_project(&CountryTestOptions {
        project_directory: golden("custom-system"),
        environment: None,
        live: true,
    })
    .expect_err("implicit live environment must fail closed");
    assert!(error
        .to_string()
        .contains("explicit non-production --environment"));
}

#[test]
fn strict_country_authoring_schemas_compile_and_accept_every_golden() {
    let schema_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/country-authoring");
    let compile = |schema_name: &str| {
        let schema: serde_json::Value = serde_json::from_slice(
            &std::fs::read(schema_root.join(schema_name)).expect("schema reads"),
        )
        .expect("schema is JSON");
        jsonschema::JSONSchema::compile(&schema)
            .unwrap_or_else(|error| panic!("{schema_name} did not compile: {error}"))
    };
    let project_schema = compile("project.schema.json");
    let environment_schema = compile("environment.schema.json");
    let integration_schema = compile("integration.schema.json");
    let fixture_schema = compile("fixture.schema.json");
    let records_schema = compile("records.schema.json");
    let mut projects =
        vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/country-starters/bounded-http")];
    projects.extend(
        [
            "custom-system",
            "dhis2-tracker",
            "dhis2-sandboxed-rhai",
            "fhir-r4-coverage-active",
            "opencrvs",
            "opencrvs-country-variant",
            "openspp-exact",
            "snapshot-exact",
        ]
        .map(golden),
    );
    for project in projects {
        validate_yaml(&project_schema, &project.join("registry-stack.yaml"));
        validate_yaml(
            &environment_schema,
            &project.join("environments/local.yaml"),
        );
        let records = project.join("records");
        if records.is_dir() {
            for definition in std::fs::read_dir(records).expect("records directory reads") {
                validate_yaml(&records_schema, &definition.expect("records entry").path());
            }
        }
        for integration_dir in
            std::fs::read_dir(project.join("integrations")).expect("integration directory reads")
        {
            let integration_dir = integration_dir.expect("integration entry").path();
            validate_yaml(
                &integration_schema,
                &integration_dir.join("integration.yaml"),
            );
            for fixture in std::fs::read_dir(integration_dir.join("fixtures"))
                .expect("fixture directory reads")
            {
                validate_yaml(&fixture_schema, &fixture.expect("fixture entry").path());
            }
        }
    }
}

#[test]
fn exact_selector_sizes_one_through_four_compile_for_http_and_snapshot() {
    for size in 1..=4 {
        let temporary = tempfile::tempdir().expect("temporary directory");
        for golden_name in ["custom-system", "snapshot-exact"] {
            let project = copy_project(golden_name, temporary.path());
            if golden_name == "custom-system" {
                remove_custom_cel_claim(&project);
            }
            extend_exact_selector(&project, golden_name, size);
            check_country_project(&CountryCheckOptions {
                project_directory: project,
                environment: "local".to_string(),
                explain: false,
                against: None,
                anchor: None,
            })
            .unwrap_or_else(|error| {
                panic!("{golden_name} exact selector size {size} failed: {error:#}")
            });
        }
    }
}

#[test]
fn integration_input_bounds_match_the_production_compiler_limit() {
    let accepted_root = tempfile::tempdir().expect("accepted temporary directory");
    let accepted = copy_project("custom-system", accepted_root.path());
    remove_custom_cel_claim(&accepted);
    replace_in_file(
        &accepted.join("integrations/eligibility/integration.yaml"),
        "bytes: 18",
        "bytes: 256",
    );
    let report = build_country_project(&CountryBuildOptions {
        project_directory: accepted,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("256-byte input builds through the production Relay compiler closure");
    let output = PathBuf::from(report.output.expect("build output"));
    let pack: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            output.join("private/relay/config/artifacts/integration-packs/eligibility.json"),
        )
        .expect("generated integration pack reads"),
    )
    .expect("generated integration pack parses");
    assert_eq!(
        pack["spec"]["input_slots"]["household_reference"]["max_bytes"],
        256
    );

    let rejected_root = tempfile::tempdir().expect("rejected temporary directory");
    let rejected = copy_project("custom-system", rejected_root.path());
    replace_in_file(
        &rejected.join("integrations/eligibility/integration.yaml"),
        "bytes: 18",
        "bytes: 257",
    );
    let error = test_country_project(&CountryTestOptions {
        project_directory: rejected,
        environment: None,
        live: false,
    })
    .expect_err("257-byte input must be rejected before source access");
    let error = format!("{error:#}");
    assert!(error.contains("integration.yaml"), "{error}");
    assert!(error.contains("input.household_reference.bytes"), "{error}");
}

#[test]
fn integration_input_names_match_the_wire_grammar() {
    let accepted_root = tempfile::tempdir().expect("accepted temporary directory");
    let accepted = copy_project("custom-system", accepted_root.path());
    remove_custom_cel_claim(&accepted);
    let boundary_name = format!("a{}", "0".repeat(63));
    rename_custom_input(&accepted, &boundary_name);
    let report = build_country_project(&CountryBuildOptions {
        project_directory: accepted,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("64-byte input name builds through the production Relay compiler closure");
    let output = PathBuf::from(report.output.expect("build output"));
    let pack: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            output.join("private/relay/config/artifacts/integration-packs/eligibility.json"),
        )
        .expect("generated integration pack reads"),
    )
    .expect("generated integration pack parses");
    assert_eq!(
        pack["spec"]["input_slots"]
            .as_object()
            .expect("input slots")
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec![boundary_name]
    );

    for invalid_name in [
        format!("a{}", "0".repeat(64)),
        "bad-name".to_string(),
        "bad.name".to_string(),
    ] {
        let rejected_root = tempfile::tempdir().expect("rejected temporary directory");
        let rejected = copy_project("custom-system", rejected_root.path());
        rename_custom_input(&rejected, &invalid_name);
        let error = test_country_project(&CountryTestOptions {
            project_directory: rejected,
            environment: None,
            live: false,
        })
        .expect_err("invalid input name must be rejected before source access");
        let error = format!("{error:#}");
        assert!(error.contains("integration.yaml"), "{error}");
        assert!(
            error.contains(&format!("input.{invalid_name}.name")),
            "{error}"
        );
    }
}

#[test]
fn integration_input_pattern_schema_matches_the_wire_limit() {
    let schema: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("schemas/country-authoring/integration.schema.json"),
        )
        .expect("integration schema reads"),
    )
    .expect("integration schema parses");
    let schema = jsonschema::JSONSchema::compile(&schema).expect("integration schema compiles");
    let authored: serde_yaml::Value = serde_yaml::from_slice(
        &std::fs::read(golden("custom-system").join("integrations/eligibility/integration.yaml"))
            .expect("integration reads"),
    )
    .expect("integration parses");
    let mut authored = serde_json::to_value(authored).expect("integration converts to JSON");
    authored["input"]["household_reference"]["pattern"] =
        serde_json::Value::String("a".repeat(1024));
    assert!(schema.validate(&authored).is_ok());
    authored["input"]["household_reference"]["pattern"] =
        serde_json::Value::String("a".repeat(1025));
    assert!(schema.validate(&authored).is_err());
}

#[test]
fn exact_selector_authored_member_order_is_canonical() {
    let first_root = tempfile::tempdir().expect("first temporary directory");
    let second_root = tempfile::tempdir().expect("second temporary directory");
    let first = copy_project("custom-system", first_root.path());
    let second = copy_project("custom-system", second_root.path());
    remove_custom_cel_claim(&first);
    remove_custom_cel_claim(&second);
    extend_exact_selector(&first, "custom-system", 3);
    extend_exact_selector(&second, "custom-system", 3);

    reverse_yaml_mapping(
        &second.join("integrations/eligibility/integration.yaml"),
        &["input"],
    );
    reverse_yaml_mapping(
        &second.join("registry-stack.yaml"),
        &[
            "services",
            "household-eligibility",
            "consultations",
            "household",
            "input",
        ],
    );
    for fixture in std::fs::read_dir(second.join("integrations/eligibility/fixtures"))
        .expect("fixture directory")
    {
        reverse_yaml_mapping(&fixture.expect("fixture entry").path(), &["input"]);
    }

    let build = |project_directory| {
        build_country_project(&CountryBuildOptions {
            project_directory,
            environment: "local".to_string(),
            against: None,
            anchor: None,
        })
        .expect("ordered selector project builds")
    };
    let first = PathBuf::from(build(first).output.expect("first output"));
    let second = PathBuf::from(build(second).output.expect("second output"));
    for relative in [
        "private/relay/config/artifacts/integration-packs/eligibility.json",
        "private/relay/config/artifacts/consultation-contracts/household-eligibility-household.json",
        "private/relay/config/artifacts/private-bindings/household-eligibility-household.json",
    ] {
        assert_eq!(
            std::fs::read(first.join(relative)).expect("first canonical artifact"),
            std::fs::read(second.join(relative)).expect("second canonical artifact"),
            "{relative}"
        );
    }
}

#[test]
fn api_key_interfaces_keep_values_environment_only_and_enforce_query_review() {
    for (credential_type, name) in [
        ("api_key_header", "x-country-api-key"),
        ("api_key_query", "apiKey"),
    ] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project("custom-system", temporary.path());
        remove_custom_cel_claim(&project);
        let integration = project.join("integrations/eligibility/integration.yaml");
        let mut document = read_yaml(&integration);
        document["capability"]["bounded_http"]["credential"] = serde_yaml::from_str(&format!(
            "type: {credential_type}\nname: {name}\nmax_value_bytes: 128\n"
        ))
        .expect("API-key interface YAML");
        write_yaml(&integration, &document);

        let environment = project.join("environments/local.yaml");
        let mut document = read_yaml(&environment);
        document["integrations"]["eligibility"]["credential"] = serde_yaml::from_str(&format!(
            "type: {credential_type}\nvalue: {{ secret: COUNTRY_SOURCE_API_KEY }}\ngeneration: 1\n{}",
            if credential_type == "api_key_query" {
                "review: operator_security\n"
            } else {
                ""
            }
        ))
        .expect("API-key environment YAML");
        write_yaml(&environment, &document);

        let report = build_country_project(&CountryBuildOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            against: None,
            anchor: None,
        })
        .unwrap_or_else(|error| panic!("{credential_type} failed: {error:#}"));
        let output = PathBuf::from(report.output.expect("build output"));
        let closure = directory_closure(&output);
        let joined = closure
            .iter()
            .flat_map(|(_, bytes)| bytes.iter().copied())
            .collect::<Vec<_>>();
        let generated = String::from_utf8_lossy(&joined);
        assert!(generated.contains("COUNTRY_SOURCE_API_KEY"));
        assert!(!generated.contains("secret: COUNTRY_SOURCE_API_KEY"));
        assert!(!generated.contains("country-source-secret-value"));
    }

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let integration = project.join("integrations/eligibility/integration.yaml");
    replace_in_file(
        &integration,
        "type: basic",
        "type: api_key_header\n      name: authorization\n      max_value_bytes: 128",
    );
    let error = test_country_project(&CountryTestOptions {
        project_directory: project,
        environment: None,
        live: false,
    })
    .expect_err("security-sensitive header must fail");
    assert!(format!("{error:#}").contains("security-sensitive"));

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let integration = project.join("integrations/eligibility/integration.yaml");
    replace_in_file(
        &integration,
        "type: basic",
        "type: api_key_query\n      name: fields\n      max_value_bytes: 128",
    );
    let error = test_country_project(&CountryTestOptions {
        project_directory: project,
        environment: None,
        live: false,
    })
    .expect_err("query-name collision must fail");
    assert!(format!("{error:#}").contains("collides"));

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let integration = project.join("integrations/eligibility/integration.yaml");
    replace_in_file(
        &integration,
        "type: basic",
        "type: api_key_query\n      name: apiKey\n      max_value_bytes: 128",
    );
    let environment = project.join("environments/local.yaml");
    replace_in_file(
        &environment,
        "type: basic\n      username: { secret: HOUSEHOLD_USERNAME }\n      password: { secret: HOUSEHOLD_PASSWORD }",
        "type: api_key_query\n      value: { secret: COUNTRY_SOURCE_API_KEY }",
    );
    let error = check_country_project(&CountryCheckOptions {
        project_directory: project,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("query credential without operator-security review must fail");
    assert!(format!("{error:#}").contains("environment credential"));
}

#[test]
fn dci_exact_and_and_full_date_inputs_fail_closed_before_source_access() {
    let cases = [
        (
            "response_pointer: /identifier/0/identifier_value",
            "response_pointer: /identifier/00/identifier_value",
            "canonical",
        ),
        (
            "response_pointer: /identifier/0/identifier_value",
            "response_pointer: /identifier/0/missing",
            "outside the signed record schema",
        ),
        (
            "exact_and:\n              uin:",
            "exact_and:\n              other:",
            "keys must equal",
        ),
    ];
    for (from, to, expected) in cases {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project("opencrvs", temporary.path());
        replace_in_file(
            &project.join("integrations/birth-record/integration.yaml"),
            from,
            to,
        );
        let error = test_country_project(&CountryTestOptions {
            project_directory: project,
            environment: None,
            live: false,
        })
        .expect_err("invalid DCI exact conjunction must fail");
        assert!(format!("{error:#}").contains(expected), "{error:#}");
    }

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    extend_exact_selector(&project, "custom-system", 4);
    let fixture = project.join("integrations/eligibility/fixtures/eligible.yaml");
    replace_in_file(&fixture, "2017-06-15", "2017-02-31");
    let error = test_country_project(&CountryTestOptions {
        project_directory: project,
        environment: None,
        live: false,
    })
    .expect_err("nonexistent full date must fail before source access");
    assert!(format!("{error:#}").contains("full_date input is not canonical"));

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    extend_exact_selector(&project, "custom-system", 3);
    let fixture = project.join("integrations/eligibility/fixtures/eligible.yaml");
    let mut document = read_yaml(&fixture);
    document["input"]
        .as_mapping_mut()
        .expect("fixture inputs")
        .remove(serde_yaml::Value::String("selector_3".to_string()));
    write_yaml(&fixture, &document);
    let error = test_country_project(&CountryTestOptions {
        project_directory: project,
        environment: None,
        live: false,
    })
    .expect_err("missing composite component must fail before source access");
    assert!(format!("{error:#}").contains("must bind every"));
}

#[test]
fn opencrvs_composite_dci_uses_unified_exact_predicates_canonically() {
    let first_root = tempfile::tempdir().expect("first temporary directory");
    let second_root = tempfile::tempdir().expect("second temporary directory");
    let first = copy_project("opencrvs", first_root.path());
    let second = copy_project("opencrvs", second_root.path());
    make_opencrvs_composite_dci(&first);
    make_opencrvs_composite_dci(&second);
    reverse_yaml_mapping(
        &second.join("integrations/birth-record/integration.yaml"),
        &["input"],
    );

    let journey = test_country_project(&CountryTestOptions {
        project_directory: first.clone(),
        environment: None,
        live: false,
    })
    .expect("composite DCI fixtures execute through the offline production decoder");
    let ambiguous = journey
        .fixtures
        .iter()
        .find(|fixture| fixture.fixture == "birth-record-ambiguous")
        .expect("composite ambiguous fixture executes");
    assert_eq!(ambiguous.outcome.as_deref(), Some("ambiguous"));
    assert!(ambiguous.facts.is_empty());
    assert!(ambiguous.claims.is_empty());
    reverse_yaml_mapping(
        &second.join("integrations/birth-record/integration.yaml"),
        &[
            "capability",
            "bounded_http",
            "operations",
            "birth",
            "request",
            "body",
            "exact_and",
        ],
    );

    let build = |project_directory| {
        build_country_project(&CountryBuildOptions {
            project_directory,
            environment: "local".to_string(),
            against: None,
            anchor: None,
        })
        .expect("composite DCI project builds")
    };
    let first = PathBuf::from(build(first).output.expect("first output"));
    let second = PathBuf::from(build(second).output.expect("second output"));
    let relative = "private/relay/config/artifacts/integration-packs/birth-record.json";
    let first_pack = std::fs::read(first.join(relative)).expect("first DCI pack");
    let second_pack = std::fs::read(second.join(relative)).expect("second DCI pack");
    assert_eq!(first_pack, second_pack);
    let pack: serde_json::Value = serde_json::from_slice(&first_pack).expect("DCI pack JSON");
    let selector = &pack["spec"]["reviewed_acquisition"]["selector"];
    assert_eq!(selector["type"], "http_exact_and");
    assert_eq!(
        selector["components"].as_object().map(|map| map.len()),
        Some(3)
    );
    assert!(selector["components"]
        .as_object()
        .expect("selector components")
        .values()
        .all(|component| component["role"] == "dci_exact_predicate"));
    let dci = &pack["spec"]["plan"]["operations"][0]["dci"];
    assert!(dci.get("identifier_type").is_none());
    assert_eq!(dci["exact_and"].as_object().map(|map| map.len()), Some(3));
}

fn validate_yaml(schema: &jsonschema::JSONSchema, path: &Path) {
    let authored: serde_yaml::Value = serde_yaml::from_slice(
        &std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let authored = serde_json::to_value(authored).expect("YAML converts to JSON");
    if let Err(errors) = schema.validate(&authored) {
        let messages = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("schema rejected {}: {messages:?}", path.display());
    };
}

#[test]
fn check_and_build_produce_deterministic_product_inputs() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let check = check_country_project(&CountryCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: true,
        against: None,
        anchor: None,
    })
    .expect("golden project checks");
    assert_eq!(check.status, "valid");
    assert_eq!(check.semantic_changes.len(), 5);
    assert!(check
        .semantic_changes
        .iter()
        .all(|change| change.previous_digest.is_none()));
    let explanation = check.explanation.expect("explanation is present");
    assert!(explanation
        .pointer("/environment_binding/callers")
        .is_some());
    assert!(explanation
        .pointer("/services/household-eligibility/consultations")
        .is_some());
    assert!(explanation
        .pointer("/services/household-eligibility/claims/household-eligible/cel")
        .and_then(serde_json::Value::as_str)
        .is_some());
    assert!(explanation
        .pointer("/services/household-eligibility/credentials")
        .is_some());
    assert!(explanation["integrations"]["eligibility"]["operations"]
        .as_array()
        .is_some_and(|operations| operations.iter().any(|operation| {
            operation.get("body").is_some() && operation.get("query").is_some()
        })));

    let options = CountryBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    };
    let first = build_country_project(&options).expect("first build");
    let output = PathBuf::from(first.output.expect("build output"));
    let first_closure = directory_closure(&output);
    build_country_project(&options).expect("second build");
    assert_eq!(first_closure, directory_closure(&output));
    assert_eq!(
        closure_digest(&first_closure),
        "6a9b652ecbca8a0d286a1557499aac51a595d0cb90cd9c4d508604bfffde2a7a",
        "country product inputs must match the cross-machine golden digest"
    );
}

#[test]
fn records_and_snapshot_exact_share_one_generated_materialization() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("snapshot-exact", temporary.path());
    let build = build_country_project(&CountryBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("records plus evidence golden builds through production validation");
    let output = PathBuf::from(build.output.expect("build output"));
    let relay_root = output.join("private/relay");
    let relay: serde_json::Value = serde_yaml::from_slice(
        &std::fs::read(relay_root.join("config/relay.yaml")).expect("Relay config reads"),
    )
    .expect("Relay config parses");
    let datasets = relay["datasets"]
        .as_array()
        .expect("datasets are generated");
    assert_eq!(datasets.len(), 1);
    let dataset = &datasets[0];
    assert_eq!(dataset["id"], "people");
    let tables = dataset["tables"].as_array().expect("private table exists");
    assert_eq!(tables.len(), 1, "one source must produce one ingest plan");
    let resource = tables[0]["id"].as_str().expect("resource id");
    let provider = format!("people__{resource}");
    assert_eq!(
        dataset["entities"].as_array().expect("entity exists").len(),
        1
    );
    let entity = &dataset["entities"][0];
    assert_eq!(entity["table"], resource);
    assert_eq!(entity["api"]["default_limit"], 50);
    assert_eq!(entity["api"]["max_limit"], 100);
    assert_eq!(entity["api"]["require_purpose_header"], true);
    assert_eq!(
        entity["api"]["required_filter_bindings"][0]["source"],
        "principal_id"
    );
    assert!(entity["api"]["allowed_filters"]
        .as_array()
        .is_some_and(|filters| filters.len() == 3));
    assert!(entity["relationships"]
        .as_array()
        .is_some_and(|relationships| relationships.len() == 1));
    assert!(entity["aggregates"]
        .as_array()
        .is_some_and(|aggregates| aggregates.len() == 1));

    let binding_root = relay_root.join("config/artifacts/private-bindings");
    let mut binding_count = 0;
    for entry in std::fs::read_dir(binding_root).expect("private bindings read") {
        let binding: serde_json::Value = serde_json::from_slice(
            &std::fs::read(entry.expect("binding entry").path()).expect("binding reads"),
        )
        .expect("binding parses");
        assert_eq!(binding["materialization"]["table_provider"], provider);
        binding_count += 1;
    }
    assert_eq!(
        binding_count, 2,
        "both evidence purposes share the provider"
    );

    let review: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.join("reviewable/review.json")).expect("review reads"),
    )
    .expect("review parses");
    assert_eq!(
        review["entity_materializations"]["people"]["materialization_identity"],
        resource
    );
    assert_eq!(
        review["entity_materializations"]["people"]["table_provider"],
        provider
    );
}

#[test]
fn records_standards_share_the_validated_materialization() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("snapshot-exact", temporary.path());
    let records_path = project.join("records/people.yaml");
    let mut records = read_yaml(&records_path);
    records["fields"]["longitude"] =
        serde_yaml::from_str("type: number\nnullable: true\n").expect("longitude field");
    records["fields"]["latitude"] =
        serde_yaml::from_str("type: number\nnullable: true\n").expect("latitude field");
    records["api"]["standards"]["ogc_features"] = serde_yaml::from_str(
        r#"collection_id: people
title: Population locations
geometry:
  kind: point
  longitude_field: longitude
  latitude_field: latitude
  crs: http://www.opengis.net/def/crs/OGC/1.3/CRS84
max_bbox_degrees: 5
max_geometry_vertices: 1
"#,
    )
    .expect("OGC spatial mapping");
    records["api"]["standards"]["sp_dci"] = serde_yaml::from_str(
        r#"registry: population
registry_type: civil-registry
record_type: person
identifiers: { person_id: person_id }
expression_fields: { registration_status: registration_status }
response_fields: { eligible: eligible }
"#,
    )
    .expect("SP DCI mapping");
    write_yaml(&records_path, &records);

    let environment_path = project.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["entities"]["people"]["columns"]["longitude"] =
        serde_yaml::Value::String("longitude_deg".to_string());
    environment["entities"]["people"]["columns"]["latitude"] =
        serde_yaml::Value::String("latitude_deg".to_string());
    write_yaml(&environment_path, &environment);

    let build = build_country_project(&CountryBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("enabled records standards build through Relay production validation");
    let output = PathBuf::from(build.output.expect("build output"));
    let relay: serde_json::Value = serde_yaml::from_slice(
        &std::fs::read(output.join("private/relay/config/relay.yaml")).expect("Relay config reads"),
    )
    .expect("Relay config parses");
    let dataset = &relay["datasets"][0];
    assert_eq!(dataset["tables"].as_array().map(Vec::len), Some(1));
    assert_eq!(dataset["entities"][0]["table"], dataset["tables"][0]["id"]);
    assert_eq!(
        dataset["entities"][0]["spatial"]["geometry"]["kind"],
        "point"
    );
    assert_eq!(
        relay["standards"]["spdci"]["registries"]["population"]["dataset"],
        "people"
    );
    assert_eq!(
        relay["standards"]["spdci"]["registries"]["population"]["entity"],
        "people"
    );
}

#[test]
fn records_environment_mapping_fails_closed() {
    let temporary = tempfile::tempdir().expect("temporary directory");

    let duplicate = copy_project("snapshot-exact", temporary.path());
    replace_in_file(
        &duplicate.join("environments/local.yaml"),
        "guardian_id: guardian_key",
        "guardian_id: subject_key",
    );
    let error = check_country_project(&CountryCheckOptions {
        project_directory: duplicate,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("non-injective physical mapping must fail");
    assert!(format!("{error:#}").contains("must be injective"));

    let missing = temporary.path().join("missing");
    copy_tree(&golden("snapshot-exact"), &missing);
    replace_in_file(
        &missing.join("environments/local.yaml"),
        "      guardian_id: guardian_key\n",
        "",
    );
    let error = check_country_project(&CountryCheckOptions {
        project_directory: missing,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("missing logical field mapping must fail");
    assert!(format!("{error:#}").contains("every logical field exactly once"));

    let physical = temporary.path().join("physical");
    copy_tree(&golden("snapshot-exact"), &physical);
    let records = physical.join("records/people.yaml");
    let mut authored = std::fs::read_to_string(&records).expect("records reads");
    authored.push_str("path: /private/people.csv\n");
    std::fs::write(&records, authored).expect("hostile records writes");
    let error = check_country_project(&CountryCheckOptions {
        project_directory: physical,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("physical provider member in logical records must fail");
    assert!(format!("{error:#}").contains("unknown field"));
}

#[test]
fn records_provider_change_requires_a_new_generation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("snapshot-exact", temporary.path());
    let initial = build_country_project(&CountryBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("initial records build passes");
    let output = PathBuf::from(initial.output.expect("initial output"));
    let private_key = temporary.path().join("records-private.jwk");
    let public_key = temporary.path().join("records-public.jwk");
    let anchor = temporary.path().join("records-anchor.json");
    let baseline = temporary.path().join("records-baseline");
    std::fs::write(&private_key, TEST_PRIVATE_JWK).expect("private key writes");
    std::fs::write(&public_key, TEST_PUBLIC_JWK).expect("public key writes");
    init_config_anchor(
        &anchor,
        "registry-notary".to_string(),
        "local".to_string(),
        "country-authoring".to_string(),
        "country-instance".to_string(),
    )
    .expect("anchor initializes");
    add_config_anchor_key(&anchor, &public_key, true).expect("anchor key adds");
    sign_config_bundle(BundleSignOptions {
        input: output.join("private/notary"),
        key: private_key.display().to_string(),
        product: "registry-notary".to_string(),
        environment: "local".to_string(),
        stream_id: "country-authoring".to_string(),
        instance_id: Some("country-instance".to_string()),
        sequence: 1,
        bundle_id: "records-baseline".to_string(),
        out: baseline.clone(),
    })
    .expect("records baseline signs");

    let environment = project.join("environments/local.yaml");
    replace_in_file(
        &environment,
        "/var/lib/registry/population.csv",
        "/var/lib/registry/population-next.csv",
    );
    let error = check_country_project(&CountryCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: Some(baseline.clone()),
        anchor: Some(anchor.clone()),
    })
    .expect_err("provider change with reused generation must fail");
    assert!(format!("{error:#}").contains("without a new generation"));

    replace_in_file(
        &environment,
        "generation: 2026-07-12",
        "generation: 2026-07-13",
    );
    let report = check_country_project(&CountryCheckOptions {
        project_directory: project,
        environment: "local".to_string(),
        explain: false,
        against: Some(baseline),
        anchor: Some(anchor),
    })
    .expect("provider change with a new generation checks");
    assert!(report
        .required_reviews
        .contains(&ReviewClass::OperatorSecurity));
}

#[test]
fn every_required_golden_builds_registry_backed_notary_without_transitional_sources() {
    #[cfg(not(target_os = "linux"))]
    let project_names = [
        "custom-system",
        "dhis2-tracker",
        "fhir-r4-coverage-active",
        "opencrvs",
        "opencrvs-country-variant",
        "openspp-exact",
        "snapshot-exact",
    ];
    #[cfg(target_os = "linux")]
    let project_names = [
        "custom-system",
        "dhis2-tracker",
        "dhis2-sandboxed-rhai",
        "fhir-r4-coverage-active",
        "opencrvs",
        "opencrvs-country-variant",
        "openspp-exact",
        "snapshot-exact",
    ];
    for project_name in project_names {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project(project_name, temporary.path());
        let check = check_country_project(&CountryCheckOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            explain: true,
            against: None,
            anchor: None,
        })
        .unwrap_or_else(|error| panic!("{project_name} check failed: {error:#}"));
        assert_eq!(check.status, "valid", "{project_name}");
        assert_eq!(check.baseline, "initial_without_baseline", "{project_name}");
        assert_eq!(check.required_reviews.len(), 4, "{project_name}");
        assert!(check.explanation.is_some(), "{project_name}");

        let build = build_country_project(&CountryBuildOptions {
            project_directory: project,
            environment: "local".to_string(),
            against: None,
            anchor: None,
        })
        .unwrap_or_else(|error| panic!("{project_name} build failed: {error:#}"));
        let output = PathBuf::from(build.output.expect("build output"));
        assert!(output.join("reviewable/review.json").is_file());
        assert!(output.join("private/relay/config/relay.yaml").is_file());
        let notary_config_path = output.join("private/notary/config/notary.yaml");
        let notary_config = std::fs::read_to_string(&notary_config_path)
            .unwrap_or_else(|error| panic!("{}: {error}", notary_config_path.display()));
        for forbidden in [
            "transitional_direct",
            "source_connections",
            "source_bindings",
        ] {
            assert!(
                !notary_config.contains(forbidden),
                "{project_name} generated Notary config must not contain {forbidden}"
            );
        }
        for product in ["relay", "notary"] {
            assert!(output
                .join(format!("private/{product}/descriptors/operations.json"))
                .is_file());
            assert!(output
                .join(format!(
                    "private/{product}/descriptors/secret-consumers.json"
                ))
                .is_file());
        }
        let relay_descriptor: serde_json::Value = serde_json::from_slice(
            &std::fs::read(output.join("private/relay/descriptors/secret-consumers.json"))
                .expect("Relay secret descriptor reads"),
        )
        .expect("Relay secret descriptor parses");
        assert!(relay_descriptor["consumers"]
            .as_array()
            .is_some_and(|consumers| {
                consumers
                    .iter()
                    .any(|consumer| consumer["locator"] == "REGISTRY_RELAY_AUDIT_PSEUDONYM_EPOCH_1")
            }));
        let notary_descriptor: serde_json::Value = serde_json::from_slice(
            &std::fs::read(output.join("private/notary/descriptors/secret-consumers.json"))
                .expect("Notary secret descriptor reads"),
        )
        .expect("Notary secret descriptor parses");
        assert!(notary_descriptor["consumers"]
            .as_array()
            .is_some_and(|consumers| {
                consumers.iter().any(|consumer| {
                    consumer["locator"]
                        .as_str()
                        .is_some_and(|locator| locator.ends_with("_TOKEN_HASH"))
                })
            }));
    }

    #[cfg(not(target_os = "linux"))]
    {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project("dhis2-sandboxed-rhai", temporary.path());
        let error = check_country_project(&CountryCheckOptions {
            project_directory: project,
            environment: "local".to_string(),
            explain: true,
            against: None,
            anchor: None,
        })
        .expect_err("ordinary Rhai activation must remain platform-gated");
        assert!(
            format!("{error:#}").contains("consultation service plan is unsupported"),
            "{error:#}"
        );
    }
}

#[test]
fn generated_product_inputs_sign_and_verify_without_secret_values() {
    const SECRET_SENTINEL: &str = "country-authoring-secret-sentinel-8f9d7537";

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    std::env::set_var("HOUSEHOLD_PASSWORD", SECRET_SENTINEL);
    let build = build_country_project(&CountryBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("country project builds");
    std::env::remove_var("HOUSEHOLD_PASSWORD");
    let output = PathBuf::from(build.output.expect("build output"));
    assert!(directory_closure(&output).iter().all(|(_, bytes)| !bytes
        .windows(SECRET_SENTINEL.len())
        .any(|window| window == SECRET_SENTINEL.as_bytes())));

    let private_key = temporary.path().join("private.jwk");
    let public_key = temporary.path().join("public.jwk");
    std::fs::write(&private_key, TEST_PRIVATE_JWK).expect("private test key writes");
    std::fs::write(&public_key, TEST_PUBLIC_JWK).expect("public test key writes");
    for (product, input) in [
        ("registry-relay", output.join("private/relay")),
        ("registry-notary", output.join("private/notary")),
    ] {
        let bundle = temporary.path().join(format!("{product}-bundle"));
        let anchor = temporary.path().join(format!("{product}-anchor.json"));
        init_config_anchor(
            &anchor,
            product.to_string(),
            "local".to_string(),
            "country-authoring".to_string(),
            "country-instance".to_string(),
        )
        .expect("anchor initializes");
        add_config_anchor_key(&anchor, &public_key, true).expect("anchor key adds");
        sign_config_bundle(BundleSignOptions {
            input,
            key: private_key.display().to_string(),
            product: product.to_string(),
            environment: "local".to_string(),
            stream_id: "country-authoring".to_string(),
            instance_id: Some("country-instance".to_string()),
            sequence: 1,
            bundle_id: format!("{product}-golden"),
            out: bundle.clone(),
        })
        .expect("generated input signs");
        let verified = verify_config_bundle_cli(&bundle, &anchor).expect("signed bundle verifies");
        assert_eq!(verified.product, product);
        assert_eq!(verified.signer_kids.len(), 1);
    }
}

#[cfg(unix)]
#[test]
fn generated_country_output_is_owner_only() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let build = build_country_project(&CountryBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("country project builds");
    let output = PathBuf::from(build.output.expect("build output"));
    assert_owner_only(&output);
}

#[test]
fn authored_request_literals_cannot_smuggle_secret_material() {
    const SECRET_SENTINEL: &str = "country-authoring-request-secret-4e198da1";

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let integration_path = project.join("integrations/eligibility/integration.yaml");
    let integration = std::fs::read_to_string(&integration_path)
        .expect("integration reads")
        .replace(
            "projection: { value: key }",
            &format!("password: {{ value: {SECRET_SENTINEL} }}"),
        );
    std::fs::write(&integration_path, integration).expect("hostile integration writes");
    let error = check_country_project(&CountryCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("secret-shaped request field must fail closed");
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("cannot carry credential material"));
    assert!(!diagnostic.contains(SECRET_SENTINEL));
    assert!(!project.join(".registry-stack/build").exists());

    for header in ["X-API-Key", "X-Auth-Token", "api_key_2"] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project("custom-system", temporary.path());
        let integration_path = project.join("integrations/eligibility/integration.yaml");
        let integration = std::fs::read_to_string(&integration_path)
            .expect("integration reads")
            .replace(
                "          path: /consultations/eligibility\n",
                &format!(
                    "          path: /consultations/eligibility\n          headers:\n            {header}: {{ value: {SECRET_SENTINEL} }}\n"
                ),
            );
        std::fs::write(&integration_path, integration).expect("hostile integration writes");
        let error = check_country_project(&CountryCheckOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            explain: false,
            against: None,
            anchor: None,
        })
        .expect_err("credential-bearing header must fail closed");
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("closed non-credential allow-list"));
        assert!(!diagnostic.contains(SECRET_SENTINEL));
        assert!(!project.join(".registry-stack/build").exists());
    }
}

#[test]
fn verified_signed_baseline_classifies_semantic_review_dimensions_independently() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let integration_file = project.join("integrations/eligibility/integration.yaml");
    let integration = std::fs::read_to_string(&integration_file)
        .expect("integration reads")
        .replace(
            "unverified: [fixture-contract-v2]",
            "unverified: [fixture-contract-v2, fixture-contract-v3]",
        );
    std::fs::write(&integration_file, integration).expect("second reviewed version writes");
    let initial = build_country_project(&CountryBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("initial country build passes");
    let output = PathBuf::from(initial.output.expect("initial build output"));
    let private_key = temporary.path().join("baseline-private.jwk");
    let public_key = temporary.path().join("baseline-public.jwk");
    let anchor = temporary.path().join("baseline-anchor.json");
    let baseline = temporary.path().join("baseline-bundle");
    std::fs::write(&private_key, TEST_PRIVATE_JWK).expect("private test key writes");
    std::fs::write(&public_key, TEST_PUBLIC_JWK).expect("public test key writes");
    init_config_anchor(
        &anchor,
        "registry-notary".to_string(),
        "local".to_string(),
        "country-authoring".to_string(),
        "country-instance".to_string(),
    )
    .expect("baseline anchor initializes");
    add_config_anchor_key(&anchor, &public_key, true).expect("baseline key adds");
    sign_config_bundle(BundleSignOptions {
        input: output.join("private/notary"),
        key: private_key.display().to_string(),
        product: "registry-notary".to_string(),
        environment: "local".to_string(),
        stream_id: "country-authoring".to_string(),
        instance_id: Some("country-instance".to_string()),
        sequence: 1,
        bundle_id: "country-authoring-baseline".to_string(),
        out: baseline.clone(),
    })
    .expect("baseline signs");

    let initial_review: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.join("reviewable/review.json")).expect("initial review reads"),
    )
    .expect("initial review parses");
    assert!(initial_review["baseline"].is_null());
    assert!(initial_review["disclosure_profiles"].is_object());
    for class in [
        "claim",
        "integration",
        "country_policy",
        "operator_security",
    ] {
        assert!(
            initial_review["review_digests"][class].is_string(),
            "{class}"
        );
    }

    let reviewed_build = build_country_project(&CountryBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: Some(baseline.clone()),
        anchor: Some(anchor.clone()),
    })
    .expect("verified-baseline build passes");
    let reviewed_output = PathBuf::from(reviewed_build.output.expect("reviewed build output"));
    let reviewed_record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(reviewed_output.join("reviewable/review.json"))
            .expect("reviewed record reads"),
    )
    .expect("reviewed record parses");
    assert_eq!(
        reviewed_record["baseline"]["review_digests"],
        initial_review["review_digests"]
    );
    assert!(reviewed_record["review_digests"]
        .as_object()
        .expect("current review digest slots")
        .values()
        .all(serde_json::Value::is_null));
    assert_eq!(
        reviewed_record["baseline"]["verified_manifest"]["schema"],
        "registry.platform.config_bundle.v1"
    );
    assert!(reviewed_record["baseline"]["verified_manifest"]["files"].is_array());

    let unchanged = check_country_project(&CountryCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: Some(baseline.clone()),
        anchor: Some(anchor.clone()),
    })
    .expect("unchanged project checks against signed baseline");
    assert_eq!(unchanged.baseline, "verified_signed_bundle");
    assert!(unchanged.required_reviews.is_empty());

    let scenarios = temporary.path().join("scenarios");
    std::fs::create_dir(&scenarios).expect("scenario root creates");
    let claim_project = scenarios.join("claim");
    let source_version_project = scenarios.join("source-version");
    let operator_project = scenarios.join("operator");
    let policy_project = scenarios.join("policy");
    let consultation_project = scenarios.join("consultation");
    for destination in [
        &claim_project,
        &source_version_project,
        &operator_project,
        &policy_project,
        &consultation_project,
    ] {
        copy_tree(&project, destination);
    }

    let project_file = claim_project.join("registry-stack.yaml");
    let authored = std::fs::read_to_string(&project_file)
        .expect("project reads")
        .replace(
            "household.approved != null ? household.exists && household.approved : false",
            "household.approved != null ? household.exists && household.approved == true : false",
        );
    std::fs::write(&project_file, authored).expect("claim-only edit writes");
    let changed = check_country_project(&CountryCheckOptions {
        project_directory: claim_project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: Some(baseline.clone()),
        anchor: Some(anchor.clone()),
    })
    .expect("claim-only edit checks against signed baseline");
    assert_eq!(
        changed.required_reviews,
        BTreeSet::from([ReviewClass::Claim])
    );

    let compiler_input = temporary.path().join("compiler-baseline-input");
    copy_tree(&output.join("private/notary"), &compiler_input);
    let compiler_review_path = compiler_input.join("approval/review.json");
    let mut compiler_review: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&compiler_review_path).expect("compiler baseline review reads"),
    )
    .expect("compiler baseline review parses");
    compiler_review["compiler_version"] = serde_json::Value::String("0.0.0".to_string());
    std::fs::write(
        &compiler_review_path,
        serde_json::to_vec(&compiler_review).expect("compiler baseline review serializes"),
    )
    .expect("compiler baseline review writes");
    let compiler_baseline = temporary.path().join("compiler-baseline-bundle");
    sign_config_bundle(BundleSignOptions {
        input: compiler_input,
        key: private_key.display().to_string(),
        product: "registry-notary".to_string(),
        environment: "local".to_string(),
        stream_id: "country-authoring".to_string(),
        instance_id: Some("country-instance".to_string()),
        sequence: 2,
        bundle_id: "country-authoring-compiler-baseline".to_string(),
        out: compiler_baseline.clone(),
    })
    .expect("compiler baseline signs");
    assert_review_classes(
        claim_project,
        &compiler_baseline,
        &anchor,
        BTreeSet::from([
            ReviewClass::Claim,
            ReviewClass::Integration,
            ReviewClass::CountryPolicy,
            ReviewClass::OperatorSecurity,
        ]),
    );

    replace_in_file(
        &source_version_project.join("environments/local.yaml"),
        "source_version: fixture-contract-v2",
        "source_version: fixture-contract-v3",
    );
    assert_review_classes(
        source_version_project,
        &baseline,
        &anchor,
        BTreeSet::from([ReviewClass::Integration]),
    );

    replace_in_file(
        &operator_project.join("environments/local.yaml"),
        "https://household-authority.invalid",
        "https://household-authority-two.invalid",
    );
    assert_review_classes(
        operator_project,
        &baseline,
        &anchor,
        BTreeSet::from([ReviewClass::OperatorSecurity]),
    );

    replace_in_file(
        &policy_project.join("registry-stack.yaml"),
        "legal_basis: public-service-delivery",
        "legal_basis: statutory-benefit-screening",
    );
    assert_review_classes(
        policy_project,
        &baseline,
        &anchor,
        BTreeSet::from([ReviewClass::CountryPolicy]),
    );

    replace_in_file(
        &consultation_project.join("registry-stack.yaml"),
        "request.target.identifiers.household_reference",
        "request.target.identifiers.household_case_number",
    );
    assert_review_classes(
        consultation_project,
        &baseline,
        &anchor,
        BTreeSet::from([ReviewClass::Integration]),
    );
}

fn assert_review_classes(
    project: PathBuf,
    baseline: &Path,
    anchor: &Path,
    expected: BTreeSet<ReviewClass>,
) {
    let report = check_country_project(&CountryCheckOptions {
        project_directory: project,
        environment: "local".to_string(),
        explain: false,
        against: Some(baseline.to_path_buf()),
        anchor: Some(anchor.to_path_buf()),
    })
    .expect("semantic review scenario checks against signed baseline");
    assert_eq!(report.required_reviews, expected);
}

fn replace_in_file(path: &Path, from: &str, to: &str) {
    let contents = std::fs::read_to_string(path).expect("scenario file reads");
    assert!(contents.contains(from), "replacement source must exist");
    std::fs::write(path, contents.replace(from, to)).expect("scenario file writes");
}

fn extend_exact_selector(project: &Path, golden_name: &str, size: usize) {
    let (integration_relative, alias, original_input) = match golden_name {
        "custom-system" => (
            "integrations/eligibility/integration.yaml",
            "eligibility",
            "household_reference",
        ),
        "snapshot-exact" => (
            "integrations/person-snapshot/integration.yaml",
            "person-snapshot",
            "person_id",
        ),
        _ => panic!("unsupported selector test golden"),
    };
    let integration_path = project.join(integration_relative);
    let mut integration = read_yaml(&integration_path);
    for component in 2..=size {
        let name = format!("selector_{component}");
        let declaration = if component == 4 {
            serde_yaml::from_str(
                "type: full_date\nbytes: 10\npattern: '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'\ncanonicalization: identity\n",
            )
            .expect("full-date input declaration")
        } else {
            serde_yaml::from_str(&format!(
                "type: string\nbytes: 32\npattern: '^S{component}$'\ncanonicalization: identity\n"
            ))
            .expect("string input declaration")
        };
        integration["input"]
            .as_mapping_mut()
            .expect("integration input mapping")
            .insert(serde_yaml::Value::String(name.clone()), declaration);
        if golden_name == "custom-system" {
            integration["capability"]["bounded_http"]["operations"]["resolve"]["request"]["body"]
                .as_mapping_mut()
                .expect("root body mapping")
                .insert(
                    serde_yaml::Value::String(name.clone()),
                    serde_yaml::from_str(&format!("input: {name}\n"))
                        .expect("body input expression"),
                );
        }
    }
    write_yaml(&integration_path, &integration);

    let project_path = project.join("registry-stack.yaml");
    let mut project_document = read_yaml(&project_path);
    let services: &[(&str, &str)] = if golden_name == "custom-system" {
        &[("household-eligibility", "household")]
    } else {
        &[
            ("benefits-eligibility", "person"),
            ("emergency-assistance", "person"),
        ]
    };
    for (service, consultation) in services {
        let mapping =
            &mut project_document["services"][*service]["consultations"][*consultation]["input"];
        for component in 2..=size {
            let name = format!("selector_{component}");
            mapping
                .as_mapping_mut()
                .expect("consultation input mapping")
                .insert(
                    serde_yaml::Value::String(name.clone()),
                    serde_yaml::Value::String(format!("request.target.identifiers.{name}")),
                );
        }
    }
    write_yaml(&project_path, &project_document);

    let fixture_directory = integration_path
        .parent()
        .expect("integration parent")
        .join("fixtures");
    for fixture in std::fs::read_dir(fixture_directory).expect("fixture directory") {
        let path = fixture.expect("fixture entry").path();
        let mut document = read_yaml(&path);
        for component in 2..=size {
            let value = if component == 4 {
                "2017-06-15".to_string()
            } else {
                format!("S{component}")
            };
            document["input"]
                .as_mapping_mut()
                .expect("fixture input mapping")
                .insert(
                    serde_yaml::Value::String(format!("selector_{component}")),
                    serde_yaml::Value::String(value),
                );
        }
        write_yaml(&path, &document);
    }

    if golden_name == "snapshot-exact" {
        let records_path = project.join("records/people.yaml");
        let mut records = read_yaml(&records_path);
        let environment_path = project.join("environments/local.yaml");
        let mut environment = read_yaml(&environment_path);
        for component in 2..=size {
            let name = format!("selector_{component}");
            records["fields"]
                .as_mapping_mut()
                .expect("records fields")
                .insert(
                    serde_yaml::Value::String(name.clone()),
                    serde_yaml::from_str("type: string\n").expect("records selector field"),
                );
            environment["entities"]["people"]["columns"]
                .as_mapping_mut()
                .expect("entity columns")
                .insert(
                    serde_yaml::Value::String(name),
                    serde_yaml::Value::String(format!("selector_col_{component}")),
                );
        }
        write_yaml(&records_path, &records);
        write_yaml(&environment_path, &environment);
    }

    assert!(integration["input"].get(original_input).is_some());
    assert!(integration["id"].as_str().is_some(), "{alias}");
}

fn read_yaml(path: &Path) -> serde_yaml::Value {
    serde_yaml::from_slice(&std::fs::read(path).expect("YAML reads")).expect("YAML parses")
}

fn write_yaml(path: &Path, document: &serde_yaml::Value) {
    std::fs::write(
        path,
        serde_yaml::to_string(document).expect("YAML serializes"),
    )
    .expect("YAML writes");
}

fn reverse_yaml_mapping(path: &Path, keys: &[&str]) {
    let mut document = read_yaml(path);
    let mut current = &mut document;
    for key in keys {
        current = &mut current[*key];
    }
    let mapping = current.as_mapping_mut().expect("selected YAML mapping");
    let mut entries = mapping
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Vec<_>>();
    entries.reverse();
    *mapping = entries.into_iter().collect();
    write_yaml(path, &document);
}

fn remove_custom_cel_claim(project: &Path) {
    let project_path = project.join("registry-stack.yaml");
    let mut document = read_yaml(&project_path);
    let service = &mut document["services"]["household-eligibility"];
    service["claims"]
        .as_mapping_mut()
        .expect("custom claims")
        .remove(serde_yaml::Value::String("household-eligible".to_string()));
    service["credentials"]["household-eligibility"]["claims"]
        .as_sequence_mut()
        .expect("custom credential claims")
        .retain(|claim| claim.as_str() != Some("household-eligible"));
    write_yaml(&project_path, &document);
    for fixture in std::fs::read_dir(project.join("integrations/eligibility/fixtures"))
        .expect("custom fixture directory")
    {
        let path = fixture.expect("fixture entry").path();
        let mut document = read_yaml(&path);
        let claims = document
            .get_mut("expect")
            .and_then(serde_yaml::Value::as_mapping_mut)
            .and_then(|expect| expect.get_mut("claims"))
            .and_then(serde_yaml::Value::as_mapping_mut);
        if let Some(claims) = claims {
            claims.remove(serde_yaml::Value::String("household-eligible".to_string()));
        }
        write_yaml(&path, &document);
    }
}

fn make_opencrvs_composite_dci(project: &Path) {
    let integration_path = project.join("integrations/birth-record/integration.yaml");
    let mut integration = read_yaml(&integration_path);
    integration["input"] = serde_yaml::from_str(
        r#"uin:
  type: string
  bytes: 16
  pattern: "^[0-9]{10}$"
  canonicalization: identity
family:
  type: string
  bytes: 80
  pattern: "^Example$"
  canonicalization: identity
place:
  type: string
  bytes: 120
  pattern: "^Fictional District$"
  canonicalization: identity
"#,
    )
    .expect("composite DCI inputs");
    let body =
        &mut integration["capability"]["bounded_http"]["operations"]["birth"]["request"]["body"];
    body.as_mapping_mut()
        .expect("DCI body")
        .remove(serde_yaml::Value::String("identifier_type".to_string()));
    body["exact_and"] = serde_yaml::from_str(
        r#"uin: { field: identifier_value, response_pointer: /identifier/0/identifier_value }
family: { field: family_name, response_pointer: /child/family_name }
place: { field: place_of_birth, response_pointer: /place_of_birth }
"#,
    )
    .expect("composite DCI predicates");
    write_yaml(&integration_path, &integration);

    let project_path = project.join("registry-stack.yaml");
    let mut project_document = read_yaml(&project_path);
    project_document["services"]["birth-verification"]["consultations"]["birth"]["input"] =
        serde_yaml::from_str(
            r#"uin: request.target.identifiers.uin
family: request.target.identifiers.family
place: request.target.identifiers.place
"#,
        )
        .expect("composite DCI consultation mapping");
    let service = &mut project_document["services"]["birth-verification"];
    service["claims"]
        .as_mapping_mut()
        .expect("OpenCRVS claims")
        .remove(serde_yaml::Value::String("age-band".to_string()));
    service["credentials"]["birth-summary"]["claims"]
        .as_sequence_mut()
        .expect("OpenCRVS credential claims")
        .retain(|claim| claim.as_str() != Some("age-band"));
    write_yaml(&project_path, &project_document);

    let fixture_directory = project.join("integrations/birth-record/fixtures");
    for entry in std::fs::read_dir(&fixture_directory).expect("OpenCRVS fixture directory") {
        let path = entry.expect("OpenCRVS fixture entry").path();
        let retained = matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("match.yaml" | "ambiguous.yaml")
        );
        if !retained {
            std::fs::remove_file(path).expect("unused OpenCRVS fixture removes");
            continue;
        }
        let mut fixture = read_yaml(&path);
        fixture["input"] =
            serde_yaml::from_str("uin: '0000000001'\nfamily: Example\nplace: Fictional District\n")
                .expect("composite DCI fixture inputs");
        if let Some(claims) = fixture
            .get_mut("expect")
            .and_then(serde_yaml::Value::as_mapping_mut)
            .and_then(|expect| expect.get_mut("claims"))
            .and_then(serde_yaml::Value::as_mapping_mut)
        {
            claims.remove(serde_yaml::Value::String("age-band".to_string()));
        }
        write_yaml(&path, &fixture);
    }
}

fn copy_project(name: &str, temporary: &Path) -> PathBuf {
    let destination = temporary.join(name);
    copy_tree(&golden(name), &destination);
    destination
}

fn rename_custom_input(project: &Path, name: &str) {
    let mut paths = vec![
        project.join("registry-stack.yaml"),
        project.join("integrations/eligibility/integration.yaml"),
    ];
    paths.extend(
        std::fs::read_dir(project.join("integrations/eligibility/fixtures"))
            .expect("fixture directory reads")
            .map(|entry| entry.expect("fixture entry").path()),
    );
    for path in paths {
        let contents = std::fs::read_to_string(&path).expect("authored file reads");
        let replaced = contents.replace("household_reference", name);
        assert_ne!(
            contents,
            replaced,
            "{} did not bind the input",
            path.display()
        );
        std::fs::write(path, replaced).expect("renamed authored input writes");
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    std::fs::create_dir(destination).expect("copy destination creates");
    for entry in std::fs::read_dir(source).expect("copy source reads") {
        let entry = entry.expect("copy entry");
        if entry.file_name() == ".registry-stack" {
            continue;
        }
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_tree(&source_path, &destination_path);
        } else {
            std::fs::copy(&source_path, &destination_path).expect("project file copies");
        }
    }
}

fn directory_closure(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    walkdir(root, root, &mut files);
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn closure_digest(files: &[(PathBuf, Vec<u8>)]) -> String {
    use std::fmt::Write as _;

    let mut hasher = Sha256::new();
    for (path, bytes) in files {
        let path = path
            .to_str()
            .expect("generated relative paths are UTF-8")
            .as_bytes();
        hasher.update(
            u64::try_from(path.len())
                .expect("path length fits u64")
                .to_be_bytes(),
        );
        hasher.update(path);
        hasher.update(
            u64::try_from(bytes.len())
                .expect("file length fits u64")
                .to_be_bytes(),
        );
        hasher.update(bytes);
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn walkdir(root: &Path, directory: &Path, output: &mut Vec<(PathBuf, Vec<u8>)>) {
    for entry in std::fs::read_dir(directory).expect("build directory reads") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            walkdir(root, &path, output);
        } else {
            output.push((
                path.strip_prefix(root)
                    .expect("generated path is rooted")
                    .to_path_buf(),
                std::fs::read(path).expect("generated file reads"),
            ));
        }
    }
}

#[cfg(unix)]
fn assert_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = std::fs::metadata(path).expect("generated metadata reads");
    let expected = if metadata.is_dir() { 0o700 } else { 0o600 };
    assert_eq!(
        metadata.permissions().mode() & 0o777,
        expected,
        "{}",
        path.display()
    );
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path).expect("generated directory reads") {
            assert_owner_only(&entry.expect("generated entry reads").path());
        }
    }
}
