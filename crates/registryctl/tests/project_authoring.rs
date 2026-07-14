// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use registryctl::{
    add_config_anchor_key, build_registry_project, check_registry_project, init_config_anchor,
    init_registry_project, sign_config_bundle, test_registry_project, verify_config_bundle_cli,
    BundleSignOptions, ProjectBuildOptions, ProjectCheckOptions, ProjectInitOptions,
    ProjectStarter, ProjectTestOptions,
};
use sha2::{Digest as _, Sha256};

const TEST_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;
const TEST_PUBLIC_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;

fn golden(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/project-authoring")
        .join(name)
}

#[test]
fn every_project_golden_passes_the_offline_journey() {
    for project in [
        "custom-system",
        "dhis2-tracker",
        "fhir-r4-coverage-active",
        "opencrvs",
        "opencrvs-country-variant",
        "openspp-exact",
        "snapshot-exact",
        "snapshot-with-records",
    ] {
        let report = test_registry_project(&ProjectTestOptions {
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
    let report = test_registry_project(&ProjectTestOptions {
        project_directory: golden("fhir-r4-coverage-active"),
        environment: None,
        live: false,
    })
    .expect("FHIR R4 Coverage-active golden passes");
    assert_eq!(report.status, "passed");
    assert!(
        report.fixtures.len() >= 5,
        "the five authored journeys and their derived security cases must execute"
    );
    assert!(report
        .fixtures
        .iter()
        .any(|fixture| fixture.fixture.ends_with("::derived/request_authority")));
    assert!(report.fixtures.iter().any(|fixture| fixture
        .fixture
        .ends_with("::derived/authorization_before_source")));
    assert!(report.fixtures.iter().all(|fixture| fixture.passed));
}

#[test]
fn approved_opencrvs_and_dhis2_claim_sets_execute_offline() {
    for project in ["opencrvs", "opencrvs-country-variant", "dhis2-tracker"] {
        let report = test_registry_project(&ProjectTestOptions {
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
    let report = test_registry_project(&ProjectTestOptions {
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
        .find(|fixture| {
            fixture
                .fixture
                .ends_with("::derived/authorization_before_source")
        })
        .expect("derived authorization fixture report");
    assert!(denied_before_access.passed);
    assert_eq!(
        denied_before_access.expected_error.as_deref(),
        Some("authorization.denied")
    );
    assert_eq!(denied_before_access.source_access, Some(false));

    let denied_after_access = report
        .fixtures
        .iter()
        .find(|fixture| fixture.fixture.ends_with("::derived/malformed_decode"))
        .expect("derived malformed-response fixture report");
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
        golden("dhis2-sandboxed-rhai").join("integrations/health-record/adapter.rhai"),
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
fn local_rhai_modules_are_a_static_hash_covered_closure() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("dhis2-sandboxed-rhai", temporary.path());
    let integration_directory = project.join("integrations/health-record");
    std::fs::create_dir(integration_directory.join("lib")).expect("module directory creates");
    let module = integration_directory.join("lib/normalize.rhai");
    std::fs::write(&module, "fn normalize_status(value) { value }\n").expect("local module writes");
    let integration_path = integration_directory.join("integration.yaml");
    let mut integration = read_yaml(&integration_path);
    integration["capability"]["script"]["modules"] =
        serde_yaml::from_str("[lib/normalize.rhai]").expect("module list");
    write_yaml(&integration_path, &integration);

    let options = ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    };
    let first = build_registry_project(&options).expect("project with local module builds");
    let first_output = PathBuf::from(first.output.expect("first build output"));
    let compiled_path = first_output.join("private/relay/config/artifacts/rhai/health-record.rhai");
    let compiled = std::fs::read_to_string(&compiled_path).expect("compiled closure reads");
    assert!(compiled.contains("registry-local-module:lib/normalize.rhai"));
    assert!(compiled.contains("fn normalize_status(value)"));
    assert!(compiled.contains("registry-entrypoint:adapter.rhai"));
    let first_closure = directory_closure(&first_output);

    std::fs::write(&module, "fn normalize_status(value) { value == () }\n")
        .expect("local module changes");
    let second = build_registry_project(&options).expect("changed local module builds");
    let second_output = PathBuf::from(second.output.expect("second build output"));
    assert_ne!(
        closure_digest(&first_closure),
        closure_digest(&directory_closure(&second_output)),
        "changing a local module must change the generated project closure"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn public_rhai_commands_accept_the_released_contract_for_an_unknown_product() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let baseline_root = temporary.path().join("baseline");
    let changed_root = temporary.path().join("changed");
    let absent_root = temporary.path().join("absent");
    std::fs::create_dir(&baseline_root).expect("baseline root creates");
    std::fs::create_dir(&changed_root).expect("changed root creates");
    std::fs::create_dir(&absent_root).expect("absent root creates");
    let baseline = copy_project("dhis2-sandboxed-rhai", &baseline_root);
    let project = copy_project("dhis2-sandboxed-rhai", &changed_root);
    replace_in_file(
        &project.join("integrations/health-record/integration.yaml"),
        "product: dhis2",
        "product: fictional-health-registry",
    );
    replace_in_file(
        &project.join("integrations/health-record/integration.yaml"),
        "versions: { unverified: [2.41.9] }",
        "versions: { unverified: [7.3] }",
    );

    let metadata_free = copy_project("dhis2-sandboxed-rhai", &absent_root);
    let metadata_free_integration =
        metadata_free.join("integrations/health-record/integration.yaml");
    let mut integration = read_yaml(&metadata_free_integration);
    let source = integration["source"]
        .as_mapping_mut()
        .expect("Rhai source mapping");
    source.remove(serde_yaml::Value::String("product".to_string()));
    source.remove(serde_yaml::Value::String("versions".to_string()));
    write_yaml(&metadata_free_integration, &integration);

    let exercise = |project_directory: PathBuf| {
        let test_report = test_registry_project(&ProjectTestOptions {
            project_directory: project_directory.clone(),
            environment: None,
            live: false,
        })
        .expect("released Rhai contract tests independent of product metadata");
        assert_eq!(test_report.status, "passed");

        let check_report = check_registry_project(&ProjectCheckOptions {
            project_directory: project_directory.clone(),
            environment: "local".to_string(),
            explain: false,
            against: None,
            anchor: None,
        })
        .expect("product-neutral Rhai project checks");
        assert_eq!(check_report.status, "valid");

        let build_report = build_registry_project(&ProjectBuildOptions {
            project_directory,
            environment: "local".to_string(),
            against: None,
            anchor: None,
        })
        .expect("product-neutral Rhai project builds");
        assert_eq!(build_report.status, "built");
        let output = PathBuf::from(build_report.output.expect("build output"));
        let pack: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                output.join("private/relay/config/artifacts/integration-packs/health-record.json"),
            )
            .expect("Rhai integration pack reads"),
        )
        .expect("Rhai integration pack parses");
        (
            serde_json::to_value(test_report.fixtures).expect("fixture reports serialize"),
            pack["spec"]["plan"]["kind"].clone(),
            pack["spec"]["plan"]["rhai"]["script_hash"].clone(),
        )
    };

    let baseline_dispatch = exercise(baseline);
    let changed_dispatch = exercise(project);
    let absent_dispatch = exercise(metadata_free);
    assert_eq!(baseline_dispatch, changed_dispatch);
    assert_eq!(baseline_dispatch, absent_dispatch);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn project_authoring_rhai_commands_are_portable_offline() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("dhis2-sandboxed-rhai", temporary.path());

    let test_report = test_registry_project(&ProjectTestOptions {
        project_directory: project.clone(),
        environment: None,
        live: false,
    })
    .expect("portable offline Rhai test passes without production activation");
    assert_eq!(test_report.status, "passed");

    let check_report = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect("portable project check compiles the reviewed Rhai program");
    assert_eq!(check_report.status, "valid");

    let build_report = build_registry_project(&ProjectBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("portable project build compiles product inputs");
    assert_eq!(build_report.status, "built");
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
        "fn consult(input) { result.no_match() }",
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
fn production_cel_worker_evaluates_project_date_policy() {
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
        .expect("production CEL worker evaluates the project date policy");
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
        ProjectStarter::Http,
        ProjectStarter::Dhis2Tracker,
        ProjectStarter::OpencrvsDci,
        ProjectStarter::FhirR4,
        ProjectStarter::Snapshot,
    ] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = temporary.path().join("registry-project");
        let initialized = init_registry_project(&ProjectInitOptions {
            starter,
            directory: project.clone(),
        })
        .expect("starter initializes");
        assert_eq!(initialized.status, "initialized");
        let provenance = initialized
            .explanation
            .as_ref()
            .expect("starter initialization reports provenance");
        assert_eq!(provenance["state"], "matches");
        assert!(provenance["id"].as_str().is_some());
        assert_eq!(provenance["release"], env!("CARGO_PKG_VERSION"));
        let tested = test_registry_project(&ProjectTestOptions {
            project_directory: project,
            environment: None,
            live: false,
        })
        .expect("initialized starter passes offline tests");
        assert_eq!(tested.status, "passed");
    }
}

#[test]
fn check_explain_reports_starter_divergence_and_runtime_abi() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("registry-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: project.clone(),
    })
    .expect("starter initializes");

    let project_file = project.join("registry-stack.yaml");
    let authored = std::fs::read_to_string(&project_file).expect("project file");
    std::fs::write(
        &project_file,
        authored.replace("fictional-citizen-registry", "adapted-citizen-registry"),
    )
    .expect("project identity is adapted");

    let checked = check_registry_project(&ProjectCheckOptions {
        project_directory: project,
        environment: "local".to_string(),
        explain: true,
        against: None,
        anchor: None,
    })
    .expect("adapted starter remains valid");
    let explanation = checked.explanation.expect("explanation");
    assert_eq!(explanation["starter"]["id"], "http");
    assert_eq!(explanation["starter"]["state"], "diverged");
    assert_ne!(
        explanation["starter"]["expected_content_digest"],
        explanation["starter"]["current_content_digest"]
    );
    assert_eq!(
        explanation["platform"]["defaults_release"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(explanation["platform"]["script_runtime"], "rhai_v1");
    assert_eq!(explanation["platform"]["script_abi"], "xw.v1");
}

#[test]
fn http_starter_adapts_to_a_structurally_different_source_api() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("adapted-registry-api");
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/project-starters/bounded-http"),
        &project,
    );
    let integration = project.join("integrations/person-record/integration.yaml");
    std::fs::write(
        &integration,
        r#"version: 1
id: fictional-municipal-person-record
revision: 1
source:
  product: unanticipated-municipal-api
  versions: { unverified: [municipal-contract-v3] }
  auth: { type: static_bearer }
input:
  municipal_reference:
    role: selector
    type: string
    maxLength: 9
    pattern: "^[A-Z]{2}-[0-9]{6}$"
capability:
  http:
    request:
      method: GET
      path: /municipal/registry/lookup
      query:
        reference: { input: municipal_reference }
        include: status,category
    response:
      no_match: [404]
      ambiguous: [409]
outputs:
  status: { type: [string, "null"], maxLength: 24, x-registry-source: /record/status }
  category: { type: [string, "null"], maxLength: 32, x-registry-source: /record/category }
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
classification: synthetic
input: { municipal_reference: AB-123456 }
interactions:
  - expect:
      method: GET
      path: /municipal/registry/lookup
      query: { reference: AB-123456, include: "status,category" }
    respond:
      status: 200
      body: { record: { status: ACTIVE, category: RESIDENT, ignored_additive_field: safe } }
expect:
  outcome: match
  outputs: { status: ACTIVE, category: RESIDENT }
  claims: { person-record-exists: true, person-status: ACTIVE }
"#,
    )
    .expect("adapted fixture writes");
    let project_file = project.join("registry-stack.yaml");
    let mut project_document = read_yaml(&project_file);
    let service = &mut project_document["services"]["person-verification"];
    service["purpose"] = serde_yaml::Value::String("municipal-benefit-screening".to_string());
    service["consultations"]["person_record"]["input"] = serde_yaml::from_str(
        "municipal_reference: request.target.identifiers.registry_person_id\n",
    )
    .expect("adapted consultation input");
    service["claims"]
        .as_mapping_mut()
        .expect("starter claims")
        .remove(serde_yaml::Value::String("person-active".to_string()));
    service["claims"]
        .as_mapping_mut()
        .expect("starter claims")
        .insert(
            serde_yaml::Value::String("person-status".to_string()),
            serde_yaml::from_str("output: person_record.status\ndisclosure: value\n")
                .expect("adapted status claim"),
        );
    service["credential_profiles"]["person-status"]["claims"]
        .as_sequence_mut()
        .expect("starter credential claims")
        .iter_mut()
        .for_each(|claim| {
            if claim.as_str() == Some("person-active") {
                *claim = serde_yaml::Value::String("person-status".to_string());
            }
        });
    write_yaml(&project_file, &project_document);

    let report = check_registry_project(&ProjectCheckOptions {
        project_directory: project,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect("structurally adapted starter compiles and executes");
    assert!(report
        .semantic_changes
        .iter()
        .any(|change| change.dimension == "integration"));
    assert!(report
        .semantic_changes
        .iter()
        .any(|change| change.dimension == "service_policy"));
}

#[test]
fn source_product_is_metadata_not_runtime_dispatch() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    for (name, integration, product) in [
        (
            "fhir-r4-coverage-active",
            "integrations/coverage/integration.yaml",
            "project-fhir-server",
        ),
        (
            "opencrvs",
            "integrations/birth-record/integration.yaml",
            "opencrvs",
        ),
    ] {
        let case_root = temporary.path().join(format!("case-{name}"));
        std::fs::create_dir(&case_root).expect("case root creates");
        let case = copy_project(name, &case_root);
        replace_in_file(
            &case.join(integration),
            &format!("product: {product}"),
            "product: previously-unknown-source-system",
        );
        let report = test_registry_project(&ProjectTestOptions {
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
        "product: previously-unknown-source-system",
    );
    replace_in_file(
        &project.join("integrations/eligibility/integration.yaml"),
        "unverified: [fixture-contract-v2]",
        "unverified: [project-contract-99]",
    );
    let offline = test_registry_project(&ProjectTestOptions {
        project_directory: project.clone(),
        environment: None,
        live: false,
    })
    .expect("unknown product uses the generic bounded HTTP executor");
    assert_eq!(offline.status, "passed");

    let check = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: true,
        against: None,
        anchor: None,
    })
    .expect("unknown product compiles through the generic authoring contract");
    assert_eq!(check.status, "valid");

    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("unknown product builds generic Relay and Notary inputs");
    assert_eq!(build.status, "built");

    let metadata_free_root = tempfile::tempdir().expect("metadata-free temporary directory");
    let metadata_free = copy_project("custom-system", metadata_free_root.path());
    let integration_path = metadata_free.join("integrations/eligibility/integration.yaml");
    let mut integration = read_yaml(&integration_path);
    let source = integration["source"]
        .as_mapping_mut()
        .expect("authored source mapping");
    source.remove(serde_yaml::Value::String("product".to_string()));
    source.remove(serde_yaml::Value::String("versions".to_string()));
    write_yaml(&integration_path, &integration);
    let report = test_registry_project(&ProjectTestOptions {
        project_directory: metadata_free,
        environment: None,
        live: false,
    })
    .expect("product and version metadata are optional for generic HTTP");
    assert_eq!(report.status, "passed");
}

#[test]
fn project_integrations_share_one_logical_source_without_conflating_protocol_helpers() {
    let shared_root = tempfile::tempdir().expect("shared-source temporary directory");
    let shared = copy_project("custom-system", shared_root.path());
    duplicate_project_integration(&shared, "eligibility", "secondary");
    check_registry_project(&ProjectCheckOptions {
        project_directory: shared,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect("two integrations over the same source pass");

    let product_root = tempfile::tempdir().expect("independent-product temporary directory");
    let independent_product = copy_project("custom-system", product_root.path());
    duplicate_project_integration(&independent_product, "eligibility", "secondary");
    replace_in_file(
        &independent_product.join("integrations/secondary/integration.yaml"),
        "product: aurora-household-service",
        "product: unrelated-registry",
    );
    check_registry_project(&ProjectCheckOptions {
        project_directory: independent_product,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect("product evidence never defines or dispatches the project source");

    let origin_root = tempfile::tempdir().expect("independent-origin temporary directory");
    let independent_origin = copy_project("custom-system", origin_root.path());
    duplicate_project_integration(&independent_origin, "eligibility", "secondary");
    let environment_path = independent_origin.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["integrations"]["secondary"]["source"]["origin"] =
        serde_yaml::Value::String("https://unrelated-registry.invalid".to_string());
    write_yaml(&environment_path, &environment);
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: independent_origin,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("two source data origins in one project fail closed");
    assert!(format!("{error:#}").contains("same logical source data origin"));

    let helper_root = tempfile::tempdir().expect("protocol-helper temporary directory");
    let protocol_helper = copy_project("opencrvs", helper_root.path());
    duplicate_project_integration(&protocol_helper, "birth-record", "secondary");
    let environment_path = protocol_helper.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["integrations"]["secondary"]["source"]["oauth"]["origin"] =
        serde_yaml::Value::String("https://oauth-helper.invalid".to_string());
    write_yaml(&environment_path, &environment);
    check_registry_project(&ProjectCheckOptions {
        project_directory: protocol_helper,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect("a distinct protocol helper is not a second registry source");
}

#[test]
fn pre_freeze_fact_authoring_keys_are_rejected_without_aliases() {
    let integration_root = tempfile::tempdir().expect("integration-key temporary directory");
    let integration = copy_project("custom-system", integration_root.path());
    replace_in_file(
        &integration.join("integrations/eligibility/integration.yaml"),
        "\noutputs:\n",
        "\nfacts:\n",
    );
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: integration,
        environment: None,
        live: false,
    })
    .expect_err("integration facts alias must be rejected");
    assert!(format!("{error:#}").contains("facts"));

    let claim_root = tempfile::tempdir().expect("claim-key temporary directory");
    let claim = copy_project("custom-system", claim_root.path());
    replace_in_file(
        &claim.join("registry-stack.yaml"),
        "output: household.category",
        "fact: household.category",
    );
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: claim,
        environment: None,
        live: false,
    })
    .expect_err("claim fact alias must be rejected");
    assert!(format!("{error:#}").contains("fact"));

    let fixture_root = tempfile::tempdir().expect("fixture-key temporary directory");
    let fixture = copy_project("custom-system", fixture_root.path());
    let fixture_path = fixture.join("integrations/eligibility/fixtures/eligible.yaml");
    replace_in_file(&fixture_path, "  outputs:", "  facts:");
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: fixture,
        environment: None,
        live: false,
    })
    .expect_err("fixture facts alias must be rejected");
    assert!(format!("{error:#}").contains("facts"));
}

#[test]
fn init_accepts_an_existing_empty_directory_and_rejects_authored_content() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let empty = temporary.path().join("empty");
    std::fs::create_dir(&empty).expect("empty destination creates");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: empty,
    })
    .expect("empty destination initializes");

    let occupied = temporary.path().join("occupied");
    std::fs::create_dir(&occupied).expect("occupied destination creates");
    std::fs::write(occupied.join("owned.txt"), b"user content").expect("user content writes");
    let error = init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
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
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: unknown.clone(),
    })
    .expect("starter initializes");
    let project_path = unknown.join("registry-stack.yaml");
    let mut project = std::fs::read_to_string(&project_path).expect("project reads");
    project.push_str("unexpected_authority: true\n");
    std::fs::write(&project_path, project).expect("invalid project writes");
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: unknown,
        environment: None,
        live: false,
    })
    .expect_err("unknown field must fail");
    assert!(format!("{error:#}").contains("unknown field"));

    let conformance_escape = copy_project("dhis2-sandboxed-rhai", temporary.path());
    let fixture_path = conformance_escape.join("integrations/health-record/fixtures/match.yaml");
    let mut fixture = read_yaml(&fixture_path);
    fixture["worker_probe"] = serde_yaml::Value::String("network".to_string());
    write_yaml(&fixture_path, &fixture);
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: conformance_escape,
        environment: None,
        live: false,
    })
    .expect_err("implementation conformance mode must not be authored");
    assert!(format!("{error:#}").contains("worker_probe"));

    let traversal = temporary.path().join("traversal");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
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
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: traversal,
        environment: None,
        live: false,
    })
    .expect_err("path traversal must fail");
    assert!(format!("{error:#}").contains("cannot traverse"));
}

#[test]
fn fixture_failure_reports_safe_validation_error_without_input_value() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let fixture_path = project.join("integrations/eligibility/fixtures/eligible.yaml");
    replace_in_file(&fixture_path, "HH-AB12CD34", "invalid-reference");

    let error = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: None,
        live: false,
    })
    .expect_err("invalid positive fixture must fail");
    let diagnostic = format!("{error:#}");
    assert!(
        diagnostic.contains("fixture input household_reference violates its pattern"),
        "{diagnostic}"
    );
    assert!(!diagnostic.contains("invalid-reference"));
}

#[cfg(unix)]
#[test]
fn authored_fixture_symlinks_fail_closed() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("registry-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
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
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: None,
        live: false,
    })
    .expect_err("fixture symlink must fail");
    assert!(format!("{error:#}").contains("symlink"));
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
    let error = build_registry_project(&ProjectBuildOptions {
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
    let error = test_registry_project(&ProjectTestOptions {
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
fn project_authoring_schemas_keep_editor_annotations_and_valid_examples() {
    const SCHEMAS: &[&str] = &[
        "project.schema.json",
        "environment.schema.json",
        "integration.schema.json",
        "fixture.schema.json",
        "entity.schema.json",
    ];

    fn schema_annotation_counts(value: &serde_json::Value) -> (usize, usize, usize) {
        let Some(object) = value.as_object() else {
            return (0, 0, 0);
        };
        let is_schema = [
            "$ref",
            "type",
            "const",
            "enum",
            "oneOf",
            "anyOf",
            "allOf",
            "properties",
        ]
        .iter()
        .any(|keyword| object.contains_key(*keyword));
        let mut counts = (
            usize::from(
                object
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|description| description.len() >= 16),
            ),
            usize::from(is_schema && object.contains_key("default")),
            usize::from(
                is_schema
                    && object
                        .get("examples")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|examples| !examples.is_empty()),
            ),
        );
        for child in object.values() {
            let child_counts = match child {
                serde_json::Value::Array(values) => values
                    .iter()
                    .map(schema_annotation_counts)
                    .fold((0, 0, 0), |totals, counts| {
                        (
                            totals.0 + counts.0,
                            totals.1 + counts.1,
                            totals.2 + counts.2,
                        )
                    }),
                _ => schema_annotation_counts(child),
            };
            counts.0 += child_counts.0;
            counts.1 += child_counts.1;
            counts.2 += child_counts.2;
        }
        counts
    }

    let schema_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/project-authoring");
    for schema_name in SCHEMAS {
        let schema: serde_json::Value = serde_json::from_slice(
            &std::fs::read(schema_root.join(schema_name)).expect("schema reads"),
        )
        .expect("schema is JSON");
        let description = schema
            .get("description")
            .and_then(serde_json::Value::as_str)
            .expect("schema has a top-level description");
        assert!(
            description.len() >= 32,
            "{schema_name} needs a meaningful top-level description"
        );

        let properties = schema["properties"]
            .as_object()
            .expect("schema has root properties");
        for (name, property) in properties {
            assert!(
                property
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|description| description.len() >= 16),
                "{schema_name} root property {name} needs a meaningful description"
            );
        }
        let definitions = schema["$defs"].as_object().expect("schema has definitions");
        for (name, definition) in definitions {
            assert!(
                definition
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|description| description.len() >= 16),
                "{schema_name} definition {name} needs a meaningful description"
            );
        }

        let (descriptions, defaults, examples) = schema_annotation_counts(&schema);
        assert!(
            descriptions > properties.len() + definitions.len(),
            "{schema_name} description coverage regressed"
        );
        assert!(defaults >= 1, "{schema_name} needs at least one default");
        assert!(examples >= 1, "{schema_name} needs at least one example");

        let compiled = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap_or_else(|error| panic!("{schema_name} did not compile: {error}"));
        for example in schema["examples"]
            .as_array()
            .expect("schema has top-level examples")
        {
            if let Err(errors) = compiled.validate(example) {
                let messages = errors.map(|error| error.to_string()).collect::<Vec<_>>();
                panic!("{schema_name} has an invalid example: {messages:?}");
            }
        }
    }
}

#[test]
fn strict_project_authoring_schemas_compile_and_accept_every_golden() {
    let schema_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/project-authoring");
    let compile = |schema_name: &str| {
        let schema: serde_json::Value = serde_json::from_slice(
            &std::fs::read(schema_root.join(schema_name)).expect("schema reads"),
        )
        .expect("schema is JSON");
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap_or_else(|error| panic!("{schema_name} did not compile: {error}"))
    };
    let project_schema = compile("project.schema.json");
    let environment_schema = compile("environment.schema.json");
    let integration_schema = compile("integration.schema.json");
    let fixture_schema = compile("fixture.schema.json");
    let entity_schema = compile("entity.schema.json");
    let mut projects =
        vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/project-starters/bounded-http")];
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
            "snapshot-with-records",
            "relay-only-records",
            "relay-only-materialization",
            "notary-only-self-attested",
        ]
        .map(golden),
    );
    for project in projects {
        validate_yaml(&project_schema, &project.join("registry-stack.yaml"));
        validate_yaml(
            &environment_schema,
            &project.join("environments/local.yaml"),
        );
        let entities = project.join("entities");
        if entities.is_dir() {
            for definition in std::fs::read_dir(entities).expect("entities directory reads") {
                let definition = definition.expect("entity entry").path();
                if definition.extension().and_then(|value| value.to_str()) == Some("yaml") {
                    validate_yaml(&entity_schema, &definition);
                }
            }
        }
        let integrations = project.join("integrations");
        if integrations.is_dir() {
            for integration_dir in
                std::fs::read_dir(integrations).expect("integration directory reads")
            {
                let integration_dir = integration_dir.expect("integration entry").path();
                validate_yaml(
                    &integration_schema,
                    &integration_dir.join("integration.yaml"),
                );
                for fixture in std::fs::read_dir(integration_dir.join("fixtures"))
                    .expect("fixture directory reads")
                {
                    let fixture = fixture.expect("fixture entry").path();
                    if fixture.extension().and_then(|value| value.to_str()) == Some("yaml") {
                        validate_yaml(&fixture_schema, &fixture);
                    }
                }
            }
        }
    }
}

#[test]
fn project_schema_accepts_sixteen_consultation_inputs_and_rejects_seventeen() {
    let schema: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("schemas/project-authoring/project.schema.json"),
        )
        .expect("project schema reads"),
    )
    .expect("project schema is JSON");
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("project schema compiles");
    let mut project = serde_json::to_value(read_yaml(
        &golden("custom-system").join("registry-stack.yaml"),
    ))
    .expect("project converts to JSON");
    {
        let input = project
            .pointer_mut("/services/household-eligibility/consultations/household/input")
            .and_then(serde_json::Value::as_object_mut)
            .expect("consultation input map exists");
        input.clear();
        for index in 0..16 {
            input.insert(
                format!("input_{index}"),
                serde_json::Value::String(format!("request.target.identifiers.identifier_{index}")),
            );
        }
    }
    assert!(schema.is_valid(&project));
    project
        .pointer_mut("/services/household-eligibility/consultations/household/input")
        .and_then(serde_json::Value::as_object_mut)
        .expect("consultation input map exists")
        .insert(
            "input_16".to_string(),
            serde_json::Value::String("request.target.identifiers.identifier_16".to_string()),
        );
    assert!(!schema.is_valid(&project));
}

#[test]
fn project_authoring_schemas_reject_incoherent_product_topologies() {
    let schema_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/project-authoring");
    let compile = |schema_name: &str| {
        let schema: serde_json::Value = serde_json::from_slice(
            &std::fs::read(schema_root.join(schema_name)).expect("schema reads"),
        )
        .expect("schema is JSON");
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap_or_else(|error| panic!("{schema_name} did not compile: {error}"))
    };
    let project_schema = compile("project.schema.json");
    assert!(!project_schema.is_valid(&serde_json::json!({
        "version": 1,
        "registry": { "id": "empty-registry" },
        "services": {},
    })));

    let environment_schema = compile("environment.schema.json");
    let relay_binding = serde_json::json!({
        "origin": "https://relay.internal.invalid",
        "issuer": "https://issuer.internal.invalid",
        "jwks_url": "https://issuer.internal.invalid/.well-known/jwks.json",
        "audience": "registry-relay",
        "allowed_clients": ["registry-client"],
    });
    let connection = serde_json::json!({
        "workload_client_id": "registry-notary",
        "token_file": "/run/secrets/notary-relay-token",
    });
    for (name, environment) in [
        (
            "Relay deployment without Relay bindings",
            serde_json::json!({
                "version": 1,
                "deployment": { "profile": "local", "relay": { "service": "relay" } },
            }),
        ),
        (
            "Notary-only deployment with Relay bindings",
            serde_json::json!({
                "version": 1,
                "relay": relay_binding.clone(),
                "deployment": { "profile": "local", "notary": { "service": "notary" } },
            }),
        ),
        (
            "Relay-only deployment with a Notary-to-Relay connection",
            serde_json::json!({
                "version": 1,
                "relay": relay_binding.clone(),
                "notary_relay": connection,
                "deployment": { "profile": "local", "relay": { "service": "relay" } },
            }),
        ),
    ] {
        assert!(
            !environment_schema.is_valid(&environment),
            "schema accepted {name}"
        );
    }
    assert!(environment_schema.is_valid(&serde_json::json!({
        "version": 1,
        "relay": relay_binding,
        "deployment": {
            "profile": "local",
            "relay": { "service": "relay" },
            "notary": { "service": "notary" },
        },
    })));
    assert!(!environment_schema.is_valid(&serde_json::json!({
        "version": 1,
        "relay": {
            "origin": "https://relay.internal.invalid",
            "issuer": "https://issuer.internal.invalid",
            "jwks_url": "https://issuer.internal.invalid/.well-known/jwks.json",
            "audience": "registry-relay",
            "workload_client_id": "obsolete-overloaded-client",
        },
        "deployment": { "profile": "local", "relay": { "service": "relay" } },
    })));
}

#[test]
fn relay_authorization_bindings_follow_authored_service_topology() {
    let missing_workload_root = tempfile::tempdir().expect("temporary directory");
    let missing_workload = copy_project("custom-system", missing_workload_root.path());
    let environment_path = missing_workload.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment
        .as_mapping_mut()
        .expect("environment mapping")
        .remove(serde_yaml::Value::String("notary_relay".to_string()));
    write_yaml(&environment_path, &environment);
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: missing_workload,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("Relay consultation without a Notary workload must fail");
    assert!(format!("{error:#}")
        .contains("Notary-to-Relay connection is required exactly for Relay consultations"));

    let missing_records_client_root = tempfile::tempdir().expect("temporary directory");
    let missing_records_client =
        copy_project("relay-only-records", missing_records_client_root.path());
    let environment_path = missing_records_client.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["relay"]["allowed_clients"] =
        serde_yaml::from_str("[]\n").expect("empty allowed client list");
    write_yaml(&environment_path, &environment);
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: missing_records_client,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("records publication without an admitted client must fail");
    assert!(format!("{error:#}")
        .contains("records_api service requires at least one admitted Relay OIDC client"));
}

#[test]
fn exact_selector_sizes_one_through_eight_compile_for_http_and_snapshot() {
    for size in 1..=8 {
        let temporary = tempfile::tempdir().expect("temporary directory");
        for golden_name in ["custom-system", "snapshot-exact"] {
            let project = copy_project(golden_name, temporary.path());
            if golden_name == "custom-system" {
                remove_custom_cel_claim(&project);
            }
            extend_exact_selector(&project, golden_name, size);
            check_registry_project(&ProjectCheckOptions {
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
        "maxLength: 18",
        "maxLength: 64",
    );
    let report = build_registry_project(&ProjectBuildOptions {
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
        pack["spec"]["input_slots"]["household_reference"]["x-registry-max-bytes"],
        256
    );

    let rejected_root = tempfile::tempdir().expect("rejected temporary directory");
    let rejected = copy_project("custom-system", rejected_root.path());
    replace_in_file(
        &rejected.join("integrations/eligibility/integration.yaml"),
        "maxLength: 18",
        "maxLength: 1025",
    );
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: rejected,
        environment: None,
        live: false,
    })
    .expect_err("selector above the aggregate byte ceiling must be rejected before source access");
    let error = format!("{error:#}");
    assert!(error.contains("input.household_reference"), "{error}");
    assert!(error.contains("exceeds 4096 bytes"), "{error}");
}

#[test]
fn integration_input_names_match_the_wire_grammar() {
    let accepted_root = tempfile::tempdir().expect("accepted temporary directory");
    let accepted = copy_project("custom-system", accepted_root.path());
    remove_custom_cel_claim(&accepted);
    let boundary_name = format!("a{}", "0".repeat(63));
    rename_custom_input(&accepted, &boundary_name);
    let report = build_registry_project(&ProjectBuildOptions {
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
        let error = test_registry_project(&ProjectTestOptions {
            project_directory: rejected,
            environment: None,
            live: false,
        })
        .expect_err("invalid input name must be rejected before source access");
        let error = format!("{error:#}");
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
                .join("schemas/project-authoring/integration.schema.json"),
        )
        .expect("integration schema reads"),
    )
    .expect("integration schema parses");
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("integration schema compiles");
    let authored: serde_yaml::Value = serde_yaml::from_slice(
        &std::fs::read(golden("custom-system").join("integrations/eligibility/integration.yaml"))
            .expect("integration reads"),
    )
    .expect("integration parses");
    let mut authored = serde_json::to_value(authored).expect("integration converts to JSON");
    authored["input"]["household_reference"]["pattern"] =
        serde_json::Value::String("a".repeat(16_384));
    assert!(schema.validate(&authored).is_ok());
    authored["input"]["household_reference"]["pattern"] =
        serde_json::Value::String("a".repeat(16_385));
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
        build_registry_project(&ProjectBuildOptions {
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
fn api_key_interfaces_keep_values_environment_only_and_use_the_stable_auth_type() {
    for (credential_type, name) in [
        ("api_key_header", "x-project-api-key"),
        ("api_key_query", "apiKey"),
    ] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project("custom-system", temporary.path());
        remove_custom_cel_claim(&project);
        let integration = project.join("integrations/eligibility/integration.yaml");
        let mut document = read_yaml(&integration);
        document["source"]["auth"] = serde_yaml::from_str(&format!(
            "type: {credential_type}\nname: {name}\nmax_value_bytes: 128\n"
        ))
        .expect("API-key interface YAML");
        write_yaml(&integration, &document);

        let environment = project.join("environments/local.yaml");
        let mut document = read_yaml(&environment);
        document["integrations"]["eligibility"]["source"]["credential"] =
            serde_yaml::from_str("value: { secret: PROJECT_SOURCE_API_KEY }\ngeneration: 1\n")
                .expect("API-key environment YAML");
        write_yaml(&environment, &document);

        let report = build_registry_project(&ProjectBuildOptions {
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
        assert!(generated.contains("PROJECT_SOURCE_API_KEY"));
        assert!(!generated.contains("secret: PROJECT_SOURCE_API_KEY"));
        assert!(!generated.contains("registry-source-secret-value"));
    }

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let integration = project.join("integrations/eligibility/integration.yaml");
    let mut document = read_yaml(&integration);
    document["source"]["auth"] =
        serde_yaml::from_str("type: api_key_header\nname: authorization\nmax_value_bytes: 128\n")
            .expect("invalid API-key header interface");
    write_yaml(&integration, &document);
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: None,
        live: false,
    })
    .expect_err("security-sensitive header must fail");
    assert!(format!("{error:#}").contains("security-sensitive"));

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let integration = project.join("integrations/eligibility/integration.yaml");
    let mut document = read_yaml(&integration);
    document["source"]["auth"] =
        serde_yaml::from_str("type: api_key_query\nname: fields\nmax_value_bytes: 128\n")
            .expect("colliding API-key query interface");
    write_yaml(&integration, &document);
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: None,
        live: false,
    })
    .expect_err("query-name collision must fail");
    assert!(format!("{error:#}").contains("collides"));

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let integration = project.join("integrations/eligibility/integration.yaml");
    let mut document = read_yaml(&integration);
    document["source"]["auth"] =
        serde_yaml::from_str("type: api_key_query\nname: apiKey\nmax_value_bytes: 128\n")
            .expect("API-key query interface");
    write_yaml(&integration, &document);
    let environment = project.join("environments/local.yaml");
    replace_in_file(
        &environment,
        "username: { secret: HOUSEHOLD_USERNAME }\n        password: { secret: HOUSEHOLD_PASSWORD }",
        "type: api_key_query\n        value: { secret: PROJECT_SOURCE_API_KEY }",
    );
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: project,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("environment auth-type compatibility alias must fail");
    assert!(format!("{error:#}").contains("unknown field `type`"));
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
    ];
    for (from, to, expected) in cases {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project("opencrvs", temporary.path());
        replace_in_file(
            &project.join("integrations/birth-record/integration.yaml"),
            from,
            to,
        );
        let error = test_registry_project(&ProjectTestOptions {
            project_directory: project,
            environment: None,
            live: false,
        })
        .expect_err("invalid DCI exact conjunction must fail");
        assert!(format!("{error:#}").contains(expected), "{error:#}");
    }

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("opencrvs", temporary.path());
    let integration_path = project.join("integrations/birth-record/integration.yaml");
    let mut integration = read_yaml(&integration_path);
    let selectors = integration["source"]["protocol"]["signed_dci"]["selectors"]
        .as_mapping_mut()
        .expect("DCI selectors");
    let uin = selectors
        .remove(serde_yaml::Value::String("uin".to_string()))
        .expect("UIN selector");
    selectors.insert(serde_yaml::Value::String("other".to_string()), uin);
    write_yaml(&integration_path, &integration);
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: None,
        live: false,
    })
    .expect_err("DCI must bind every authored selector exactly once");
    assert!(format!("{error:#}").contains("bind every selector exactly once"));

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    extend_exact_selector(&project, "custom-system", 4);
    let fixture = project.join("integrations/eligibility/fixtures/eligible.yaml");
    replace_in_file(&fixture, "2017-06-15", "2017-02-31");
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: None,
        live: false,
    })
    .expect_err("nonexistent full date must fail before source access");
    assert!(format!("{error:#}").contains("fixture full-date input selector_4 is not canonical"));

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
    let error = test_registry_project(&ProjectTestOptions {
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

    let journey = test_registry_project(&ProjectTestOptions {
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
    assert!(ambiguous.outputs.is_empty());
    assert!(ambiguous.claims.is_empty());
    reverse_yaml_mapping(
        &second.join("integrations/birth-record/integration.yaml"),
        &["source", "protocol", "signed_dci", "selectors"],
    );

    let build = |project_directory| {
        build_registry_project(&ProjectBuildOptions {
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
    let check = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: true,
        against: None,
        anchor: None,
    })
    .expect("golden project checks");
    assert_eq!(check.status, "valid");
    assert_eq!(check.semantic_changes.len(), 5);
    assert_eq!(
        check
            .semantic_changes
            .iter()
            .map(|change| change.dimension)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "claim",
            "disclosure",
            "integration",
            "operator_security",
            "service_policy",
        ])
    );
    let explanation = check.explanation.expect("explanation is present");
    assert!(explanation
        .pointer("/integrations/eligibility/generated_pack")
        .is_none());
    assert!(explanation
        .pointer("/services/household-eligibility/profiles/0/policy_hash")
        .is_none());
    assert!(explanation
        .pointer("/services/household-eligibility/profiles/0/version")
        .is_none());
    assert!(explanation
        .pointer("/services/household-eligibility/profiles/0/contract_hash")
        .and_then(serde_json::Value::as_str)
        .is_some());
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
        .pointer("/services/household-eligibility/credential_profiles")
        .is_some());
    assert_eq!(
        explanation["integrations"]["eligibility"]["capability"],
        "http"
    );

    let options = ProjectBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    };
    let first = build_registry_project(&options).expect("first build");
    let output = PathBuf::from(first.output.expect("build output"));
    let first_closure = directory_closure(&output);
    build_registry_project(&options).expect("second build");
    assert_eq!(first_closure, directory_closure(&output));
    assert_eq!(
        closure_digest(&first_closure),
        "7b20a7531535e91de513ca74b327744e2e8b364059ec59e060266041cdd3f004",
        "project inputs must match the cross-machine golden digest"
    );
}

#[test]
fn records_and_snapshot_share_one_generated_materialization() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("snapshot-with-records", temporary.path());
    let build = build_registry_project(&ProjectBuildOptions {
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
        .is_some_and(|filters| filters.len() == 1));
    assert!(entity["relationships"]
        .as_array()
        .is_some_and(Vec::is_empty));
    assert!(entity["aggregates"].as_array().is_some_and(Vec::is_empty));

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
    assert!(review["entity_materializations"]["people"]["provider"].is_object());
    assert!(review["entity_materializations"]["people"]["columns"].is_object());
    assert!(review["entity_materializations"]["people"]
        .get("provider_digest")
        .is_none());
}

#[test]
fn relay_only_and_notary_only_projects_emit_only_selected_products() {
    for (project_name, present, absent) in [
        ("relay-only-records", "relay", "notary"),
        ("notary-only-self-attested", "notary", "relay"),
    ] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project(project_name, temporary.path());
        let build = build_registry_project(&ProjectBuildOptions {
            project_directory: project,
            environment: "local".to_string(),
            against: None,
            anchor: None,
        })
        .unwrap_or_else(|error| panic!("{project_name} build failed: {error:#}"));
        let output = PathBuf::from(build.output.expect("build output"));
        assert!(
            output.join("private").join(present).is_dir(),
            "{project_name}"
        );
        assert!(
            !output.join("private").join(absent).exists(),
            "{project_name} emitted unselected {absent} configuration"
        );
        let approval_state: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                output
                    .join("private")
                    .join(present)
                    .join("approval/project-state.json"),
            )
            .expect("approval state reads"),
        )
        .expect("approval state parses");
        assert!(approval_state["generated_closure_digests"][present].is_string());
        assert!(approval_state["generated_closure_digests"][absent].is_null());
    }
}

#[test]
fn materialization_only_project_emits_private_relay_table_without_public_records() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("relay-only-materialization", temporary.path());
    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("materialization-only Relay project builds");
    let output = PathBuf::from(build.output.expect("build output"));
    assert!(output.join("private/relay").is_dir());
    assert!(!output.join("private/notary").exists());

    let relay = read_yaml(&output.join("private/relay/config/relay.yaml"));
    let datasets = relay["datasets"].as_sequence().expect("Relay datasets");
    assert_eq!(datasets.len(), 1);
    assert_eq!(
        datasets[0]["tables"].as_sequence().map(std::vec::Vec::len),
        Some(1)
    );
    assert!(datasets[0]["entities"]
        .as_sequence()
        .is_some_and(std::vec::Vec::is_empty));
    assert!(relay.get("consultation").is_none());

    let approval_state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.join("private/relay/approval/project-state.json"))
            .expect("approval state reads"),
    )
    .expect("approval state parses");
    assert!(approval_state["generated_closure_digests"]["relay"].is_string());
    assert!(approval_state["generated_closure_digests"]["notary"].is_null());
}

#[test]
fn relay_oidc_clients_are_separate_from_the_notary_consultation_workload() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("combined project builds with separate Relay identities");
    let output = PathBuf::from(build.output.expect("build output"));
    let relay = read_yaml(&output.join("private/relay/config/relay.yaml"));
    let allowed_clients = relay["auth"]["oidc"]["allowed_clients"]
        .as_sequence()
        .expect("Relay OIDC allowed clients");
    assert!(allowed_clients
        .iter()
        .any(|client| client.as_str() == Some("household-relay-client")));
    assert!(allowed_clients
        .iter()
        .any(|client| client.as_str() == Some("household-notary")));
    assert_eq!(
        relay["consultation"]["authorized_workload"]["client_value"].as_str(),
        Some("household-notary")
    );
    assert_eq!(
        relay["consultation"]["authorized_workload"]["principal_id"].as_str(),
        Some("household-notary")
    );
    assert_ne!(
        relay["consultation"]["authorized_workload"]["client_value"].as_str(),
        Some("household-relay-client")
    );
}

#[test]
fn combined_project_without_relay_consultations_needs_no_notary_relay_workload() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("relay-only-records", temporary.path());
    let project_path = project.join("registry-stack.yaml");
    let mut authored_project = read_yaml(&project_path);
    authored_project["services"]["applicant-declaration"] = serde_yaml::from_str(
        r#"kind: evidence
version: 1
purpose: application-processing
legal_basis: application-processing
consent: not_required
access: { scopes: ["evidence:declaration:read"] }
claims:
  applicant-declaration:
    cel: "true"
    value: { type: boolean }
    disclosure: predicate
credential_profiles: {}
"#,
    )
    .expect("self-attested evaluation service");
    write_yaml(&project_path, &authored_project);

    let environment_path = project.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["callers"] = serde_yaml::from_str(
        "application-service:\n  api_key_fingerprint: { secret: APPLICATION_SERVICE_TOKEN_HASH }\n  scopes: ['evidence:declaration:read']\n",
    )
    .expect("Notary caller binding");
    environment["deployment"]["notary"] =
        serde_yaml::from_str("service: declaration-notary\n").expect("Notary deployment");
    write_yaml(&environment_path, &environment);

    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("combined records and evaluation project builds without a Relay consultation");
    let output = PathBuf::from(build.output.expect("build output"));
    let relay = read_yaml(&output.join("private/relay/config/relay.yaml"));
    assert!(relay.get("consultation").is_none());
    let notary = read_yaml(&output.join("private/notary/config/notary.yaml"));
    assert!(notary["evidence"].get("relay").is_none());
    assert!(notary["evidence"].get("signing_keys").is_none());
}

#[test]
fn notary_without_credential_profiles_omits_issuance_and_signing_keys() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("notary-only-self-attested", temporary.path());
    let project_path = project.join("registry-stack.yaml");
    let mut authored_project = read_yaml(&project_path);
    authored_project["services"]["applicant-declaration"]["credential_profiles"] =
        serde_yaml::from_str("{}\n").expect("empty credential profiles");
    write_yaml(&project_path, &authored_project);
    let environment_path = project.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment
        .as_mapping_mut()
        .expect("environment mapping")
        .remove(serde_yaml::Value::String("issuance".to_string()));
    write_yaml(&environment_path, &environment);

    let check = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect("evaluation-only Notary project checks without issuance");
    assert_eq!(check.status, "valid");
    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("evaluation-only Notary project builds without issuance");
    let output = PathBuf::from(build.output.expect("build output"));
    let notary = read_yaml(&output.join("private/notary/config/notary.yaml"));
    assert!(notary["evidence"].get("signing_keys").is_none());
    assert!(notary["evidence"]["credential_profiles"]
        .as_mapping()
        .is_some_and(serde_yaml::Mapping::is_empty));

    let missing_issuance_root = tempfile::tempdir().expect("temporary directory");
    let missing_issuance = copy_project("notary-only-self-attested", missing_issuance_root.path());
    let missing_issuance_environment = missing_issuance.join("environments/local.yaml");
    let mut environment = read_yaml(&missing_issuance_environment);
    environment
        .as_mapping_mut()
        .expect("environment mapping")
        .remove(serde_yaml::Value::String("issuance".to_string()));
    write_yaml(&missing_issuance_environment, &environment);
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: missing_issuance,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("credential profiles without issuance must fail");
    assert!(format!("{error:#}").contains(
        "environment issuance binding is required exactly when credential profiles exist"
    ));

    let unexpected_issuance_root = tempfile::tempdir().expect("temporary directory");
    let unexpected_issuance =
        copy_project("notary-only-self-attested", unexpected_issuance_root.path());
    let project_path = unexpected_issuance.join("registry-stack.yaml");
    let mut authored_project = read_yaml(&project_path);
    authored_project["services"]["applicant-declaration"]["credential_profiles"] =
        serde_yaml::from_str("{}\n").expect("empty credential profiles");
    write_yaml(&project_path, &authored_project);
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: unexpected_issuance,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("issuance without credential profiles must fail");
    assert!(format!("{error:#}").contains(
        "environment issuance binding is required exactly when credential profiles exist"
    ));
}

#[test]
fn records_standards_share_the_validated_materialization() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("snapshot-with-records", temporary.path());
    let entity_path = project.join("entities/people.yaml");
    let mut entity = read_yaml(&entity_path);
    entity["schema"]["properties"]["longitude"] =
        serde_yaml::from_str("type: [integer, 'null']\nminimum: -180\nmaximum: 180\n")
            .expect("longitude field");
    entity["schema"]["properties"]["latitude"] =
        serde_yaml::from_str("type: [integer, 'null']\nminimum: -90\nmaximum: 90\n")
            .expect("latitude field");
    entity["schema"]["required"]
        .as_sequence_mut()
        .expect("entity required fields")
        .extend([
            serde_yaml::Value::String("longitude".to_string()),
            serde_yaml::Value::String("latitude".to_string()),
        ]);
    write_yaml(&entity_path, &entity);

    let project_path = project.join("registry-stack.yaml");
    let mut authored_project = read_yaml(&project_path);
    authored_project["services"]["people-records"]["api"]["standards"]["ogc_features"] =
        serde_yaml::from_str(
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
    authored_project["services"]["people-records"]["api"]["standards"]["sp_dci"] =
        serde_yaml::from_str(
            r#"registry: population
registry_type: civil-registry
record_type: person
identifiers: { person_id: person_id }
expression_fields: { registration_status: registration_status }
response_fields: { eligible: eligible }
"#,
        )
        .expect("SP DCI mapping");
    write_yaml(&project_path, &authored_project);

    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("standards must not widen the explicit records projection");
    assert!(format!("{error:#}").contains("must be explicitly projected"));

    authored_project["services"]["people-records"]["api"]["projection"]
        .as_sequence_mut()
        .expect("records projection")
        .extend([
            serde_yaml::Value::String("longitude".to_string()),
            serde_yaml::Value::String("latitude".to_string()),
        ]);
    authored_project["services"]["people-records"]["api"]["filters"]["registration_status"] =
        serde_yaml::from_str("[eq]").expect("SP DCI expression filter");
    write_yaml(&project_path, &authored_project);

    let environment_path = project.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["entities"]["people"]["columns"]["longitude"] =
        serde_yaml::Value::String("longitude_deg".to_string());
    environment["entities"]["people"]["columns"]["latitude"] =
        serde_yaml::Value::String("latitude_deg".to_string());
    write_yaml(&environment_path, &environment);

    let build = build_registry_project(&ProjectBuildOptions {
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
    let error = check_registry_project(&ProjectCheckOptions {
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
    let error = check_registry_project(&ProjectCheckOptions {
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
    let entity = physical.join("entities/people.yaml");
    let mut authored = std::fs::read_to_string(&entity).expect("entity reads");
    authored.push_str("path: /private/people.csv\n");
    std::fs::write(&entity, authored).expect("hostile entity writes");
    let error = check_registry_project(&ProjectCheckOptions {
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
    let initial = build_registry_project(&ProjectBuildOptions {
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
        "project-authoring".to_string(),
        "project-instance".to_string(),
    )
    .expect("anchor initializes");
    add_config_anchor_key(&anchor, &public_key, true).expect("anchor key adds");
    sign_config_bundle(BundleSignOptions {
        input: output.join("private/notary"),
        key: private_key.display().to_string(),
        product: "registry-notary".to_string(),
        environment: "local".to_string(),
        stream_id: "project-authoring".to_string(),
        instance_id: Some("project-instance".to_string()),
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
    let error = check_registry_project(&ProjectCheckOptions {
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
    let report = check_registry_project(&ProjectCheckOptions {
        project_directory: project,
        environment: "local".to_string(),
        explain: false,
        against: Some(baseline),
        anchor: Some(anchor),
    })
    .expect("provider change with a new generation checks");
    assert!(report
        .semantic_changes
        .iter()
        .any(|change| change.dimension == "operator_security"));
}

#[test]
fn every_required_golden_builds_registry_backed_notary_without_transitional_sources() {
    let project_names = [
        "custom-system",
        "dhis2-tracker",
        "dhis2-sandboxed-rhai",
        "fhir-r4-coverage-active",
        "opencrvs",
        "opencrvs-country-variant",
        "openspp-exact",
        "snapshot-exact",
        "snapshot-with-records",
    ];
    for project_name in project_names {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project(project_name, temporary.path());
        let check = check_registry_project(&ProjectCheckOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            explain: true,
            against: None,
            anchor: None,
        })
        .unwrap_or_else(|error| panic!("{project_name} check failed: {error:#}"));
        assert_eq!(check.status, "valid", "{project_name}");
        assert_eq!(check.baseline, "initial_without_baseline", "{project_name}");
        assert!(check.explanation.is_some(), "{project_name}");

        let build = build_registry_project(&ProjectBuildOptions {
            project_directory: project,
            environment: "local".to_string(),
            against: None,
            anchor: None,
        })
        .unwrap_or_else(|error| panic!("{project_name} build failed: {error:#}"));
        let output = PathBuf::from(build.output.expect("build output"));
        assert!(output.join("reviewable/review.json").is_file());
        assert!(output
            .join("private/relay/approval/project-state.json")
            .is_file());
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
        let review_bytes =
            std::fs::read(output.join("reviewable/review.json")).expect("human review reads");
        let review: serde_json::Value =
            serde_json::from_slice(&review_bytes).expect("human review parses");
        assert_public_review_has_only_contract_hashes(&review);
        for product in ["relay", "notary"] {
            assert_eq!(
                std::fs::read(output.join(format!("private/{product}/approval/review.json")))
                    .expect("signed review input reads"),
                review_bytes,
                "{project_name} {product} approval carries the exact human review"
            );
        }
        assert_eq!(
            std::fs::read(output.join("private/relay/approval/project-state.json"))
                .expect("Relay approval state reads"),
            std::fs::read(output.join("private/notary/approval/project-state.json"))
                .expect("Notary approval state reads"),
            "{project_name} products carry identical approval state"
        );
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
}

#[test]
fn generated_product_inputs_sign_and_verify_without_secret_values() {
    const SECRET_SENTINEL: &str = "project-authoring-secret-sentinel-8f9d7537";

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    std::env::set_var("HOUSEHOLD_PASSWORD", SECRET_SENTINEL);
    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("project builds");
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
            "project-authoring".to_string(),
            "project-instance".to_string(),
        )
        .expect("anchor initializes");
        add_config_anchor_key(&anchor, &public_key, true).expect("anchor key adds");
        sign_config_bundle(BundleSignOptions {
            input,
            key: private_key.display().to_string(),
            product: product.to_string(),
            environment: "local".to_string(),
            stream_id: "project-authoring".to_string(),
            instance_id: Some("project-instance".to_string()),
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
fn generated_project_output_is_owner_only() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("project builds");
    let output = PathBuf::from(build.output.expect("build output"));
    assert_owner_only(&output);
}

#[test]
fn authored_request_literals_cannot_smuggle_secret_material() {
    const SECRET_SENTINEL: &str = "project-authoring-request-secret-4e198da1";

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let integration_path = project.join("integrations/eligibility/integration.yaml");
    let mut integration = read_yaml(&integration_path);
    integration["capability"]["http"]["request"]["query"]["password"] =
        serde_yaml::Value::String(SECRET_SENTINEL.to_string());
    write_yaml(&integration_path, &integration);
    let error = check_registry_project(&ProjectCheckOptions {
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
        let mut integration = read_yaml(&integration_path);
        integration["capability"]["http"]["request"]["headers"][header] =
            serde_yaml::Value::String(SECRET_SENTINEL.to_string());
        write_yaml(&integration_path, &integration);
        let error = check_registry_project(&ProjectCheckOptions {
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
    let initial = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("initial project build passes");
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
        "project-authoring".to_string(),
        "project-instance".to_string(),
    )
    .expect("baseline anchor initializes");
    add_config_anchor_key(&anchor, &public_key, true).expect("baseline key adds");
    sign_config_bundle(BundleSignOptions {
        input: output.join("private/notary"),
        key: private_key.display().to_string(),
        product: "registry-notary".to_string(),
        environment: "local".to_string(),
        stream_id: "project-authoring".to_string(),
        instance_id: Some("project-instance".to_string()),
        sequence: 1,
        bundle_id: "project-authoring-baseline".to_string(),
        out: baseline.clone(),
    })
    .expect("baseline signs");

    for relative in ["approval/review.json", "approval/project-state.json"] {
        let tampered = temporary
            .path()
            .join(format!("tampered-{}", relative.replace(['/', '.'], "-")));
        copy_tree(&baseline, &tampered);
        let path = tampered.join(relative);
        let mut bytes = std::fs::read(&path).expect("signed approval payload reads");
        bytes.push(b' ');
        std::fs::write(&path, bytes).expect("signed approval payload tampers");
        let error = check_registry_project(&ProjectCheckOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            explain: false,
            against: Some(tampered),
            anchor: Some(anchor.clone()),
        })
        .expect_err("post-signature approval payload tamper must fail");
        assert!(format!("{error:#}").contains("failed to verify config bundle"));
    }

    let initial_review: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.join("reviewable/review.json")).expect("initial review reads"),
    )
    .expect("initial review parses");
    let initial_state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.join("private/notary/approval/project-state.json"))
            .expect("initial approval state reads"),
    )
    .expect("initial approval state parses");
    assert_eq!(initial_review["baseline"], "initial_without_baseline");
    assert!(initial_review["disclosure_profiles"].is_object());
    assert_public_review_has_only_contract_hashes(&initial_review);
    assert!(initial_state["semantic_digests"].is_object());
    assert!(initial_state["generated_closure_digests"]["notary"].is_string());
    assert!(initial_state["report_digest"].is_string());

    let reviewed_build = build_registry_project(&ProjectBuildOptions {
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
    let reviewed_state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(reviewed_output.join("private/notary/approval/project-state.json"))
            .expect("reviewed approval state reads"),
    )
    .expect("reviewed approval state parses");
    assert_eq!(reviewed_record["baseline"], "verified_signed_bundle");
    assert_public_review_has_only_contract_hashes(&reviewed_record);
    assert_eq!(
        reviewed_state["baseline"]["verified_manifest"]["schema"],
        "registry.platform.config_bundle.v1"
    );
    let signed_paths = reviewed_state["baseline"]["verified_manifest"]["files"]
        .as_array()
        .expect("verified manifest files")
        .iter()
        .filter_map(|file| file["path"].as_str())
        .collect::<BTreeSet<_>>();
    assert!(signed_paths.contains("approval/review.json"));
    assert!(signed_paths.contains("approval/project-state.json"));

    let unchanged = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: Some(baseline.clone()),
        anchor: Some(anchor.clone()),
    })
    .expect("unchanged project checks against signed baseline");
    assert_eq!(unchanged.baseline, "verified_signed_bundle");
    assert!(unchanged.semantic_changes.is_empty());

    let mismatched_input = temporary.path().join("mismatched-baseline-input");
    copy_tree(&output.join("private/notary"), &mismatched_input);
    let mismatched_config = mismatched_input.join("config/notary.yaml");
    let mut mismatched_bytes = std::fs::read(&mismatched_config).expect("Notary config reads");
    mismatched_bytes.push(b'\n');
    std::fs::write(&mismatched_config, mismatched_bytes).expect("Notary config changes");
    let mismatched_bundle = temporary.path().join("mismatched-baseline-bundle");
    sign_config_bundle(BundleSignOptions {
        input: mismatched_input,
        key: private_key.display().to_string(),
        product: "registry-notary".to_string(),
        environment: "local".to_string(),
        stream_id: "project-authoring".to_string(),
        instance_id: Some("project-instance".to_string()),
        sequence: 2,
        bundle_id: "project-authoring-mismatched-baseline".to_string(),
        out: mismatched_bundle.clone(),
    })
    .expect("mismatched baseline signs");
    let mismatch = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: Some(mismatched_bundle),
        anchor: Some(anchor.clone()),
    })
    .expect_err("signed product closure must match the signed review");
    assert!(format!("{mismatch:#}").contains("product closure does not match"));

    let report_mismatch_input = temporary.path().join("report-mismatch-input");
    copy_tree(&output.join("private/notary"), &report_mismatch_input);
    let report_mismatch_path = report_mismatch_input.join("approval/review.json");
    let mut mismatched_report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&report_mismatch_path).expect("approval review reads"),
    )
    .expect("approval review parses");
    mismatched_report["semantic_changes"] = serde_json::Value::Array(Vec::new());
    std::fs::write(
        &report_mismatch_path,
        serde_json::to_vec(&mismatched_report).expect("mismatched review serializes"),
    )
    .expect("mismatched approval review writes");
    let report_mismatch_bundle = temporary.path().join("report-mismatch-bundle");
    sign_config_bundle(BundleSignOptions {
        input: report_mismatch_input,
        key: private_key.display().to_string(),
        product: "registry-notary".to_string(),
        environment: "local".to_string(),
        stream_id: "project-authoring".to_string(),
        instance_id: Some("project-instance".to_string()),
        sequence: 2,
        bundle_id: "project-authoring-report-mismatch".to_string(),
        out: report_mismatch_bundle.clone(),
    })
    .expect("report mismatch bundle signs");
    let report_mismatch = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: Some(report_mismatch_bundle),
        anchor: Some(anchor.clone()),
    })
    .expect_err("signed report/state binding mismatch must fail");
    assert!(format!("{report_mismatch:#}").contains("does not bind the signed review"));

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
            "household.approved != null ? household.matched && household.approved : false",
            "household.approved != null ? household.matched && household.approved == true : false",
        );
    std::fs::write(&project_file, authored).expect("claim-only edit writes");
    let changed = check_registry_project(&ProjectCheckOptions {
        project_directory: claim_project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: Some(baseline.clone()),
        anchor: Some(anchor.clone()),
    })
    .expect("claim-only edit checks against signed baseline");
    assert_eq!(
        changed
            .semantic_changes
            .iter()
            .map(|change| change.dimension)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["claim"])
    );

    let compiler_input = temporary.path().join("compiler-baseline-input");
    copy_tree(&output.join("private/notary"), &compiler_input);
    let compiler_state_path = compiler_input.join("approval/project-state.json");
    let mut compiler_state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&compiler_state_path).expect("compiler baseline approval state reads"),
    )
    .expect("compiler baseline approval state parses");
    compiler_state["compiler_version"] = serde_json::Value::String("0.0.0".to_string());
    std::fs::write(
        &compiler_state_path,
        serde_json::to_vec(&compiler_state).expect("compiler baseline state serializes"),
    )
    .expect("compiler baseline approval state writes");
    let compiler_baseline = temporary.path().join("compiler-baseline-bundle");
    sign_config_bundle(BundleSignOptions {
        input: compiler_input,
        key: private_key.display().to_string(),
        product: "registry-notary".to_string(),
        environment: "local".to_string(),
        stream_id: "project-authoring".to_string(),
        instance_id: Some("project-instance".to_string()),
        sequence: 2,
        bundle_id: "project-authoring-compiler-baseline".to_string(),
        out: compiler_baseline.clone(),
    })
    .expect("compiler baseline signs");
    let compiler_mismatch = check_registry_project(&ProjectCheckOptions {
        project_directory: claim_project,
        environment: "local".to_string(),
        explain: false,
        against: Some(compiler_baseline),
        anchor: Some(anchor.clone()),
    })
    .expect_err("signed report and approval-state mismatch must fail");
    assert!(format!("{compiler_mismatch:#}").contains("disagree on compiler version"));

    replace_in_file(
        &source_version_project.join("integrations/eligibility/integration.yaml"),
        "unverified: [fixture-contract-v2, fixture-contract-v3]",
        "unverified: [fixture-contract-v2, fixture-contract-v3, fixture-contract-v4]",
    );
    assert_change_dimensions(
        source_version_project,
        &baseline,
        &anchor,
        BTreeSet::from(["integration"]),
    );

    replace_in_file(
        &operator_project.join("environments/local.yaml"),
        "https://household-authority.invalid",
        "https://household-authority-two.invalid",
    );
    assert_change_dimensions(
        operator_project,
        &baseline,
        &anchor,
        BTreeSet::from(["operator_security"]),
    );

    replace_in_file(
        &policy_project.join("registry-stack.yaml"),
        "legal_basis: public-service-delivery",
        "legal_basis: statutory-benefit-screening",
    );
    assert_change_dimensions(
        policy_project,
        &baseline,
        &anchor,
        BTreeSet::from(["service_policy"]),
    );

    replace_in_file(
        &consultation_project.join("registry-stack.yaml"),
        "request.target.identifiers.household_reference",
        "request.target.identifiers.household_case_number",
    );
    assert_change_dimensions(
        consultation_project,
        &baseline,
        &anchor,
        BTreeSet::from(["integration"]),
    );
}

fn assert_change_dimensions(
    project: PathBuf,
    baseline: &Path,
    anchor: &Path,
    expected: BTreeSet<&str>,
) {
    let report = check_registry_project(&ProjectCheckOptions {
        project_directory: project,
        environment: "local".to_string(),
        explain: false,
        against: Some(baseline.to_path_buf()),
        anchor: Some(anchor.to_path_buf()),
    })
    .expect("semantic review scenario checks against signed baseline");
    assert_eq!(
        report
            .semantic_changes
            .iter()
            .map(|change| change.dimension)
            .collect::<BTreeSet<_>>(),
        expected
    );
}

fn assert_public_review_has_only_contract_hashes(review: &serde_json::Value) {
    fn visit(value: &serde_json::Value, contract_hashes: &mut usize) {
        match value {
            serde_json::Value::Object(object) => {
                for (key, value) in object {
                    let lower = key.to_ascii_lowercase();
                    if lower.contains("hash") || lower.contains("digest") {
                        assert_eq!(
                            key, "contract_hash",
                            "human review exposes lower-level field {key}"
                        );
                        let contract_hash =
                            value.as_str().expect("generated contract_hash is a string");
                        assert!(contract_hash.starts_with("sha256:"));
                        *contract_hashes += 1;
                    }
                    visit(value, contract_hashes);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    visit(value, contract_hashes);
                }
            }
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_) => {}
        }
    }

    let mut contract_hashes = 0;
    visit(review, &mut contract_hashes);
    assert!(
        contract_hashes > 0,
        "registry-backed human review exposes its generated contract_hash"
    );
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
                "role: selector\ntype: string\nformat: date\nminLength: 10\nmaxLength: 10\n",
            )
            .expect("full-date input declaration")
        } else {
            serde_yaml::from_str(&format!(
                "role: selector\ntype: string\nmaxLength: 8\npattern: '^S{component}$'\n"
            ))
            .expect("string input declaration")
        };
        integration["input"]
            .as_mapping_mut()
            .expect("integration input mapping")
            .insert(serde_yaml::Value::String(name.clone()), declaration);
        if golden_name == "custom-system" {
            integration["capability"]["http"]["request"]["query"]
                .as_mapping_mut()
                .expect("HTTP query mapping")
                .insert(
                    serde_yaml::Value::String(name.clone()),
                    serde_yaml::from_str(&format!("input: {name}\n"))
                        .expect("query input expression"),
                );
        } else {
            integration["capability"]["snapshot"]["exact"]
                .as_mapping_mut()
                .expect("snapshot exact mapping")
                .insert(
                    serde_yaml::Value::String(name.clone()),
                    serde_yaml::from_str(&format!("input: {name}\n"))
                        .expect("snapshot input expression"),
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
        if path.extension().and_then(|value| value.to_str()) != Some("yaml") {
            continue;
        }
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
                    serde_yaml::Value::String(value.clone()),
                );
            if golden_name == "custom-system" {
                if let Some(interactions) = document
                    .get_mut("interactions")
                    .and_then(serde_yaml::Value::as_sequence_mut)
                {
                    for interaction in interactions {
                        let query = interaction["expect"]["query"]
                            .as_mapping_mut()
                            .expect("fixture expected query mapping");
                        query.insert(
                            serde_yaml::Value::String(format!("selector_{component}")),
                            serde_yaml::Value::String(value.clone()),
                        );
                    }
                }
            }
        }
        write_yaml(&path, &document);
    }

    if golden_name == "snapshot-exact" {
        let entity_path = project.join("entities/people.yaml");
        let mut entity = read_yaml(&entity_path);
        let environment_path = project.join("environments/local.yaml");
        let mut environment = read_yaml(&environment_path);
        for component in 2..=size {
            let name = format!("selector_{component}");
            entity["schema"]["properties"]
                .as_mapping_mut()
                .expect("entity properties")
                .insert(
                    serde_yaml::Value::String(name.clone()),
                    if component == 4 {
                        // Full-date canonicalization belongs to the consultation input.
                        // Snapshot exact keys remain physical UTF-8 binary values.
                        serde_yaml::from_str("type: string\nmaxLength: 10\n")
                            .expect("full-date snapshot key field")
                    } else {
                        serde_yaml::from_str("type: string\nmaxLength: 8\n")
                            .expect("string entity selector field")
                    },
                );
            entity["schema"]["required"]
                .as_sequence_mut()
                .expect("entity required fields")
                .push(serde_yaml::Value::String(name.clone()));
            environment["entities"]["people"]["columns"]
                .as_mapping_mut()
                .expect("entity columns")
                .insert(
                    serde_yaml::Value::String(name),
                    serde_yaml::Value::String(format!("selector_col_{component}")),
                );
        }
        write_yaml(&entity_path, &entity);
        write_yaml(&environment_path, &environment);
    }

    assert!(integration["input"].get(original_input).is_some());
    assert!(integration["id"].as_str().is_some(), "{alias}");
}

fn duplicate_project_integration(project: &Path, source_alias: &str, target_alias: &str) {
    copy_tree(
        &project.join("integrations").join(source_alias),
        &project.join("integrations").join(target_alias),
    );
    let integration_path = project
        .join("integrations")
        .join(target_alias)
        .join("integration.yaml");
    let mut integration = read_yaml(&integration_path);
    integration["id"] = serde_yaml::Value::String(format!("{target_alias}-integration"));
    write_yaml(&integration_path, &integration);

    let project_path = project.join("registry-stack.yaml");
    let mut project_document = read_yaml(&project_path);
    project_document["integrations"]
        .as_mapping_mut()
        .expect("project integrations mapping")
        .insert(
            serde_yaml::Value::String(target_alias.to_string()),
            serde_yaml::from_str(&format!(
                "file: integrations/{target_alias}/integration.yaml\n"
            ))
            .expect("project integration reference"),
        );
    let (service_name, consultation_name, duplicated_consultation) = project_document["services"]
        .as_mapping()
        .and_then(|services| {
            services.iter().find_map(|(service_name, service)| {
                service["consultations"]
                    .as_mapping()
                    .and_then(|consultations| {
                        consultations
                            .iter()
                            .find_map(|(consultation_name, consultation)| {
                                (consultation["integration"].as_str() == Some(source_alias)).then(
                                    || {
                                        (
                                            service_name.clone(),
                                            consultation_name.clone(),
                                            consultation.clone(),
                                        )
                                    },
                                )
                            })
                    })
            })
        })
        .expect("source integration consultation");
    let mut duplicated_consultation = duplicated_consultation;
    duplicated_consultation["integration"] = serde_yaml::Value::String(target_alias.to_string());
    let service = project_document["services"]
        .as_mapping_mut()
        .and_then(|services| services.get_mut(&service_name))
        .expect("project service");
    service["consultations"]
        .as_mapping_mut()
        .expect("project consultations mapping")
        .insert(
            serde_yaml::Value::String(target_alias.to_string()),
            duplicated_consultation,
        );
    let consultation_name = consultation_name
        .as_str()
        .expect("consultation name is a string");
    let reference = format!("{consultation_name}.");
    let (source_claim_name, mut duplicated_claim) = service["claims"]
        .as_mapping()
        .and_then(|claims| {
            claims.iter().find_map(|(name, claim)| {
                yaml_contains_string(claim, &reference).then(|| (name.clone(), claim.clone()))
            })
        })
        .expect("source consultation claim");
    replace_yaml_strings(
        &mut duplicated_claim,
        &reference,
        &format!("{target_alias}."),
    );
    let claim_name = format!(
        "{target_alias}-{}",
        source_claim_name.as_str().expect("claim name is a string")
    );
    service["claims"]
        .as_mapping_mut()
        .expect("project claims mapping")
        .insert(
            serde_yaml::Value::String(claim_name.clone()),
            duplicated_claim,
        );
    for credential in service["credential_profiles"]
        .as_mapping_mut()
        .expect("project credential profiles")
        .values_mut()
    {
        credential["claims"]
            .as_sequence_mut()
            .expect("credential profile claims")
            .push(serde_yaml::Value::String(claim_name.clone()));
    }
    write_yaml(&project_path, &project_document);
    rewrite_duplicated_fixture_claims(
        &project
            .join("integrations")
            .join(target_alias)
            .join("fixtures"),
        source_claim_name
            .as_str()
            .expect("source claim name is a string"),
        &claim_name,
    );

    let environment_path = project.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    let mut source_binding = environment["integrations"][source_alias].clone();
    namespace_secret_references(&mut source_binding, target_alias);
    environment["integrations"]
        .as_mapping_mut()
        .expect("environment integrations mapping")
        .insert(
            serde_yaml::Value::String(target_alias.to_string()),
            source_binding,
        );
    write_yaml(&environment_path, &environment);
}

fn rewrite_duplicated_fixture_claims(fixtures: &Path, source_claim: &str, target_claim: &str) {
    for entry in std::fs::read_dir(fixtures).expect("duplicated fixtures directory reads") {
        let path = entry.expect("duplicated fixture entry reads").path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("yaml") {
            continue;
        }
        let mut fixture = read_yaml(&path);
        let Some(claims) = fixture["expect"]["claims"].as_mapping_mut() else {
            continue;
        };
        let source_key = serde_yaml::Value::String(source_claim.to_string());
        let Some(expected) = claims.get(&source_key).cloned() else {
            continue;
        };
        claims.clear();
        claims.insert(
            serde_yaml::Value::String(target_claim.to_string()),
            expected,
        );
        write_yaml(&path, &fixture);
    }
}

fn yaml_contains_string(value: &serde_yaml::Value, needle: &str) -> bool {
    match value {
        serde_yaml::Value::String(value) => value.contains(needle),
        serde_yaml::Value::Mapping(mapping) => mapping.iter().any(|(key, value)| {
            yaml_contains_string(key, needle) || yaml_contains_string(value, needle)
        }),
        serde_yaml::Value::Sequence(sequence) => sequence
            .iter()
            .any(|value| yaml_contains_string(value, needle)),
        _ => false,
    }
}

fn replace_yaml_strings(value: &mut serde_yaml::Value, from: &str, to: &str) {
    match value {
        serde_yaml::Value::String(value) => *value = value.replace(from, to),
        serde_yaml::Value::Mapping(mapping) => {
            for value in mapping.values_mut() {
                replace_yaml_strings(value, from, to);
            }
        }
        serde_yaml::Value::Sequence(sequence) => {
            for value in sequence {
                replace_yaml_strings(value, from, to);
            }
        }
        _ => {}
    }
}

fn namespace_secret_references(value: &mut serde_yaml::Value, namespace: &str) {
    let namespace = namespace.replace('-', "_").to_ascii_uppercase();
    namespace_secret_references_with_suffix(value, &namespace);
}

fn namespace_secret_references_with_suffix(value: &mut serde_yaml::Value, namespace: &str) {
    match value {
        serde_yaml::Value::Mapping(mapping) => {
            if let Some(secret) = mapping
                .get_mut(serde_yaml::Value::String("secret".to_string()))
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
            {
                mapping.insert(
                    serde_yaml::Value::String("secret".to_string()),
                    serde_yaml::Value::String(format!("{secret}_{namespace}")),
                );
                return;
            }
            for nested in mapping.values_mut() {
                namespace_secret_references_with_suffix(nested, namespace);
            }
        }
        serde_yaml::Value::Sequence(sequence) => {
            for nested in sequence {
                namespace_secret_references_with_suffix(nested, namespace);
            }
        }
        _ => {}
    }
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
    service["credential_profiles"]["household-eligibility"]["claims"]
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
  role: selector
  type: string
  maxLength: 16
  pattern: "^[0-9]{10}$"
family:
  role: selector
  type: string
  maxLength: 80
  pattern: "^Example$"
place:
  role: selector
  type: string
  maxLength: 120
  pattern: "^Fictional District$"
"#,
    )
    .expect("composite DCI inputs");
    integration["source"]["protocol"]["signed_dci"]["selectors"] = serde_yaml::from_str(
        r#"uin: { field: identifier_value, response_pointer: /identifier/0/identifier_value }
family: { field: family_name, response_pointer: /child/family_name }
place: { field: place_of_birth, response_pointer: /place_of_birth }
"#,
    )
    .expect("composite DCI predicates");
    write_yaml(&integration_path, &integration);
    replace_in_file(
        &project.join("integrations/birth-record/adapter.rhai"),
        "selectors: #{ uin: ctx.input.uin }",
        "selectors: #{\n            uin: ctx.input.uin,\n            family: ctx.input.family,\n            place: ctx.input.place\n        }",
    );

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
    service["credential_profiles"]["birth-summary"]["claims"]
        .as_sequence_mut()
        .expect("OpenCRVS credential claims")
        .retain(|claim| claim.as_str() != Some("age-band"));
    write_yaml(&project_path, &project_document);

    let fixture_directory = project.join("integrations/birth-record/fixtures");
    for entry in std::fs::read_dir(&fixture_directory).expect("OpenCRVS fixture directory") {
        let path = entry.expect("OpenCRVS fixture entry").path();
        if !path.is_file() {
            continue;
        }
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
        let data_interaction = fixture["interactions"]
            .as_sequence_mut()
            .and_then(|interactions| {
                interactions.iter_mut().find(|interaction| {
                    interaction["expect"]["path"].as_str() == Some("/dci/v1/birth/search")
                })
            })
            .expect("DCI data interaction");
        data_interaction["expect"]["body"]["message"]["search_request"][0]["search_criteria"]
            ["query"]["predicates"] = serde_yaml::from_str(
            r#"- { field: family_name, operator: eq, value: Example }
- { field: place_of_birth, operator: eq, value: Fictional District }
- { field: identifier_value, operator: eq, value: "0000000001" }
"#,
        )
        .expect("composite DCI request predicates");
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
