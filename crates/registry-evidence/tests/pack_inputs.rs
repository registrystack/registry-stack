use registry_evidence::config::{AuthorityKind, SourceConfig, ValueOrigin};
use registry_evidence::pack_source::{authorized_route_inputs, PackSourceError};
use registry_evidence::selector::{
    ResolvedAuthorization, ResolvedSelectorField, ResolvedSelectorValue, ResolvedSubject,
    ResolvedSubjectScope,
};
use serde_json::json;

fn source() -> SourceConfig {
    serde_json::from_value(json!({
            "pack":{"id":"people","version":"1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifactPrefix":"adapter-packs/people/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            "route":"lookup","connection":"people","inputs":{"personId":{"selector":{"role":"subject","profile":"person-id","field":"identifier"}}},
            "posture":"record-transformed","factSchema":"schemas/source-facts/people.json"
        })).unwrap()
}

fn resolved() -> ResolvedAuthorization {
    ResolvedAuthorization {
        authority_profile: "service".to_owned(),
        authority_kind: AuthorityKind::Statutory,
        grant_id: None,
        requirement: "adult-status".to_owned(),
        purpose: "eligibility".to_owned(),
        subject_scope: ResolvedSubjectScope::Audience("urn:example:consumer".to_owned()),
        subjects: vec![ResolvedSubject {
            role: "subject".to_owned(),
            selector_profile: "person-id".to_owned(),
            value_origin: ValueOrigin::Request,
            fields: vec![
                ResolvedSelectorField {
                    name: "identifier".to_owned(),
                    value: ResolvedSelectorValue::String("0007".to_owned()),
                },
                ResolvedSelectorField {
                    name: "unrequested".to_owned(),
                    value: ResolvedSelectorValue::String("private-canary".to_owned()),
                },
            ],
        }],
    }
}

#[test]
fn only_bound_authorized_fields_reach_route_inputs_without_scalar_coercion() {
    assert_eq!(
        authorized_route_inputs(&source(), &resolved()).unwrap(),
        json!({"personId":"0007"})
    );
}

#[test]
fn changed_profile_missing_field_and_duplicate_role_are_refused() {
    let mut authorization = resolved();
    authorization.subjects[0].selector_profile = "other-profile".to_owned();
    assert!(matches!(
        authorized_route_inputs(&source(), &authorization),
        Err(PackSourceError::Inputs)
    ));
    let mut authorization = resolved();
    authorization.subjects[0].fields.clear();
    assert!(matches!(
        authorized_route_inputs(&source(), &authorization),
        Err(PackSourceError::Inputs)
    ));
    let mut authorization = resolved();
    authorization
        .subjects
        .push(authorization.subjects[0].clone());
    assert!(matches!(
        authorized_route_inputs(&source(), &authorization),
        Err(PackSourceError::Inputs)
    ));
}

#[test]
fn absent_optional_role_is_omitted_for_the_route_schema_to_decide() {
    let mut authorization = resolved();
    authorization.subjects.clear();
    assert_eq!(
        authorized_route_inputs(&source(), &authorization).unwrap(),
        json!({})
    );
}

#[test]
fn offline_source_fixtures_require_an_exact_transcript_instead_of_precomputed_facts() {
    use registry_evidence::fixture_source::fixture_acquisition;
    for invalid in [
        json!({"lookup":"matched","facts":{"adult":true}}),
        json!({"total":1,"record":{"id":"0007"}}),
        json!({"intercepts":[],"exchanges":[],"liveOrigin":"https://unreviewed.invalid"}),
    ] {
        assert!(fixture_acquisition(&invalid).is_err());
    }
    let fixture = fixture_acquisition(&json!({
        "intercepts":[{"type":"endpoint","endpoint":"people"}],
        "exchanges":[{
            "request":{"endpoint":"people","method":"GET","path":"/people/0007"},
            "response":{"status":200,"body":{"id":"0007"}}
        }]
    }))
    .unwrap();
    assert_eq!(fixture.exchanges.len(), 1);
}

#[test]
fn maintained_acceptance_bundles_compile_without_runtime_bindings_or_credentials() {
    use registry_evidence::{
        bundle::{evidence_package_limits, Bundle},
        fixture_source::compile_sources,
        kernel::OfflineKernel,
    };
    use std::{path::PathBuf, sync::Arc};
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../products/evidence/fixtures");
    for fixture in [
        "acceptance/all-definitions",
        "acceptance/holder-bound",
        "acceptance/adult-status",
        "acceptance/residence-region",
        "acceptance/professional-licence",
        "acceptance/legal-parent-relationship",
        "conformance/supported-values",
    ] {
        let path = root.join(fixture);
        let verified = registry_platform_config::verify_package(
            &path,
            &evidence_package_limits(),
            "evidencectl package",
        )
        .expect("maintained package checksum closure");
        let bundle = Arc::new(
            Bundle::load_as_found(&path, &verified)
                .unwrap_or_else(|error| panic!("{fixture}: {error}")),
        );
        compile_sources(&bundle).unwrap_or_else(|error| panic!("{fixture}: {error}"));
        OfflineKernel::compile(bundle).unwrap_or_else(|error| panic!("{fixture}: {error}"));
    }
}

#[test]
fn generated_facts_schema_can_change_formatting_but_cannot_change_its_contract() {
    use registry_evidence::bundle::{evidence_package_limits, Bundle};
    use std::{fs, path::Path};
    fn copy_tree(source: &Path, target: &Path) {
        fs::create_dir_all(target).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = target.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                assert!(entry.file_type().unwrap().is_file());
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }
    fn load(root: &Path) -> Result<Bundle, registry_evidence::bundle::BundleError> {
        // This file belongs only to this test's disposable package copy.
        fs::remove_file(root.join(registry_platform_config::SUM_FILE)).unwrap();
        let verified = registry_platform_config::write_sum_file(
            root,
            None,
            &evidence_package_limits(),
            "evidencectl package",
        )
        .unwrap();
        Bundle::load_as_found(root, &verified)
    }
    let scratch = tempfile::tempdir().unwrap();
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance/adult-status"),
        scratch.path(),
    );
    let schema_path = scratch.path().join("schemas/facts.schema.yaml");
    let mut schema: serde_json::Value =
        serde_json::from_slice(&fs::read(&schema_path).unwrap()).unwrap();
    fs::write(&schema_path, serde_json::to_vec(&schema).unwrap()).unwrap();
    load(scratch.path()).expect("JSON formatting preserves the exact schema contract");
    schema["properties"]["date_of_birth"]["type"] = json!("integer");
    fs::write(schema_path, serde_json::to_vec(&schema).unwrap()).unwrap();
    assert!(
        load(scratch.path()).is_err(),
        "a projected artifact cannot replace the original pack facts contract"
    );
}

#[test]
fn opencrvs_reference_uses_the_same_reviewed_pack_as_the_facade() {
    use registry_evidence::bundle::{evidence_package_limits, Bundle};
    use std::{fs, path::PathBuf};
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = repository.join("products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence/bundle");
    let verified = registry_platform_config::verify_package(
        &root,
        &evidence_package_limits(),
        "evidencectl package",
    )
    .unwrap();
    let bundle = Bundle::load_as_found(&root, &verified).expect("current pack bindings");
    registry_evidence::fixture_source::compile_sources(&bundle).expect("pure provider compile");
    let maintained_pack =
        fs::read(repository.join("products/adapter/packs/opencrvs-events/pack.yaml")).unwrap();
    for (_, source) in bundle.config.sources.iter() {
        assert_eq!(source.pack.id.as_str(), "opencrvs-events");
        assert_eq!(
            source.pack.digest.as_str(),
            registry_platform_config::sha256_uri(&maintained_pack)
        );
        assert_eq!(
            fs::read(
                root.join(source.pack.artifact_prefix.as_str())
                    .join("pack.yaml")
            )
            .unwrap(),
            maintained_pack
        );
    }
}

#[test]
fn reference_fixture_reader_accepts_the_complete_acquisition_transcript() {
    use registry_evidence::{config::AssuranceProfile, fixture::read_fixture};
    let fixture = b"apiVersion: id.registrystack.org/formats/evidence/fixture/v1alpha1\nkind: EvidenceFixture\nsyntheticOnly: true\ncommon: {}\nprivacyExpectation: {}\ncases:\n  - id: positive\n    acquisition: {intercepts: [], exchanges: []}\n    expected: {lookup: match, signed: true, derivationRuns: true}\n";
    let value = read_fixture(
        "fixtures/cases.yaml",
        fixture,
        false,
        AssuranceProfile::Local,
    )
    .expect("the same transcript control key used by the evaluator");
    assert!(value["cases"][0]["acquisition"].is_object());
}

#[tokio::test]
async fn shared_opencrvs_provider_executes_sealed_oauth_and_data_exchanges() {
    use registry_evidence::{
        bundle::{evidence_package_limits, Bundle},
        fixture_source::{compile_sources, fixture_acquisition},
        model::LookupResult,
        selector::resolve_offline_fixture_authorization,
    };
    use std::path::PathBuf;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence/bundle");
    let verified = registry_platform_config::verify_package(
        &root,
        &evidence_package_limits(),
        "evidencectl package",
    )
    .unwrap();
    let bundle = Bundle::load_as_found(&root, &verified).unwrap();
    let programs = compile_sources(&bundle).unwrap();
    for requirement in &bundle.config.requirements {
        let fixture_path = requirement.fixtures.as_ref().unwrap().as_str();
        let fixture = serde_json::to_value(&bundle.fixtures[fixture_path]).unwrap();
        let case = fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["id"] == "positive")
            .unwrap()
            .as_object()
            .unwrap();
        let resolved = resolve_offline_fixture_authorization(
            &bundle,
            requirement,
            fixture["common"].as_object(),
            case,
            "urn:registry-evidence:offline-evaluation",
        )
        .unwrap();
        let acquired = programs
            .get(requirement.initial_source())
            .unwrap()
            .execute(
                &resolved,
                fixture_acquisition(&case["acquisition"]).unwrap(),
                chrono::DateTime::parse_from_rfc3339("2026-08-02T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            )
            .await
            .unwrap();
        assert!(
            matches!(acquired, LookupResult::Match(_)),
            "{}",
            requirement.id
        );
    }
}

#[test]
fn reviewed_alternate_profiles_project_only_the_exact_authorized_profile() {
    let mut source = source();
    source.inputs.insert(
        "citizenNumber".to_owned(),
        serde_json::from_value(json!({
            "selector": {"role": "subject", "profile": "citizen-id", "field": "citizen_number"}
        }))
        .unwrap(),
    );
    assert_eq!(
        authorized_route_inputs(&source, &resolved()).unwrap(),
        json!({"personId": "0007"}),
        "a different reviewed profile cannot contribute fields to this request"
    );
    let mut authorization = resolved();
    authorization.subjects[0].selector_profile = "citizen-id".to_owned();
    authorization.subjects[0].fields = vec![ResolvedSelectorField {
        name: "citizen_number".to_owned(),
        value: ResolvedSelectorValue::String("000012".to_owned()),
    }];
    assert_eq!(
        authorized_route_inputs(&source, &authorization).unwrap(),
        json!({"citizenNumber": "000012"})
    );
    authorization.subjects[0].selector_profile = "unreviewed-id".to_owned();
    assert!(matches!(
        authorized_route_inputs(&source, &authorization),
        Err(PackSourceError::Inputs)
    ));
    authorization.subjects[0].selector_profile = "citizen-id".to_owned();
    authorization.subjects[0].fields[0].name = "identifier".to_owned();
    assert!(matches!(
        authorized_route_inputs(&source, &authorization),
        Err(PackSourceError::Inputs)
    ));
}
