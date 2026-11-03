use std::path::PathBuf;

use registry_evidence::{
    bundle::{evidence_package_limits, Bundle},
    fixture_source::{compile_sources, fixture_acquisition},
    model::LookupResult,
    selector::resolve_offline_fixture_authorization,
};

#[tokio::test]
async fn protected_read_pack_replays_exact_requests_and_retains_lookup_outcomes() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../products/evidence/reference/request-adapter/deployment-projects/protected-read-evidence/bundle",
    );
    let verified = registry_platform_config::verify_package(
        &root,
        &evidence_package_limits(),
        "evidencectl package",
    )
    .expect("the protected-read package has an exact closure");
    let bundle = Bundle::load_as_found(&root, &verified)
        .expect("the protected read uses a current pack binding");
    let programs = compile_sources(&bundle).expect("the pack compiles without credentials");
    let requirement = &bundle.config.requirements[0];
    let fixture =
        serde_json::to_value(&bundle.fixtures[requirement.fixtures.as_ref().unwrap().as_str()])
            .unwrap();
    let expected_acquisitions = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case.get("acquisition").is_some())
        .count();
    let mut executed = 0;
    for case in fixture["cases"].as_array().unwrap() {
        let Some(acquisition) = case.get("acquisition") else {
            continue;
        };
        let resolved = resolve_offline_fixture_authorization(
            &bundle,
            requirement,
            fixture["common"].as_object(),
            case.as_object().unwrap(),
            "urn:registry-evidence:protected-read-replay",
        )
        .unwrap();
        let result = programs[requirement.initial_source()]
            .execute(
                &resolved,
                fixture_acquisition(acquisition).unwrap(),
                chrono::DateTime::parse_from_rfc3339("2026-08-02T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            )
            .await;
        let expected = &case["expected"];
        let id = case["id"].as_str().unwrap();
        match expected["lookup"].as_str() {
            Some("match") => {
                let LookupResult::Match(facts) =
                    result.unwrap_or_else(|error| panic!("{id}: {error}"))
                else {
                    panic!("{id}: expected matched facts");
                };
                let facts = serde_json::to_value(facts).unwrap();
                if let Some(exact) = expected.get("facts") {
                    assert_eq!(&facts, exact, "{id}");
                }
                assert!(
                    !facts.to_string().contains("SOURCE-UNRELATED-CANARY"),
                    "{id}"
                );
            }
            Some("no_match") => assert!(matches!(result, Ok(LookupResult::NoMatch)), "{id}"),
            Some("ambiguous") => assert!(matches!(result, Ok(LookupResult::Ambiguous)), "{id}"),
            Some("unresolved") => assert!(matches!(result, Ok(LookupResult::Unresolved)), "{id}"),
            _ => assert!(result.is_err(), "{id}: expected pre-derivation refusal"),
        }
        executed += 1;
    }
    assert_eq!(
        executed, expected_acquisitions,
        "every declared acquisition case must execute"
    );
    let source = bundle.config.sources.get("residence-register").unwrap();
    assert_eq!(source.route.as_str(), "residence-region");
    assert_eq!(source.connection.as_str(), "residence-register");
}
