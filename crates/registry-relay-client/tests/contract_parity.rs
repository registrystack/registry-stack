use registry_relay_client::ProblemCode;
use registry_relay_http_contract::{routes, PROBLEM_MEDIA_TYPE};

#[test]
fn fixed_route_inventory_and_problem_catalog_are_shared() {
    assert_eq!(
        routes::ALL,
        [
            "/health",
            "/ready",
            "/openapi.json",
            "/v2",
            "/v2/resources",
            "/v2/resources/{resource}",
            "/v2/resources/{resource}/records",
            "/v2/resources/{resource}/records/{record_identifier}",
            "/v2/resources/{resource}/lookups/{lookup}",
            "/v2/resources/{resource}/searches/{search}",
            "/v2/artifacts/{artifact_identifier}",
            "/sdmx/v2/data/{context}/{agency}/{resource}/{version}/{key}",
            "/sdmx/v2/data/{context}/{agency}/{resource}/{version}",
            "/sdmx/v2/structure/{artefact_type}/{agency}/{resource}/{version}",
        ]
    );
    assert_eq!(PROBLEM_MEDIA_TYPE, "application/problem+json");
    assert_eq!(ProblemCode::ALL.len(), 26);
    for problem in ProblemCode::ALL {
        assert!((400..=599).contains(&problem.status()));
        assert!(problem
            .type_uri()
            .contains(&problem.code().replace('.', "/")));
    }
}
