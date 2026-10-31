// SPDX-License-Identifier: Apache-2.0

//! Native acceptance proof for every authored API transformation experiment.
//! Each case runs the external adapterctl acceptance commands, then starts the
//! real Adapter binary over an isolated PostgreSQL schema and drives the
//! documented facade request through the compiled pack to a socket upstream.
#![cfg(feature = "postgres-test")]

#[path = "support/experiments/mod.rs"]
mod experiments;

use experiments::upstream::Upstream;
use experiments::{
    assert_fixture_response, assert_transcript, Fixture, NativeExperiment, Scenario,
};

async fn execute(scenario: Scenario) {
    let fixture = Fixture::load(scenario);
    let upstream = if matches!(scenario, Scenario::RestMutualTls | Scenario::SecondProfile) {
        Upstream::mutual_tls().await
    } else {
        Upstream::plain()
    };
    upstream.respond_with(fixture.responses());

    let served = NativeExperiment::start(scenario, &upstream).await;
    served.run_cli_acceptance(&fixture);
    served.assert_forged_token_rejected(&fixture, &upstream);
    let response = served.call(&fixture);

    assert_transcript(scenario, &fixture, &upstream);
    assert_fixture_response(&fixture, &response);
}

#[tokio::test(flavor = "multi_thread")]
async fn fhir_patient_search_runs_both_documented_pages_with_oauth2() {
    execute(Scenario::FhirPatient).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn fhir_conditional_create_runs_the_transaction_and_readback_with_oauth2() {
    execute(Scenario::FhirConditionalCreate).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn graphql_case_search_runs_with_the_declared_api_key() {
    execute(Scenario::GraphQlCases).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rest_offset_search_runs_with_mutual_tls_and_a_signed_client_assertion() {
    execute(Scenario::RestMutualTls).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn second_target_profile_runs_the_same_pack_to_its_distinct_closed_shape() {
    execute(Scenario::SecondProfile).await;
}
