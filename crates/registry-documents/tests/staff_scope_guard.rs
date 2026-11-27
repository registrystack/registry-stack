// SPDX-License-Identifier: Apache-2.0

//! A person signs in through any client of the deployment, so a staff client's
//! token may carry the scope the person holds for their own documents. The
//! staff access profile is selected by its client and then gated by its own
//! scope: a token for the staff client that carries only the citizen
//! profile's scope is refused at the scope check, and the operator's line
//! names that check.
//!
//! The database is named by `DOCUMENTS_TEST_DATABASE_URL`.

mod support;

use registry_documents::runtime::prepare_with_verifier;
use registry_platform_authcommon::FailedCheck;
use serde_json::Value;
use support::{
    Api, Deployment, FakeVerifier, Principal, APPROVE, CITIZEN, DATABASE_STORAGE,
    DISABLED_VERIFIER, STAFF,
};
use tracing::instrument::WithSubscriber as _;

/// The staff client carrying the scope of the citizen profile.
const STAFF_CLIENT_WITH_CITIZEN_SCOPE: Principal = Principal {
    scope: CITIZEN.scope,
    ..STAFF
};

async fn api(deployment: &Deployment) -> Api {
    let prepared = prepare_with_verifier(
        &deployment.runtime,
        FakeVerifier::new("staff-scope-guard", APPROVE),
    )
    .await
    .expect("the runtime prepares");
    Api::new(&prepared)
}

#[tokio::test]
async fn a_staff_client_token_with_only_the_citizen_scope_is_refused_at_the_scope_check() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let api = api(&deployment).await;
    assert_ne!(
        STAFF.scope, CITIZEN.scope,
        "each profile has a scope of its own"
    );
    assert_ne!(STAFF.client, CITIZEN.client);

    let logs = registry_platform_testing::CapturedDiagnosticLogs::default();
    let answer = api
        .get(STAFF_CLIENT_WITH_CITIZEN_SCOPE, "/v1/documents")
        .with_subscriber(logs.subscriber())
        .await;
    assert_eq!(answer.status, 403);
    let body: Value = serde_json::from_slice(&answer.body).expect("a problem body");
    assert_eq!(body["code"], "profile.not-authorized");

    let text = logs.text();
    let line: Value = text
        .lines()
        .filter(|line| line.contains("request refused"))
        .map(|line| serde_json::from_str(line).expect("a JSON log line"))
        .next()
        .unwrap_or_else(|| panic!("no refusal line\n{text}"));
    let fields = &line["fields"];
    assert_eq!(fields["failed_check"], FailedCheck::Scope.as_str());
    assert_eq!(fields["access_profile"], "staff");
    assert_eq!(fields["required_scope"], STAFF.scope);
    assert!(
        !text.contains(STAFF.client),
        "the client reached the log\n{text}"
    );
    drop(deployment);
}

#[tokio::test]
async fn each_client_is_admitted_with_the_scope_of_its_own_profile() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let api = api(&deployment).await;
    for principal in [STAFF, CITIZEN] {
        let answer = api.get(principal, "/v1/documents").await;
        assert_eq!(answer.status, 200, "{}", principal.client);
    }
    drop(deployment);
}
