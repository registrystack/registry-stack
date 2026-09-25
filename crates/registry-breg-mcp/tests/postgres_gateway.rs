// SPDX-License-Identifier: Apache-2.0

//! The citizen gateway against a real Base Registry Engine on PostgreSQL.

#![cfg(all(feature = "postgres-test", unix))]

#[path = "support/gateway.rs"]
mod gateway;
#[path = "support/mock_registry.rs"]
mod mock_registry;
#[path = "../../registry-breg/tests/support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;
#[path = "support/real_registry.rs"]
mod real_registry;

use real_registry::{citizen_journey, RealRegistry, ReviewPage, CITIZEN_A, CITIZEN_B};
use serde_json::{json, Value};
use tempfile::TempDir;

/// A gateway served on its own loopback port, configured against `fixture`.
struct RunningGateway {
    resource: String,
    _directory: TempDir,
}

impl RunningGateway {
    /// Serve a gateway whose review links point under `review`.
    async fn start(
        listener: tokio::net::TcpListener,
        fixture: &RealRegistry,
        review: &str,
    ) -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        let address = listener.local_addr().expect("gateway address");
        let config_path = real_registry::write_gateway_config(
            directory.path(),
            &address.to_string(),
            fixture,
            review,
        );
        gateway::serve(listener, &config_path).await;
        Self {
            resource: fixture.gateway_resource.clone(),
            _directory: directory,
        }
    }
}

async fn gateway_listener() -> (tokio::net::TcpListener, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("gateway listens");
    let resource = format!(
        "http://{}/mcp",
        listener.local_addr().expect("gateway address")
    );
    (listener, resource)
}

/// The metadata the stand-in registry serves is the registry's own answer
/// for the citizen agent profile, so the unit and protocol suites exercise
/// the contract a real engine publishes.
#[tokio::test(flavor = "multi_thread")]
async fn the_captured_agent_metadata_is_the_registrys_own() {
    let (_listener, resource) = gateway_listener().await;
    let fixture = RealRegistry::start(&resource, None).await;
    fixture.seed_citizen("A-1", CITIZEN_A).await;
    let token = fixture.agent_token(CITIZEN_A, true).await;
    let response = reqwest::Client::new()
        .get(format!(
            "{}/v1/registry?accessProfile=citizen-agent",
            fixture.base_url
        ))
        .header("authorization", token)
        .send()
        .await
        .expect("registry answers");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let live: Value = response.json().await.expect("metadata is JSON");
    let captured: Value =
        serde_json::from_slice(mock_registry::METADATA).expect("captured metadata is JSON");
    assert_eq!(live, captured);
    fixture.finish().await;
}

/// A token exchanged without the gateway's actor assertion names the citizen
/// but no agent, and the agent profile refuses it.
#[tokio::test(flavor = "multi_thread")]
async fn a_token_exchanged_without_the_actor_is_refused_by_the_registry() {
    let (_listener, resource) = gateway_listener().await;
    let fixture = RealRegistry::start(&resource, None).await;
    fixture.seed_citizen("A-1", CITIZEN_A).await;
    let token = fixture.agent_token(CITIZEN_A, false).await;
    let response = reqwest::Client::new()
        .get(format!(
            "{}/v1/records/person-addresses?accessProfile=citizen-agent",
            fixture.base_url
        ))
        .header("authorization", token)
        .send()
        .await
        .expect("registry answers");
    let status = response.status();
    let body = response.text().await.expect("refusal body");
    assert!(status.is_client_error(), "{status}");
    assert!(!body.contains("1 Harbour Road"));
    fixture.finish().await;
}

/// Citizen B's chat host tries every way the tool surface offers to name
/// citizen A's address. Nothing lands; the one draft B creates names B's
/// own address, resolved by the gateway through B's delegated lookup.
#[tokio::test(flavor = "multi_thread")]
async fn the_gateway_writes_only_the_citizens_own_address() {
    let (listener, resource) = gateway_listener().await;
    let fixture = RealRegistry::start(&resource, None).await;
    let address_a = fixture.seed_citizen("A-1", CITIZEN_A).await;
    let address_b = fixture.seed_citizen("B-1", CITIZEN_B).await;
    let running = RunningGateway::start(listener, &fixture, gateway::REVIEW_BASE_URL).await;
    let client = gateway::connect(&running.resource, &fixture.chat_host_token(CITIZEN_B)).await;

    let details = gateway::call(&client, "get_my_details", json!({})).await;
    assert_eq!(details.is_error, Some(false), "{details:?}");
    let details = serde_json::to_string(&gateway::structured(&details)).expect("details");
    assert!(details.contains("4 Mill Street"), "{details}");
    assert!(!details.contains("1 Harbour Road"), "{details}");

    let fields = json!({"newAddressLine": "2 Quay", "newLocality": "Port Selene", "newPostalCode": "PS-200"});
    for (field, value) in [("address", address_a.as_str()), ("owner", CITIZEN_A)] {
        let mut smuggled = fields.clone();
        smuggled[field] = json!(value);
        let result = gateway::call(&client, "start_application", smuggled).await;
        assert_eq!(gateway::error_code(&result), "invalid-arguments", "{field}");
    }
    assert!(fixture.listed_requests().await.is_empty());

    let started = gateway::call(&client, "start_application", fields).await;
    assert_eq!(started.is_error, Some(false), "{started:?}");
    let application = gateway::structured(&started)["application"].clone();
    assert_eq!(application["status"], "prepared");
    let identifier = application["applicationId"].clone();
    for path in ["/address", "/owner", "/data/address"] {
        let result = gateway::call(
            &client,
            "update_application",
            json!({"applicationId": identifier, "expectedRevision": application["revision"],
                "patch": [{"op": "replace", "path": path, "value": address_a}]}),
        )
        .await;
        assert_eq!(gateway::error_code(&result), "invalid-arguments", "{path}");
    }
    let updated = gateway::call(
        &client,
        "update_application",
        json!({"applicationId": identifier, "expectedRevision": application["revision"],
            "patch": [{"op": "replace", "path": "/newLocality", "value": "Old Town"}]}),
    )
    .await;
    assert_eq!(updated.is_error, Some(false), "{updated:?}");
    let status = gateway::call(
        &client,
        "get_application_status",
        json!({"applicationId": identifier}),
    )
    .await;
    assert_eq!(
        gateway::structured(&status)["application"]["status"],
        "prepared"
    );
    let review = gateway::call(
        &client,
        "prepare_review",
        json!({"applicationId": identifier}),
    )
    .await;
    assert_eq!(review.is_error, Some(false), "{review:?}");
    client.cancel().await.expect("client closes");

    let listed = fixture.listed_requests().await;
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(
        listed[0]["domainData"]["address"],
        address_b.as_str(),
        "{listed:?}"
    );
    assert_eq!(listed[0]["domainData"]["newLocality"], "Old Town");
    assert!(!serde_json::to_string(&listed)
        .expect("listed")
        .contains(&address_a));
    fixture.finish().await;
}

/// A retried start returns the draft it already created, and once the
/// citizen cancels that draft on the review page the same values start a
/// new application instead of replaying the closed one.
#[tokio::test(flavor = "multi_thread")]
async fn a_citizen_starts_again_after_cancelling_and_a_retry_reuses_the_draft() {
    let (listener, resource) = gateway_listener().await;
    let fixture = RealRegistry::start(&resource, None).await;
    fixture.seed_citizen("B-1", CITIZEN_B).await;
    let running = RunningGateway::start(listener, &fixture, gateway::REVIEW_BASE_URL).await;
    let client = gateway::connect(&running.resource, &fixture.chat_host_token(CITIZEN_B)).await;
    let fields = json!({"newAddressLine": "2 Quay", "newLocality": "Port Selene", "newPostalCode": "PS-200"});

    let start = || gateway::call(&client, "start_application", fields.clone());
    let first = start().await;
    assert_eq!(first.is_error, Some(false), "{first:?}");
    let first = gateway::structured(&first)["application"].clone();
    let retried = start().await;
    assert_eq!(retried.is_error, Some(false), "{retried:?}");
    assert_eq!(
        gateway::structured(&retried)["application"]["applicationId"],
        first["applicationId"]
    );

    fixture
        .cancel_as_citizen(
            CITIZEN_B,
            first["applicationId"].as_str().expect("identifier"),
        )
        .await;
    let status = gateway::call(
        &client,
        "get_application_status",
        json!({"applicationId": first["applicationId"]}),
    )
    .await;
    assert_eq!(
        gateway::structured(&status)["application"]["status"],
        "cancelled"
    );

    let second = start().await;
    assert_eq!(second.is_error, Some(false), "{second:?}");
    let second = gateway::structured(&second)["application"].clone();
    assert_ne!(second["applicationId"], first["applicationId"]);
    assert_eq!(second["status"], "prepared");
    let retried = start().await;
    assert_eq!(retried.is_error, Some(false), "{retried:?}");
    assert_eq!(
        gateway::structured(&retried)["application"]["applicationId"],
        second["applicationId"]
    );
    client.cancel().await.expect("client closes");

    let listed = fixture.listed_requests().await;
    let mut states: Vec<&str> = listed
        .iter()
        .map(|item| item["request"]["bregState"].as_str().expect("state"))
        .collect();
    states.sort_unstable();
    assert_eq!(states, ["cancelled", "draft"], "{listed:?}");
    fixture.finish().await;
}

/// An update whose answer was lost, retried with the same arguments, is
/// answered as applied rather than stale, and applies nothing twice. A
/// different edit from the same stale revision is still refused and never
/// lands over the change that moved the application on.
#[tokio::test(flavor = "multi_thread")]
async fn a_retried_update_is_applied_once_and_a_concurrent_edit_stays_stale() {
    let (listener, resource) = gateway_listener().await;
    let fixture = RealRegistry::start(&resource, None).await;
    fixture.seed_citizen("B-1", CITIZEN_B).await;
    let running = RunningGateway::start(listener, &fixture, gateway::REVIEW_BASE_URL).await;
    let client = gateway::connect(&running.resource, &fixture.chat_host_token(CITIZEN_B)).await;

    let started = gateway::call(
        &client,
        "start_application",
        json!({"newAddressLine": "2 Quay", "newLocality": "Port Selene", "newPostalCode": "PS-200"}),
    )
    .await;
    assert_eq!(started.is_error, Some(false), "{started:?}");
    let application = gateway::structured(&started)["application"].clone();
    let update = |locality: &str| {
        gateway::call(
            &client,
            "update_application",
            json!({"applicationId": application["applicationId"],
                "expectedRevision": application["revision"],
                "patch": [{"op": "replace", "path": "/newLocality", "value": locality}]}),
        )
    };
    let locality = |result: &rmcp::model::CallToolResult| {
        gateway::structured(result)["registryData"]["fields"]
            .as_array()
            .and_then(|fields| {
                fields
                    .iter()
                    .find(|field| field["name"] == "newLocality")
                    .map(|field| field["value"].clone())
            })
            .expect("the locality is reported")
    };

    let first = update("Old Town").await;
    assert_eq!(first.is_error, Some(false), "{first:?}");
    let applied = gateway::structured(&first)["application"]["revision"].clone();
    assert_ne!(applied, application["revision"]);

    // The chat host never saw the first answer and sends the same call.
    let retried = update("Old Town").await;
    assert_eq!(retried.is_error, Some(false), "{retried:?}");
    assert_eq!(
        gateway::structured(&retried)["application"]["revision"],
        applied
    );
    assert_eq!(locality(&retried), "Old Town");

    // Another edit from the revision the first update moved past is stale.
    let concurrent = update("New Town").await;
    assert_eq!(gateway::error_code(&concurrent), "stale-application");
    let status = gateway::call(
        &client,
        "get_application_status",
        json!({"applicationId": application["applicationId"]}),
    )
    .await;
    assert_eq!(
        gateway::structured(&status)["application"]["revision"],
        applied
    );
    assert_eq!(locality(&status), "Old Town");
    client.cancel().await.expect("client closes");
    fixture.finish().await;
}

/// The whole citizen journey across the three services on one registry,
/// with the gateway and the review page served in process. The scripted
/// local run drives the same journey against their binaries.
#[tokio::test(flavor = "multi_thread")]
async fn the_citizen_journey_runs_from_chat_to_an_applied_change() {
    let (listener, resource) = gateway_listener().await;
    let page_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("review page listens");
    let page_origin = format!(
        "http://{}",
        page_listener.local_addr().expect("review page address")
    );
    let fixture = RealRegistry::start(&resource, Some(&page_origin)).await;
    let running = RunningGateway::start(listener, &fixture, &format!("{page_origin}/")).await;
    let page = ReviewPage::start(page_listener, &page_origin, &fixture).await;
    citizen_journey(&fixture, &running.resource, &page).await;
    page.finish().await;
    fixture.finish().await;
}
