// SPDX-License-Identifier: Apache-2.0

use base64::Engine as _;
use registry_breg_client::BRegProblemCode;
use registry_platform_audit::{AuditDestination, AuditProfile, AuditWriter, FileDestination};
use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
use registry_platform_testing::{
    ExchangeProfile, TestActorKind, TestAuthorizationServer, TestClient,
};
use serde_json::json;
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::*;
use crate::{
    audit::AuditCapture,
    config::{ExchangeConfig, RegistryConfig},
    contract::tests::spec,
    inbound::VerifiedCaller,
    mock_registry::{draft_request, MockRegistry, Seen},
};

const AUDIENCE: &str = "urn:breg:citizen-address-correction";
const RESOURCE: &str = "https://gateway.example.test/mcp";
const GATEWAY: &str = "citizen-gateway";
const ACTOR: &str = "6f1c2d8e-3b4a-4e59-9c7d-2a8b5e0f1d34";
const SCOPE: &str = "address-correction:self";
const CITIZEN_A: &str = "synthetic-citizen-a";
const CITIZEN_B: &str = "synthetic-citizen-b";
const ADDRESS_A: &str = "c7110c06-8938-4294-bd68-7390de8e752e";
const ADDRESS_B: &str = "5b0a3c1e-2d4f-4a6b-8c9d-0e1f2a3b4c5d";
const CANARY: &str = "canary-field-value-7f3a";

struct Fixture {
    server: TestAuthorizationServer,
    registry: MockRegistry,
    gateway: Gateway,
    directory: TempDir,
}

impl Fixture {
    async fn start() -> Self {
        Self::start_with_audit(None).await
    }

    async fn start_with_audit(override_audit: Option<ToolAuditLog>) -> Self {
        let key = generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("key");
        let server = TestAuthorizationServer::builder()
            .client(
                TestClient::new(GATEWAY)
                    .with_public_jwk(key.public())
                    .with_resource(AUDIENCE)
                    // The gateway's actor token is requested for its own resource.
                    .with_resource(RESOURCE)
                    .with_actor_kind(TestActorKind::Agent)
                    .with_service_subject(ACTOR),
            )
            .client(TestClient::new("chat-host").with_resource(RESOURCE))
            .exchange_profile(ExchangeProfile::Conformant)
            .start()
            .await;
        let registry = MockRegistry::start().await;
        registry.add_address(CITIZEN_A, ADDRESS_A, "1 Harbour Road");
        registry.add_address(CITIZEN_B, ADDRESS_B, "4 Mill Street");
        let outbound = Outbound::new(
            &RegistryConfig {
                base_url: registry.base_url.clone(),
                access_profile: "citizen-agent".to_owned(),
                audience: AUDIENCE.to_owned(),
                scopes: vec![SCOPE.to_owned()],
                request_timeout_milliseconds: 5_000,
            },
            &ExchangeConfig {
                token_endpoint: server.token_endpoint(),
                client_id: GATEWAY.to_owned(),
                private_key_ref: "secret:file/unused".to_owned(),
                assertion_audience: None,
            },
            RESOURCE,
            key,
        )
        .expect("outbound configures");
        let directory = tempfile::tempdir().expect("temporary directory");
        let profile = AuditProfile::production_from_secret_bytes(Zeroizing::new(vec![9; 32]))
            .expect("audit profile");
        let destination = AuditDestination::File(
            FileDestination::new(directory.path().join("audit.jsonl")).expect("audit destination"),
        );
        let audit = match override_audit {
            Some(audit) => audit,
            None => ToolAuditLog::new(AuditWriter::open(destination).await.expect("audit opens")),
        };
        let gateway = Gateway::new(
            outbound,
            spec(),
            ServiceDescription {
                name: "Address correction".to_owned(),
                description: "Correct the postal address the registry holds for you.".to_owned(),
                disclosure: "The assistant will see your current address.".to_owned(),
            },
            Url::parse("https://review.example.test/").expect("review url"),
            audit,
            profile.key_hasher(),
        );
        Self {
            server,
            registry,
            gateway,
            directory,
        }
    }

    fn caller(&self, citizen: &str) -> VerifiedCaller {
        let expires_at = now() + 300;
        let token =
            self.server
                .issue_access_token("chat-host", citizen, RESOURCE, SCOPE, expires_at);
        VerifiedCaller::for_test(
            &self.server.issuer(),
            citizen,
            "chat-host",
            &token,
            expires_at,
        )
    }

    async fn call(&self, caller: &VerifiedCaller, tool: &str, arguments: Value) -> Value {
        let arguments = arguments.as_object().cloned();
        let result = self.gateway.call(caller, tool, arguments.as_ref()).await;
        let mut value = result.structured_content.expect("structured result");
        value["isError"] = Value::Bool(result.is_error == Some(true));
        value
    }

    fn writes(&self) -> Vec<Seen> {
        self.registry
            .seen()
            .into_iter()
            .filter(|seen| seen.method != http::Method::GET)
            .collect()
    }

    fn audit_text(&self) -> String {
        std::fs::read_to_string(self.directory.path().join("audit.jsonl")).expect("audit reads")
    }
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("time fits")
}

fn error_code(value: &Value) -> &str {
    assert_eq!(value["isError"], Value::Bool(true), "{value}");
    value["error"]["code"].as_str().expect("error code")
}

fn start_arguments() -> Value {
    json!({"newAddressLine": "2 Quay", "newLocality": "Port Selene", "newPostalCode": "PS-200"})
}

fn claims(authorization: &str) -> Value {
    let token = authorization.strip_prefix("Bearer ").expect("bearer");
    let payload = token.split('.').nth(1).expect("payload");
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("base64"),
    )
    .expect("claims")
}

#[tokio::test]
async fn describe_service_reads_nothing_from_the_registry() {
    let fixture = Fixture::start().await;
    let caller = fixture.caller(CITIZEN_A);
    let value = fixture.call(&caller, DESCRIBE_SERVICE, json!({})).await;
    assert_eq!(value["isError"], false);
    assert_eq!(value["service"]["name"], "Address correction");
    assert_eq!(
        value["service"]["disclosure"],
        "The assistant will see your current address."
    );
    assert!(fixture.registry.seen().is_empty());
}

#[tokio::test]
async fn audit_request_refusal_prevents_exchange_and_registry_dispatch() {
    let mut fixture = Fixture::start_with_audit(Some(ToolAuditLog::refusing_after(0))).await;
    let dispatch = fixture.gateway.pause_dispatch();
    let caller = fixture.caller(CITIZEN_A);
    let value = fixture.call(&caller, GET_MY_DETAILS, json!({})).await;
    assert_eq!(error_code(&value), "service-unavailable");
    assert!(!dispatch.was_entered());
    assert!(fixture.registry.seen().is_empty());
}

#[tokio::test]
async fn audit_response_refusal_withholds_the_tool_result() {
    let fixture = Fixture::start_with_audit(Some(ToolAuditLog::refusing_after(1))).await;
    let caller = fixture.caller(CITIZEN_A);
    let value = fixture.call(&caller, GET_MY_DETAILS, json!({})).await;
    assert_eq!(error_code(&value), "service-unavailable");
    assert!(value.get("registryData").is_none(), "{value}");
    assert!(!fixture.registry.seen().is_empty());
}

#[tokio::test]
async fn cancelling_an_in_flight_call_writes_same_correlation_unfinished() {
    let (audit, capture): (ToolAuditLog, AuditCapture) = ToolAuditLog::capture();
    let mut fixture = Fixture::start_with_audit(Some(audit)).await;
    let barrier = fixture.gateway.pause_dispatch();
    let caller = fixture.caller(CITIZEN_A);
    let arguments = Map::new();
    {
        let call = fixture
            .gateway
            .call(&caller, GET_MY_DETAILS, Some(&arguments));
        tokio::pin!(call);
        tokio::select! {
            () = barrier.wait_until_entered() => {}
            result = &mut call => panic!("call completed before cancellation: {result:?}"),
        }
    }

    let entries = capture.entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["phase"], "request");
    assert_eq!(entries[1]["phase"], "response");
    assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
    assert_eq!(entries[1]["record"]["outcome"], "unfinished");
    assert_eq!(entries[1]["record"]["tool"], GET_MY_DETAILS);
    assert_eq!(
        entries[1]["record"]["principalPseudonym"],
        caller.citizen_pseudonym()
    );
    assert_eq!(
        entries[1]["record"]["clientPseudonym"],
        caller.client_pseudonym()
    );
    assert!(entries[1]["record"].get("reason").is_none());
    assert!(fixture.registry.seen().is_empty());
}

#[tokio::test]
async fn my_details_are_labelled_registry_data_for_the_caller_only() {
    let fixture = Fixture::start().await;
    let caller = fixture.caller(CITIZEN_A);
    let value = fixture.call(&caller, GET_MY_DETAILS, json!({})).await;
    assert_eq!(value["isError"], false, "{value}");
    assert_eq!(value["notice"], REGISTRY_DATA_NOTICE);
    assert_eq!(
        value["registryData"]["fields"],
        json!([
            {"name": "addressLine", "label": "Address line", "value": "1 Harbour Road"},
            {"name": "locality", "label": "Locality", "value": "Port Selene"},
            {"name": "postalCode", "label": "Postal code", "value": "PS-100"},
        ])
    );
    assert!(!value.to_string().contains("4 Mill Street"));
}

#[tokio::test]
async fn no_linked_record_or_more_than_one_creates_nothing() {
    let fixture = Fixture::start().await;
    fixture.registry.add_address(
        CITIZEN_B,
        "0f0e0d0c-0b0a-4908-8706-050403020100",
        "9 Second Street",
    );
    for citizen in ["synthetic-citizen-unlinked", CITIZEN_B] {
        let caller = fixture.caller(citizen);
        let details = fixture.call(&caller, GET_MY_DETAILS, json!({})).await;
        assert_eq!(error_code(&details), "record-not-resolved");
        let started = fixture
            .call(&caller, START_APPLICATION, start_arguments())
            .await;
        assert_eq!(error_code(&started), "record-not-resolved");
    }
    assert!(fixture.writes().is_empty());
}

#[tokio::test]
async fn start_writes_the_callers_own_target_and_owner() {
    let fixture = Fixture::start().await;
    let caller = fixture.caller(CITIZEN_A);
    let value = fixture
        .call(&caller, START_APPLICATION, start_arguments())
        .await;
    assert_eq!(value["isError"], false, "{value}");
    assert_eq!(value["application"]["status"], "prepared");
    assert_eq!(value["application"]["revision"], "1");
    let writes = fixture.writes();
    assert_eq!(writes.len(), 1);
    let body = writes[0].body.as_ref().expect("create body");
    assert_eq!(body["data"]["address"], ADDRESS_A);
    assert_eq!(body["data"]["owner"], CITIZEN_A);
    assert!(writes[0]
        .idempotency_key
        .as_deref()
        .is_some_and(|key| key.len() <= 256));
    assert!(!value.to_string().contains(ADDRESS_A));
}

#[tokio::test]
async fn a_smuggled_target_argument_never_reaches_the_registry() {
    let fixture = Fixture::start().await;
    let caller = fixture.caller(CITIZEN_B);
    let mut arguments = start_arguments();
    arguments["address"] = json!(ADDRESS_A);
    let value = fixture.call(&caller, START_APPLICATION, arguments).await;
    assert_eq!(error_code(&value), "invalid-arguments");
    let mut arguments = start_arguments();
    arguments["owner"] = json!(CITIZEN_A);
    let value = fixture.call(&caller, START_APPLICATION, arguments).await;
    assert_eq!(error_code(&value), "invalid-arguments");
    assert!(fixture.registry.seen().is_empty());
    assert!(fixture.registry.applications().is_empty());
}

#[tokio::test]
async fn a_patch_path_aimed_at_the_target_never_reaches_the_registry() {
    let fixture = Fixture::start().await;
    let application = fixture.registry.add_application(
        json!({"address": ADDRESS_B, "newAddressLine": "5 Quay", "newLocality": "Port Selene", "newPostalCode": "PS-500"}),
        draft_request(),
    );
    let caller = fixture.caller(CITIZEN_B);
    for path in ["/address", "/data/address", "/owner"] {
        let value = fixture
            .call(
                &caller,
                UPDATE_APPLICATION,
                json!({"applicationId": application.to_string(), "expectedRevision": "1",
                    "patch": [{"op": "replace", "path": path, "value": ADDRESS_A}]}),
            )
            .await;
        assert_eq!(error_code(&value), "invalid-arguments", "{path}");
    }
    assert!(fixture.registry.seen().is_empty());
    assert_eq!(
        fixture.registry.applications()[&application].data["address"],
        ADDRESS_B
    );
}

#[tokio::test]
async fn a_draft_naming_another_target_is_neither_changed_nor_shown() {
    let fixture = Fixture::start().await;
    // A draft that names citizen A's address, visible to citizen B.
    let application = fixture.registry.add_application(
        json!({"address": ADDRESS_A, "newAddressLine": "5 Quay", "newLocality": "Port Selene", "newPostalCode": "PS-500"}),
        draft_request(),
    );
    let caller = fixture.caller(CITIZEN_B);
    let update = fixture
        .call(
            &caller,
            UPDATE_APPLICATION,
            json!({"applicationId": application.to_string(), "expectedRevision": "1",
                "patch": [{"op": "replace", "path": "/newLocality", "value": "Old Town"}]}),
        )
        .await;
    assert_eq!(error_code(&update), "not-found");
    for tool in [GET_APPLICATION_STATUS, PREPARE_REVIEW] {
        let value = fixture
            .call(
                &caller,
                tool,
                json!({"applicationId": application.to_string()}),
            )
            .await;
        assert_eq!(error_code(&value), "not-found", "{tool}");
        assert!(!value.to_string().contains("5 Quay"));
    }
    assert!(fixture.writes().is_empty());
    assert_eq!(
        fixture.registry.applications()[&application].data["newLocality"],
        "Port Selene"
    );
}

#[tokio::test]
async fn an_update_pins_the_target_before_its_edits() {
    let fixture = Fixture::start().await;
    let caller = fixture.caller(CITIZEN_A);
    let started = fixture
        .call(&caller, START_APPLICATION, start_arguments())
        .await;
    let started_id = started["application"]["applicationId"].clone();
    let value = fixture
        .call(
            &caller,
            UPDATE_APPLICATION,
            json!({"applicationId": started_id, "expectedRevision": "1",
                "patch": [{"op": "replace", "path": "/newLocality", "value": "Old Town"}]}),
        )
        .await;
    assert_eq!(value["isError"], false, "{value}");
    assert_eq!(value["application"]["revision"], "2");
    let writes = fixture.writes();
    let patch = writes.last().expect("patch sent");
    assert_eq!(patch.method, http::Method::PATCH);
    assert_eq!(
        patch.body.as_ref().expect("patch body"),
        &json!([
            {"op": "test", "path": "/data/address", "value": ADDRESS_A},
            {"op": "replace", "path": "/data/newLocality", "value": "Old Town"},
        ])
    );
    assert_eq!(
        patch.if_match.as_deref(),
        Some(crate::mock_registry::etag(1).as_str())
    );
}

#[tokio::test]
async fn a_stale_revision_or_a_closed_application_is_not_written() {
    let fixture = Fixture::start().await;
    let caller = fixture.caller(CITIZEN_A);
    let draft = fixture.registry.add_application(
        json!({"address": ADDRESS_A, "newAddressLine": "5 Quay", "newLocality": "Port Selene", "newPostalCode": "PS-500"}),
        draft_request(),
    );
    let stale = fixture
        .call(
            &caller,
            UPDATE_APPLICATION,
            json!({"applicationId": draft.to_string(), "expectedRevision": "7",
                "patch": [{"op": "replace", "path": "/newLocality", "value": "Old Town"}]}),
        )
        .await;
    assert_eq!(error_code(&stale), "stale-application");
    let submitted = fixture.registry.add_application(
        json!({"address": ADDRESS_A, "newAddressLine": "5 Quay", "newLocality": "Port Selene", "newPostalCode": "PS-500"}),
        json!({"bregState": "submitted", "editable": false, "proposalVersion": 1,
            "effectDigest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}),
    );
    let closed = fixture
        .call(
            &caller,
            UPDATE_APPLICATION,
            json!({"applicationId": submitted.to_string(), "expectedRevision": "1",
                "patch": [{"op": "replace", "path": "/newLocality", "value": "Old Town"}]}),
        )
        .await;
    assert_eq!(error_code(&closed), "application-not-editable");
    assert!(fixture.writes().is_empty());
}

#[tokio::test]
async fn registry_problems_map_to_stable_codes_with_a_trace() {
    let fixture = Fixture::start().await;
    let caller = fixture.caller(CITIZEN_A);
    let draft = fixture.registry.add_application(
        json!({"address": ADDRESS_A, "newAddressLine": "5 Quay", "newLocality": "Port Selene", "newPostalCode": "PS-500"}),
        draft_request(),
    );
    let update = || {
        fixture.call(
            &caller,
            UPDATE_APPLICATION,
            json!({"applicationId": draft.to_string(), "expectedRevision": "1",
                "patch": [{"op": "replace", "path": "/newLocality", "value": "Old Town"}]}),
        )
    };
    fixture
        .registry
        .fail_next(http::Method::PATCH, BRegProblemCode::IdempotencyConflict);
    let conflict = update().await;
    assert_eq!(error_code(&conflict), "idempotency-conflict");
    assert!(conflict["error"]["traceId"].is_string());
    fixture
        .registry
        .fail_next(http::Method::PATCH, BRegProblemCode::PreconditionFailed);
    let stale = update().await;
    assert_eq!(error_code(&stale), "stale-application");
}

#[tokio::test]
async fn a_start_steps_past_a_key_the_registry_will_not_replay() {
    let (audit, capture) = ToolAuditLog::capture();
    let fixture = Fixture::start_with_audit(Some(audit)).await;
    let caller = fixture.caller(CITIZEN_A);
    fixture
        .registry
        .fail_next(http::Method::POST, BRegProblemCode::IdempotencyConflict);
    let started = fixture
        .call(&caller, START_APPLICATION, start_arguments())
        .await;
    let application = started_identifier(&started);
    assert_eq!(response_record(&capture)["outcome"], "ok");
    let keys: Vec<String> = fixture
        .writes()
        .into_iter()
        .map(|seen| seen.idempotency_key.expect("key"))
        .collect();
    assert_eq!(keys.len(), 2);
    assert_ne!(keys[0], keys[1]);
    assert_eq!(fixture.registry.applications().len(), 1);
    assert!(fixture.registry.applications().contains_key(&application));
}

/// Past its receipt horizon a key stays spent but is no longer replayed, so
/// an identical start steps past it and opens a new draft one position on,
/// and a retry walks the same chain to that draft.
#[tokio::test]
async fn a_start_steps_past_a_key_whose_receipt_expired() {
    let (audit, capture) = ToolAuditLog::capture();
    let fixture = Fixture::start_with_audit(Some(audit)).await;
    let caller = fixture.caller(CITIZEN_A);
    let start = || fixture.call(&caller, START_APPLICATION, start_arguments());
    let first = started_identifier(&start().await);

    fixture.registry.expire_receipts();
    let second = start().await;
    assert_eq!(second["application"]["status"], "prepared");
    let second = started_identifier(&second);
    assert_ne!(second, first);
    let entries = capture.entries();
    let last = entries.last().expect("audited");
    assert_eq!(last["phase"], "response");
    assert_eq!(last["record"]["outcome"], "ok");
    let keys: Vec<String> = fixture
        .writes()
        .into_iter()
        .map(|seen| seen.idempotency_key.expect("key"))
        .collect();
    assert_eq!(keys.len(), 3);
    assert_eq!(keys[1], keys[0]);
    assert_ne!(keys[2], keys[0]);

    assert_eq!(started_identifier(&start().await), second);
    assert_eq!(fixture.registry.applications().len(), 2);
}

#[tokio::test]
async fn a_retried_start_reuses_its_idempotency_key() {
    let fixture = Fixture::start().await;
    let caller = fixture.caller(CITIZEN_A);
    fixture
        .call(&caller, START_APPLICATION, start_arguments())
        .await;
    fixture
        .call(&caller, START_APPLICATION, start_arguments())
        .await;
    let other = fixture.caller(CITIZEN_B);
    fixture
        .call(&other, START_APPLICATION, start_arguments())
        .await;
    let keys: Vec<String> = fixture
        .writes()
        .into_iter()
        .map(|seen| seen.idempotency_key.expect("key"))
        .collect();
    assert_eq!(keys.len(), 3);
    assert_eq!(keys[0], keys[1]);
    assert_ne!(keys[0], keys[2]);
}

fn started_identifier(value: &Value) -> Uuid {
    assert_eq!(value["isError"], false, "{value}");
    Uuid::parse_str(
        value["application"]["applicationId"]
            .as_str()
            .expect("identifier"),
    )
    .expect("identifier is a UUID")
}

#[tokio::test]
async fn a_start_after_a_closed_application_opens_a_new_one() {
    for closed in ["cancelled", "applied"] {
        let fixture = Fixture::start().await;
        let caller = fixture.caller(CITIZEN_A);
        let start = || fixture.call(&caller, START_APPLICATION, start_arguments());
        let first = started_identifier(&start().await);
        assert_eq!(started_identifier(&start().await), first, "{closed}");
        assert_eq!(fixture.registry.applications().len(), 1, "{closed}");

        fixture.registry.set_request(
            first,
            json!({"bregState": closed, "editable": false, "proposalVersion": 1}),
        );
        let second = start().await;
        assert_eq!(second["application"]["status"], "prepared", "{closed}");
        let second = started_identifier(&second);
        assert_ne!(second, first, "{closed}");
        assert_eq!(started_identifier(&start().await), second, "{closed}");
        assert_eq!(fixture.registry.applications().len(), 2, "{closed}");
    }
}

#[tokio::test]
async fn a_submitted_application_whose_review_was_cancelled_stays_open() {
    let fixture = Fixture::start().await;
    let caller = fixture.caller(CITIZEN_A);
    let start = || fixture.call(&caller, START_APPLICATION, start_arguments());
    let first = started_identifier(&start().await);
    let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    fixture.registry.set_request(
        first,
        json!({"bregState": "submitted", "editable": false, "proposalVersion": 1,
        "effectDigest": digest,
        "review": {
            "submission": {"state": "accepted", "authority": "casework",
                "requestId": "8a1f3c52-6d4e-4b7a-9c0d-1e2f3a4b5c6d", "submissionDigest": digest,
                "recoveryDeadline": "2026-09-26T01:00:00Z",
                "policy": {"id": "address-review", "version": "1", "digest": digest}},
            "result": {"state": "cancelled", "resultId": "2b3c4d5e-6f70-4812-9a3b-4c5d6e7f8091",
                "completedAt": "2026-09-19T01:00:00Z", "availableUntil": "2026-10-19T01:00:00Z"},
            "delivery": {"state": "received", "eventId": "3c4d5e6f-7081-4923-8b4c-5d6e7f8091a2",
                "receivedAt": "2026-09-19T01:00:01Z"},
            "application": {"mode": "manual", "state": "blocked"},
            "recovery": {"state": "none"},
        }}),
    );

    let status = fixture
        .call(
            &caller,
            GET_APPLICATION_STATUS,
            json!({"applicationId": first.to_string()}),
        )
        .await;
    assert_eq!(status["application"]["status"], "under_review", "{status}");

    // Still open, so an identical start returns it rather than a second draft.
    let retried = start().await;
    assert_eq!(started_identifier(&retried), first, "{retried}");
    assert_eq!(retried["application"]["status"], "under_review");
    assert_eq!(fixture.registry.applications().len(), 1);
}

#[tokio::test]
async fn a_retried_start_answers_with_the_drafts_current_state() {
    let fixture = Fixture::start().await;
    let caller = fixture.caller(CITIZEN_A);
    let first = started_identifier(
        &fixture
            .call(&caller, START_APPLICATION, start_arguments())
            .await,
    );
    fixture.registry.set_request(
        first,
        json!({"bregState": "submitted", "editable": false, "proposalVersion": 1,
            "effectDigest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}),
    );
    let retried = fixture
        .call(&caller, START_APPLICATION, start_arguments())
        .await;
    assert_eq!(started_identifier(&retried), first);
    assert_eq!(retried["application"]["status"], "submitted");
    assert_eq!(fixture.registry.applications().len(), 1);
}

#[tokio::test]
async fn a_start_past_too_many_closed_applications_is_refused() {
    let fixture = Fixture::start().await;
    let caller = fixture.caller(CITIZEN_A);
    let cancelled = json!({"bregState": "cancelled", "editable": false, "proposalVersion": 1});
    for _ in 0..=MAX_CLOSED_REPEATS {
        let started = fixture
            .call(&caller, START_APPLICATION, start_arguments())
            .await;
        fixture
            .registry
            .set_request(started_identifier(&started), cancelled.clone());
    }
    let refused = fixture
        .call(&caller, START_APPLICATION, start_arguments())
        .await;
    assert_eq!(error_code(&refused), "not-permitted");
    assert_eq!(
        fixture.registry.applications().len(),
        usize::try_from(MAX_CLOSED_REPEATS + 1).expect("bound fits")
    );
}

#[tokio::test]
async fn a_start_after_a_package_activation_opens_a_new_one() {
    for closed in [true, false] {
        let (audit, capture) = ToolAuditLog::capture();
        let fixture = Fixture::start_with_audit(Some(audit)).await;
        let caller = fixture.caller(CITIZEN_A);
        let start = || fixture.call(&caller, START_APPLICATION, start_arguments());
        let first = started_identifier(&start().await);
        if closed {
            fixture.registry.set_request(
                first,
                json!({"bregState": "cancelled", "editable": false, "proposalVersion": 1}),
            );
        }

        fixture.registry.activate_package();
        let second = start().await;
        assert_eq!(second["application"]["status"], "prepared", "{closed}");
        let second = started_identifier(&second);
        assert_ne!(second, first, "{closed}");
        let entries = capture.entries();
        let last = entries.last().expect("audited");
        assert_eq!(last["phase"], "response", "{closed}");
        assert_eq!(last["record"]["outcome"], "ok", "{closed}");

        // A retry under the same revision lands on the same draft.
        assert_eq!(started_identifier(&start().await), second, "{closed}");
        assert_eq!(fixture.registry.applications().len(), 2, "{closed}");
    }
}

#[tokio::test]
async fn prepare_review_links_the_citizens_own_application() {
    let fixture = Fixture::start().await;
    let caller = fixture.caller(CITIZEN_A);
    let started = fixture
        .call(&caller, START_APPLICATION, start_arguments())
        .await;
    let application = started["application"]["applicationId"]
        .as_str()
        .expect("identifier")
        .to_owned();
    let value = fixture
        .call(
            &caller,
            PREPARE_REVIEW,
            json!({"applicationId": application.to_string()}),
        )
        .await;
    assert_eq!(value["isError"], false, "{value}");
    assert_eq!(
        value["reviewUrl"],
        format!("https://review.example.test/requests/{application}")
    );
    let status = fixture
        .call(
            &caller,
            GET_APPLICATION_STATUS,
            json!({"applicationId": application.to_string()}),
        )
        .await;
    assert_eq!(status["application"]["status"], "prepared", "{status}");
    assert_eq!(status["notice"], REGISTRY_DATA_NOTICE);
}

#[tokio::test]
async fn the_registry_sees_the_delegated_token_never_the_chat_hosts() {
    let fixture = Fixture::start().await;
    let caller = fixture.caller(CITIZEN_A);
    let value = fixture
        .call(&caller, START_APPLICATION, start_arguments())
        .await;
    assert!(!value.to_string().contains(caller.token()));
    let seen = fixture.registry.seen();
    assert!(!seen.is_empty());
    for request in seen {
        let authorization = request.authorization.expect("authorization sent");
        assert!(!authorization.contains(caller.token()));
        let claims = claims(&authorization);
        assert_eq!(claims["sub"], CITIZEN_A);
        assert_eq!(claims["aud"], AUDIENCE);
        assert_eq!(claims["act"]["sub"], ACTOR);
    }
}

#[tokio::test]
async fn every_call_is_audited_without_values_or_credentials() {
    let fixture = Fixture::start().await;
    let caller = fixture.caller(CITIZEN_A);
    let mut arguments = start_arguments();
    arguments["newAddressLine"] = json!(CANARY);
    fixture.call(&caller, START_APPLICATION, arguments).await;
    let mut smuggled = start_arguments();
    smuggled["address"] = json!(ADDRESS_B);
    fixture.call(&caller, START_APPLICATION, smuggled).await;
    let text = fixture.audit_text();
    let entries: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit line"))
        .collect();
    let summary: Vec<(&str, &str, Option<&str>)> = entries
        .iter()
        .map(|entry| {
            (
                entry["record"]["tool"].as_str().expect("tool"),
                entry["phase"].as_str().expect("phase"),
                entry["record"]["outcome"].as_str(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (START_APPLICATION, "request", None),
            (START_APPLICATION, "response", Some("ok")),
            (START_APPLICATION, "request", None),
            (START_APPLICATION, "response", Some("refused")),
        ]
    );
    assert!(entries[1]["record"].get("reason").is_none());
    assert_eq!(entries[3]["record"]["reason"], "invalid-arguments");
    assert_eq!(
        entries[0]["record"]["principalPseudonym"],
        caller.citizen_pseudonym()
    );
    assert_eq!(
        entries[0]["record"]["clientPseudonym"],
        caller.client_pseudonym()
    );
    assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
    assert_eq!(entries[2]["correlation"], entries[3]["correlation"]);
    assert_ne!(entries[0]["correlation"], entries[2]["correlation"]);
    for forbidden in [CANARY, CITIZEN_A, ADDRESS_A, ADDRESS_B, caller.token()] {
        assert!(!text.contains(forbidden), "audit carries a forbidden value");
    }
}

#[tokio::test]
async fn concurrent_calls_keep_distinct_request_response_correlations() {
    let fixture = Fixture::start().await;
    let caller_a = fixture.caller(CITIZEN_A);
    let caller_b = fixture.caller(CITIZEN_B);
    let (first, second) = tokio::join!(
        fixture.call(&caller_a, DESCRIBE_SERVICE, json!({})),
        fixture.call(&caller_b, DESCRIBE_SERVICE, json!({}))
    );
    assert_eq!(first["isError"], false, "{first}");
    assert_eq!(second["isError"], false, "{second}");

    let text = fixture.audit_text();
    let entries: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit line"))
        .collect();
    assert_eq!(entries.len(), 4);
    let mut by_correlation = std::collections::BTreeMap::<String, Vec<&str>>::new();
    for entry in &entries {
        by_correlation
            .entry(
                entry["correlation"]
                    .as_str()
                    .expect("correlation")
                    .to_owned(),
            )
            .or_default()
            .push(entry["phase"].as_str().expect("phase"));
    }
    assert_eq!(by_correlation.len(), 2);
    for phases in by_correlation.values() {
        assert_eq!(phases, &["request", "response"]);
    }
}

#[test]
fn request_state_maps_to_one_citizen_status() {
    use registry_breg_client::{
        BRegExternalReviewResultState as Result, BRegExternalReviewSubmissionState as Submission,
        BRegRequestState as State,
    };
    let cases = [
        (State::Draft, None, "prepared"),
        (State::Submitted, None, "submitted"),
        (
            State::Submitted,
            Some((Submission::Pending, Result::Pending)),
            "submitted",
        ),
        (
            State::Submitted,
            Some((Submission::Accepted, Result::Pending)),
            "under_review",
        ),
        (
            State::Submitted,
            Some((Submission::Accepted, Result::ChangesRequested)),
            "under_review",
        ),
        (
            State::Submitted,
            Some((Submission::Accepted, Result::Approved)),
            "approved",
        ),
        (
            State::Submitted,
            Some((Submission::Accepted, Result::Rejected)),
            "rejected",
        ),
        // A cancelled review leaves the request submitted: BReg still
        // offers revise, rebase, and cancel on it, so it is not closed.
        (
            State::Submitted,
            Some((Submission::Accepted, Result::Cancelled)),
            "under_review",
        ),
        (State::Cancelled, None, "cancelled"),
        (State::Applied, None, "applied"),
    ];
    for (state, review, expected) in cases {
        assert_eq!(
            ApplicationStatus::from_states(state, review).as_str(),
            expected,
            "{state:?} {review:?}"
        );
    }
}

fn response_record(capture: &AuditCapture) -> Value {
    let entries = capture.entries();
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert_eq!(entries[1]["phase"], "response");
    entries[1]["record"].clone()
}

#[tokio::test]
async fn a_failed_readback_after_a_committed_start_is_unfinished() {
    for code in [
        BRegProblemCode::ResourceNotFound,
        BRegProblemCode::AuthenticationRefused,
        BRegProblemCode::ServiceUnavailable,
    ] {
        let (audit, capture) = ToolAuditLog::capture();
        let fixture = Fixture::start_with_audit(Some(audit)).await;
        let caller = fixture.caller(CITIZEN_A);
        fixture.registry.fail_next_at(
            http::Method::GET,
            "/v1/records/address-correction-requests/",
            code,
        );
        let value = fixture
            .call(&caller, START_APPLICATION, start_arguments())
            .await;
        assert_eq!(error_code(&value), "registry-unavailable", "{code:?}");
        let record = response_record(&capture);
        assert_eq!(record["outcome"], "unfinished", "{code:?}");
        assert_eq!(record["reason"], "registry-unavailable", "{code:?}");
        assert_eq!(fixture.registry.applications().len(), 1, "{code:?}");

        // A retry replays the same key and lands on the same draft.
        let retried = fixture
            .call(&caller, START_APPLICATION, start_arguments())
            .await;
        assert_eq!(retried["isError"], false, "{retried}");
        assert_eq!(fixture.registry.applications().len(), 1, "{code:?}");
    }
}

#[tokio::test]
async fn a_token_exchange_failure_on_a_read_tool_is_refused() {
    let (audit, capture) = ToolAuditLog::capture();
    let fixture = Fixture::start_with_audit(Some(audit)).await;
    let caller = fixture.caller(CITIZEN_A);
    fixture.server.stop().await;
    let arguments = Map::new();
    let result = fixture
        .gateway
        .call(&caller, GET_MY_DETAILS, Some(&arguments))
        .await;
    assert_eq!(result.is_error, Some(true));
    let record = response_record(&capture);
    assert_eq!(record["outcome"], "refused");
    assert_eq!(record["reason"], "registry-unavailable");
    assert!(fixture.registry.seen().is_empty());
}

#[tokio::test]
async fn a_registry_failure_on_a_read_tool_is_refused() {
    let (audit, capture) = ToolAuditLog::capture();
    let fixture = Fixture::start_with_audit(Some(audit)).await;
    let caller = fixture.caller(CITIZEN_A);
    fixture.registry.fail_next_at(
        http::Method::GET,
        "/v1/records/",
        BRegProblemCode::ServiceUnavailable,
    );
    let value = fixture.call(&caller, GET_MY_DETAILS, json!({})).await;
    assert_eq!(error_code(&value), "registry-unavailable");
    let record = response_record(&capture);
    assert_eq!(record["outcome"], "refused");
    assert_eq!(record["reason"], "registry-unavailable");
}

#[tokio::test]
async fn a_registry_failure_on_the_update_patch_is_unfinished() {
    let (audit, capture) = ToolAuditLog::capture();
    let fixture = Fixture::start_with_audit(Some(audit)).await;
    let caller = fixture.caller(CITIZEN_A);
    let draft = fixture.registry.add_application(
        json!({"address": ADDRESS_A, "newAddressLine": "5 Quay", "newLocality": "Port Selene", "newPostalCode": "PS-500"}),
        draft_request(),
    );
    fixture
        .registry
        .fail_next(http::Method::PATCH, BRegProblemCode::ServiceUnavailable);
    let value = fixture
        .call(
            &caller,
            UPDATE_APPLICATION,
            json!({"applicationId": draft.to_string(), "expectedRevision": "1",
                "patch": [{"op": "replace", "path": "/newLocality", "value": "Old Town"}]}),
        )
        .await;
    assert_eq!(error_code(&value), "registry-unavailable");
    let record = response_record(&capture);
    assert_eq!(record["outcome"], "unfinished");
    assert_eq!(record["reason"], "registry-unavailable");
}

#[tokio::test]
async fn a_definite_refusal_of_the_update_patch_is_refused() {
    let (audit, capture) = ToolAuditLog::capture();
    let fixture = Fixture::start_with_audit(Some(audit)).await;
    let caller = fixture.caller(CITIZEN_A);
    let draft = fixture.registry.add_application(
        json!({"address": ADDRESS_A, "newAddressLine": "5 Quay", "newLocality": "Port Selene", "newPostalCode": "PS-500"}),
        draft_request(),
    );
    fixture
        .registry
        .fail_next(http::Method::PATCH, BRegProblemCode::PreconditionFailed);
    let value = fixture
        .call(
            &caller,
            UPDATE_APPLICATION,
            json!({"applicationId": draft.to_string(), "expectedRevision": "1",
                "patch": [{"op": "replace", "path": "/newLocality", "value": "Old Town"}]}),
        )
        .await;
    assert_eq!(error_code(&value), "stale-application");
    let record = response_record(&capture);
    assert_eq!(record["outcome"], "refused");
    assert_eq!(record["reason"], "stale-application");
}
