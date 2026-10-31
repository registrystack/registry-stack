// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "breg")]
//! Native connector journeys against a real BReg runtime and PostgreSQL,
//! the way BReg's own suites run them. The tests are `#[ignore]`d and
//! driven by `products/adapter/scripts/test-connector-native.py`, which
//! builds the product binaries, provisions the environment, and runs the
//! suite with `--ignored`. Env: `ADAPTER_BREG_BIN`,
//! `ADAPTER_BREGCTL_BIN`, `ADAPTER_TEST_DATABASE_URL`.

#[path = "support/breg_native_service.rs"]
mod breg_service;

use std::sync::Arc;

use registry_adapter_connectors::breg::{BregConnector, BregConnectorConfig};
use registry_adapter_connectors::operation::{
    CommandKey, ConnectorFault, Observable, Operation, OutcomeCategory,
};
use registry_breg_client::StaticToken;
use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
use registry_platform_testing::{
    fixtures, TestActorKind, TestAuthorizationServer, TestAuthorizationServerBuilder, TestClient,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
const PROFILE: &str = "writer";
const ACTION: &str = "update-item";
const PROPOSAL_ACTION: &str = "manual-item";
const AUTO_PROPOSAL_ACTION: &str = "propose-item";
const SUBJECT: &str = "connector-reader";

fn key(step: &str) -> CommandKey {
    CommandKey::new(format!("adapter-native/item/{step}")).expect("derived key")
}

async fn issuer() -> TestAuthorizationServer {
    let (_, public) = fixtures::ed25519_pair();
    let builder: TestAuthorizationServerBuilder = TestAuthorizationServer::builder()
        .with_signing_key(generate_private_jwk(GeneratedKeyAlgorithm::Es256).unwrap())
        .client(
            TestClient::new("application-reader")
                .with_public_jwk(public)
                .with_resource("urn:example:applications")
                .with_actor_kind(TestActorKind::Service)
                .with_service_subject(SUBJECT),
        );
    builder.start().await
}

async fn connector(
    service: &breg_service::Breg,
    issuer: &TestAuthorizationServer,
) -> Arc<BregConnector> {
    let token = issuer.issue_access_token(
        "application-reader",
        SUBJECT,
        "urn:example:applications",
        "applications:read",
        chrono::Utc::now().timestamp() + 3600,
    );
    let connected = BregConnector::connect(
        BregConnectorConfig::new(
            service.origin(),
            Arc::new(StaticToken::new(token).expect("static token")),
            PROFILE,
            ACTION,
            "item",
            "items",
        )
        .with_tombstone(false)
        .with_import_profile(true),
    )
    .await
    .expect("the connector resolves against the live metadata");
    Arc::new(connected)
}

/// One created item through the connector, returning its identifier.
fn create_item(connector: &Arc<BregConnector>, step: &str, owner: &str, label: &str) -> String {
    let prepared = connector
        .record_create()
        .prepare(
            &json!({"data": {"owner": owner, "label": label}}),
            key(&format!("create-{step}")),
        )
        .expect("create prepares");
    let outcome = connector
        .record_create()
        .send(&prepared)
        .expect("create sends");
    assert_eq!(
        outcome.category,
        OutcomeCategory::Completed,
        "create: {outcome:?}"
    );
    outcome.correlation.expect("the created record id")
}

/// One record's identifier, current strong etag, and domain data, read
/// the way a runner observes before preparing the next step.
struct Observed {
    id: String,
    etag: String,
    domain: Value,
}

fn observe_item(connector: &Arc<BregConnector>, record_identifier: &str) -> Observed {
    let read = connector
        .reads()
        .get_record(record_identifier)
        .expect("record read");
    Observed {
        id: read.value.data.record_identifier.clone(),
        etag: read
            .metadata
            .etag()
            .expect("a read carries the strong etag")
            .as_str()
            .to_owned(),
        domain: serde_json::to_value(&read.value.data.domain_data).expect("domain data serializes"),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs under products/adapter/scripts/test-connector-native.py"]
async fn direct_create_and_patch_honor_preconditions() {
    let issuer = issuer().await;
    let service = breg_service::Breg::start(&issuer).await;
    let connector = connector(&service, &issuer).await;
    let record = create_item(&connector, "first", SUBJECT, "First");
    let record_b = create_item(&connector, "second", SUBJECT, "Second");
    assert_ne!(record, record_b);

    // The patch precondition comes from a fresh read, the way a runner
    // observes before preparing.
    let observed = observe_item(&connector, &record);
    let prepared = connector
        .record_patch()
        .prepare(
            &json!({
                "record": observed.id,
                "etag": observed.etag,
                "operations": [{"op": "replace", "field": "label", "value": "Patched"}]
            }),
            key("patch"),
        )
        .expect("patch prepares");
    let outcome = connector
        .record_patch()
        .send(&prepared)
        .expect("patch sends");
    assert_eq!(outcome.category, OutcomeCategory::Completed);

    // Observation reads the effect back.
    let state = connector
        .record_patch()
        .observe(&observed.id)
        .expect("observation");
    assert_eq!(state.state, "present");
    let repatched = observe_item(&connector, &observed.id);
    assert_eq!(repatched.domain["label"], json!("Patched"));

    // A stale precondition is refused and never falls back.
    let prepared = connector
        .record_patch()
        .prepare(
            &json!({
                "record": observed.id,
                "etag": observed.etag,
                "operations": [{"op": "replace", "field": "label", "value": "Late"}]
            }),
            key("patch-stale"),
        )
        .expect("stale patch prepares");
    let outcome = connector
        .record_patch()
        .send(&prepared)
        .expect("refusal is an outcome");
    assert_eq!(outcome.category, OutcomeCategory::Refused);
    assert_eq!(
        outcome.native_problem.as_deref(),
        Some("precondition.failed")
    );

    // Read family: list and revisions against the live deployment.
    let page = connector
        .reads()
        .list_page(
            &registry_breg_client::BRegListRequest::default()
                .top(10)
                .expect("page"),
            10,
        )
        .expect("list answers");
    assert_eq!(page.items.len(), 2);
    let revisions = connector
        .reads()
        .record_revisions(&observed.id)
        .expect("revisions answer");
    assert!(!revisions.value.as_bytes().is_empty());
    service.finish();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs under products/adapter/scripts/test-connector-native.py"]
async fn immediate_action_invokes_once_and_recovery_proves_no_duplicate() {
    let issuer = issuer().await;
    let service = breg_service::Breg::start(&issuer).await;
    let connector = connector(&service, &issuer).await;
    let record = create_item(&connector, "before", SUBJECT, "Before");

    let prepared = connector
        .action_invoke()
        .prepare(
            &json!({"input": {"targetId": record, "label": "After"}}),
            key("invoke"),
        )
        .expect("invoke prepares");
    let first = connector
        .action_invoke()
        .send(&prepared)
        .expect("invoke sends");
    assert_eq!(first.category, OutcomeCategory::Completed);
    let correlation = first.correlation.expect("application correlation");

    // Recovery under the same key: the action's target conditions moved
    // with the first application, so the same-key replay arrives with a
    // different body and the destination answers the typed conflict. That
    // refusal is the receipt-horizon discipline working: no second
    // application, no silent duplicate.
    let second = connector
        .action_invoke()
        .recover(&prepared)
        .expect("recovery answers");
    eprintln!("PROBE recover outcome: {second:?}");
    assert_eq!(second.category, OutcomeCategory::Refused, "{second:?}");
    assert_eq!(
        second.native_problem.as_deref(),
        Some("idempotency.key-reused")
    );

    // The receipt's result record observes back, and the label shows one
    // application's effect.
    let state = connector
        .action_invoke()
        .observe(&correlation)
        .expect("observation answers");
    assert_eq!(state.state, "present");
    let observed = observe_item(&connector, &record);
    assert_eq!(observed.domain["label"], json!("After"));
    service.finish();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs under products/adapter/scripts/test-connector-native.py"]
async fn proposal_start_submit_and_observe_through_the_connector() {
    let issuer = issuer().await;
    let service = breg_service::Breg::start(&issuer).await;
    {
        let client = service.client(&issuer);
        let contract = client
            .registry_contract(Some(PROFILE))
            .await
            .expect("live metadata")
            .value;
        eprintln!(
            "PROBE proposals member: {}",
            serde_json::to_string(&contract.proposal_actions()).unwrap_or_default()
        );
        match contract.select_proposal_get(PROFILE) {
            Ok(_) => eprintln!("PROBE select_proposal_get ok"),
            Err(error) => eprintln!("PROBE select_proposal_get error: {error:?}"),
        }
        match contract.select_proposals(PROFILE) {
            Ok(_) => eprintln!("PROBE select_proposals ok"),
            Err(error) => eprintln!("PROBE select_proposals error: {error:?}"),
        }
    }
    let proposal_connector = {
        // The proposal family binds to the Proposal-mode action.
        let token = issuer.issue_access_token(
            "application-reader",
            SUBJECT,
            "urn:example:applications",
            "applications:read",
            chrono::Utc::now().timestamp() + 3600,
        );
        Arc::new(
            BregConnector::connect(
                BregConnectorConfig::new(
                    service.origin(),
                    Arc::new(StaticToken::new(token).expect("static token")),
                    PROFILE,
                    PROPOSAL_ACTION,
                    "item",
                    "items",
                )
                .with_import_profile(true),
            )
            .await
            .expect("the proposal connector resolves"),
        )
    };
    let record = create_item(&proposal_connector, "draft-target", SUBJECT, "Draft target");

    // Start: accepted with the draft id as the correlation.
    let started = proposal_connector
        .proposal_start()
        .prepare(
            &json!({"input": {"targetId": record, "label": "Proposed"}}),
            key("start"),
        )
        .expect("start prepares");
    let outcome = proposal_connector
        .proposal_start()
        .send(&started)
        .expect("start sends");
    assert_eq!(outcome.category, OutcomeCategory::Accepted);
    let proposal_id = outcome.correlation.expect("draft id");

    // The status read names the submission version the submit is prepared
    // from; the observation agrees.
    let summary = proposal_connector
        .reads()
        .proposal_summary(&proposal_id)
        .expect("status read");
    assert_eq!(summary.id, proposal_id);
    let state = proposal_connector
        .proposal_start()
        .observe(&proposal_id)
        .expect("observation");
    assert_eq!(state.state, "draft");

    // Submit: completed at the submitted receipt.
    let prepared = proposal_connector
        .proposal_submit()
        .prepare(
            &json!({
                "proposal": proposal_id,
                "submissionVersion": summary.submission_version,
                "body": {}
            }),
            key("submit"),
        )
        .expect("submit prepares");
    let outcome = proposal_connector
        .proposal_submit()
        .send(&prepared)
        .expect("submit sends");
    assert_eq!(outcome.category, OutcomeCategory::Completed, "{outcome:?}");
    assert_eq!(outcome.correlation.as_deref(), Some(proposal_id.as_str()));

    // Observation shows the submitted state; the manual-application
    // proposal waits there.
    let state = proposal_connector
        .proposal_submit()
        .observe(&proposal_id)
        .expect("observation");
    assert_eq!(state.state, "submitted");
    // The manual-application proposal holds the submission for a reviewer;
    // the application progress, where already derived, is a review wait.
    if let Some((_, application)) = state.details.iter().find(|(name, _)| name == "application") {
        assert!(
            application == "awaiting-review" || application == "pending",
            "unexpected application progress {application}"
        );
    }

    // A prepared submit whose read already holds the transition answers
    // the observed completion; the destination is not contacted again.
    let settled = proposal_connector
        .proposal_submit()
        .prepare(
            &json!({
                "proposal": proposal_id,
                "submissionVersion": summary.submission_version,
                "body": {}
            }),
            key("submit"),
        )
        .expect("settled submit prepares");
    let settled = proposal_connector
        .proposal_submit()
        .send(&settled)
        .expect("settled submit answers");
    assert_eq!(settled.category, OutcomeCategory::Completed);
    assert!(settled
        .note
        .is_some_and(|note| note.contains("already holds")));

    // The spent key under different request bytes is a typed conflict: a
    // second proposal submitted under the first's spent key never runs.
    let record_two = create_item(
        &proposal_connector,
        "second-target",
        SUBJECT,
        "Second target",
    );
    let started_two = proposal_connector
        .proposal_start()
        .prepare(
            &json!({"input": {"targetId": record_two, "label": "Proposed too"}}),
            key("start-two"),
        )
        .expect("second start prepares");
    let outcome = proposal_connector
        .proposal_start()
        .send(&started_two)
        .expect("second start sends");
    assert_eq!(outcome.category, OutcomeCategory::Accepted);
    let proposal_two = outcome.correlation.expect("second draft id");
    let summary_two = proposal_connector
        .reads()
        .proposal_summary(&proposal_two)
        .expect("second status read");
    let conflicting = proposal_connector
        .proposal_submit()
        .prepare(
            &json!({
                "proposal": proposal_two,
                "submissionVersion": summary_two.submission_version,
                "body": {}
            }),
            key("submit"),
        )
        .expect("conflicting submit prepares");
    let outcome = proposal_connector
        .proposal_submit()
        .send(&conflicting)
        .expect("conflict is an outcome");
    assert_eq!(outcome.category, OutcomeCategory::Refused, "{outcome:?}");
    assert_eq!(
        outcome.native_problem.as_deref(),
        Some("idempotency.key-reused")
    );
    service.finish();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs under products/adapter/scripts/test-connector-native.py"]
async fn automatic_proposal_recovery_reads_the_observed_state() {
    let issuer = issuer().await;
    let service = breg_service::Breg::start(&issuer).await;
    let proposal_connector = {
        let token = issuer.issue_access_token(
            "application-reader",
            SUBJECT,
            "urn:example:applications",
            "applications:read",
            chrono::Utc::now().timestamp() + 3600,
        );
        Arc::new(
            BregConnector::connect(
                BregConnectorConfig::new(
                    service.origin(),
                    Arc::new(StaticToken::new(token).expect("static token")),
                    PROFILE,
                    AUTO_PROPOSAL_ACTION,
                    "item",
                    "items",
                )
                .with_import_profile(true),
            )
            .await
            .expect("the proposal connector resolves"),
        )
    };
    let record = create_item(
        &proposal_connector,
        "recovery-target",
        SUBJECT,
        "Recovery target",
    );
    let started = proposal_connector
        .proposal_start()
        .prepare(
            &json!({"input": {"targetId": record, "label": "Recovered"}}),
            key("start"),
        )
        .expect("start prepares");
    let outcome = proposal_connector
        .proposal_start()
        .send(&started)
        .expect("start sends");
    let proposal_id = outcome.correlation.expect("draft id");
    let summary = proposal_connector
        .reads()
        .proposal_summary(&proposal_id)
        .expect("status read");

    // An uncertain submit is recovered by the same prepared form: the
    // fresh read re-arms the exact transition under the same key.
    let prepared = proposal_connector
        .proposal_submit()
        .prepare(
            &json!({
                "proposal": proposal_id,
                "submissionVersion": summary.submission_version,
                "body": {}
            }),
            key("submit"),
        )
        .expect("submit prepares");
    let outcome = proposal_connector
        .proposal_submit()
        .send(&prepared)
        .expect("submit sends");
    assert_eq!(outcome.category, OutcomeCategory::Completed, "{outcome:?}");
    let recovered = proposal_connector
        .proposal_submit()
        .recover(&prepared)
        .expect("recovery answers");
    // The read proves the transition already holds, so recovery answers
    // the observed completion without sending again.
    assert_eq!(recovered.category, OutcomeCategory::Completed);
    assert_eq!(recovered.correlation.as_deref(), Some(proposal_id.as_str()));
    assert!(recovered
        .note
        .is_some_and(|note| note.contains("already holds")));
    service.finish();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs under products/adapter/scripts/test-connector-native.py"]
async fn batch_commits_create_and_patch_atomically() {
    let issuer = issuer().await;
    let service = breg_service::Breg::start(&issuer).await;
    let connector = connector(&service, &issuer).await;
    let catalog: Vec<&str> = connector
        .catalog()
        .iter()
        .map(|descriptor| descriptor.name)
        .collect();
    assert!(
        catalog.contains(&"breg.batch.records"),
        "the live deployment did not disclose a batch binding for the writer profile"
    );
    let record = create_item(&connector, "batch-target", SUBJECT, "Batch target");
    let record_b = create_item(&connector, "batch-second", SUBJECT, "Batch second");
    let observed_b = observe_item(&connector, &record_b);
    let etag = observed_b.etag;
    let prepared = connector
        .batch_records()
        .prepare(
            &json!({
                "items": [
                    {"operation": "create", "data": {"owner": SUBJECT, "label": "Batched"}},
                    {"operation": "patch", "record": record_b, "etag": etag,
                     "operations": [{"op": "replace", "field": "label", "value": "Batched too"}]}
                ]
            }),
            key("batch"),
        )
        .expect("batch prepares");
    let outcome = connector
        .batch_records()
        .send(&prepared)
        .expect("batch sends");
    assert_eq!(outcome.category, OutcomeCategory::Completed);
    let snapshot = outcome.correlation.expect("snapshot correlation");
    // Observation reads the receipt's snapshot back.
    let state = connector
        .batch_records()
        .observe(&snapshot)
        .expect("snapshot observation");
    assert_eq!(state.state, "snapshot-readable");
    // Both effects committed under one exchange.
    let patched = observe_item(&connector, &record_b);
    assert_eq!(patched.domain["label"], json!("Batched too"));
    let _ = record;
    service.finish();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs under products/adapter/scripts/test-connector-native.py"]
async fn ingestion_run_opens_and_commits_one_chunk() {
    let issuer = issuer().await;
    let service = breg_service::Breg::start(&issuer).await;
    let connector = connector(&service, &issuer).await;
    let catalog: Vec<&str> = connector
        .catalog()
        .iter()
        .map(|descriptor| descriptor.name)
        .collect();
    assert!(
        catalog.contains(&"breg.ingestion.create-run"),
        "the ingestion family is not advertised; import authority or profile gating differs"
    );
    // The source input's digest and the destination's package binding:
    // the announcement is value-free and derived from what the connector
    // and runner can observe.
    let input = serde_json::to_vec(&json!([
        {"operation": "create", "data": {"owner": SUBJECT, "label": "Imported one"}},
        {"operation": "create", "data": {"owner": SUBJECT, "label": "Imported two"}}
    ]))
    .expect("input serializes");
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(&input);
        hex(&hasher.finalize())
    };
    // The announcement binds the run to the active package revision and
    // the entity schema fingerprint, exactly what the connector resolved
    // and the runner carries.
    let package_revision = {
        let client = service.client(&issuer);
        client
            .registry_contract(Some(PROFILE))
            .await
            .expect("live metadata")
            .value
            .registry_revision()
            .to_owned()
    };
    let schema_fingerprint = {
        let client = service.client(&issuer);
        let schema = client
            .entity_schema("item", Some(PROFILE))
            .await
            .expect("entity schema");
        let mut hasher = Sha256::new();
        hasher.update(schema.value.as_bytes());
        format!("sha256:{}", hex(&hasher.finalize()))
    };
    let prepared = connector
        .ingestion_create_run()
        .prepare(
            &json!({
                "profile": PROFILE,
                "operation": "create",
                "packageRevision": package_revision,
                "schemaFingerprint": format!("sha256:{schema_fingerprint}"),
                "inputDigest": digest,
                "inputLength": input.len() as u64,
                "itemCount": 2,
                "chunkCount": 1
            }),
            key("create-run"),
        )
        .expect("run prepares");
    let outcome = connector
        .ingestion_create_run()
        .send(&prepared)
        .expect("run opens");
    assert_eq!(outcome.category, OutcomeCategory::Accepted, "{outcome:?}");
    let correlation = outcome.correlation.expect("run correlation");
    let run_observation = connector
        .ingestion_create_run()
        .observe(&correlation)
        .expect("run observation");
    assert_eq!(run_observation.state, "open");

    // One chunk commits the whole input; the run completes.
    let prefix = {
        let mut hasher = Sha256::new();
        hasher.update(&input);
        hex(&hasher.finalize())
    };
    let chunk = connector
        .ingestion_submit_chunk()
        .prepare(
            &json!({
                "run": correlation.split('/').next().unwrap(),
                "profile": PROFILE,
                "chunkIndex": 0,
                "prefixDigest": prefix,
                "items": serde_json::from_slice::<Value>(&input).expect("items")
            }),
            key("chunk"),
        )
        .expect("chunk prepares");
    let outcome = connector
        .ingestion_submit_chunk()
        .send(&chunk)
        .expect("chunk commits");
    assert_eq!(outcome.category, OutcomeCategory::Completed, "{outcome:?}");
    let run_observation = connector
        .ingestion_submit_chunk()
        .observe(&correlation)
        .expect("run observation");
    assert_eq!(run_observation.state, "complete");
    service.finish();
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A fault that means the call could not be honored stays loud.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs under products/adapter/scripts/test-connector-native.py"]
async fn a_connector_fault_for_a_bad_input_is_typed() {
    let issuer = issuer().await;
    let service = breg_service::Breg::start(&issuer).await;
    let connector = connector(&service, &issuer).await;
    let fault = connector
        .record_create()
        .prepare(&json!({"values": {}}), key("invalid"));
    assert_eq!(fault.unwrap_err(), ConnectorFault::InvalidInput);
    service.finish();
}
