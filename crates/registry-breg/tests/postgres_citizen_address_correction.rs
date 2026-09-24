// SPDX-License-Identifier: Apache-2.0

//! The citizen address correction acceptance project, run through the
//! authenticated PostgreSQL router from its signed package. A standing citizen
//! agent reads its own address through a steward-provisioned self-service link
//! and drafts a correction; the citizen's own review page submits it; staff
//! review it through the configured review authority and apply it. The review
//! authority is a loopback stub serving one accepted result, and the accepted
//! submission is recorded the way reconciliation records it.

#![cfg(all(feature = "postgres-test", feature = "tooling", unix))]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::extract::{Path as UrlPath, State};
use axum::http::{Method, Request, StatusCode};
use axum::response::IntoResponse as _;
use postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_yaml, RegistryProject};
use registry_breg::fixtures::{
    validate_fixture_journeys, validate_schema_test_receipt_for_package, FixtureError,
    FixtureSourceFile, PostgresFixtureTestRunner, SchemaTestSources, ValidatedFixtureJourneys,
};
use registry_breg::package::{
    load_package, prepare_package, PackageBuildRequest, PackageIntent, PackageLoadContext,
    PackageMigrationPlanInput, PackageSignature, PackageSourceFile, PackageTrustAnchor,
    PreparedPackage, SignaturePolicy, TrustAnchorKey, VerifiedPackage, FIXTURE_JOURNEYS_PATH,
    TRUST_ANCHOR_API_VERSION,
};
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    managed_schema_fingerprint, ExpectedManagedCatalog, RegistryStateTestIdentity,
};
use registry_breg::startup::{prepare_with_connection_config_for_test, PreparedServer};
use registry_breg::CompiledRegistry;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_crypto::{generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk};
use registry_platform_testing::{fixtures as testing_fixtures, jwks_from_private_jwk, MockIdp};
use serde::Serialize;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::task::JoinHandle;
use tower::Service as _;
use uuid::Uuid;

const PROJECT: &str = "citizen-address-correction";
const AUDIENCE: &str = "urn:breg:citizen-address-correction";
const GATEWAY_CLIENT: &str = "citizen-gateway";
const REVIEW_PAGE_CLIENT: &str = "citizen-review-page";
const STAFF_CLIENT: &str = "registry-staff-console";
/// The synthetic actor identity the runtime pins to the gateway client.
const GATEWAY_ACTOR: &str = "6f1c2d8e-3b4a-4e59-9c7d-2a8b5e0f1d34";
const SELF_SCOPE: &str = "address-correction:self";
const REVIEW_SCOPE: &str = "address-correction:review";
const APPLY_SCOPE: &str = "address-correction:apply";
const STEWARD_SCOPE: &str = "registry:steward";
const CITIZEN_A: &str = "synthetic-citizen-a";
const CITIZEN_B: &str = "synthetic-citizen-b";
const REQUEST_ENTITY: &str = "address-correction-request";
const REVIEW_AUTHORITY: &str = "casework";
// Each fixture owns the process-global configured WASM runtime until finish.
static WASM_RUNTIME_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn citizen_address_correction_journeys_run_through_the_authenticated_postgres_runner() {
    let fixture = RunningFixture::start().await;
    let receipt_journeys = fixture.run_journeys().await;
    assert_eq!(
        receipt_journeys,
        [
            "agent-drafts-and-review-page-submits",
            "other-citizen-cannot-reach-the-draft",
        ]
    );
    fixture.finish().await;
}

/// The standing agent authors a draft and nothing else: it cannot submit,
/// cannot borrow the review page's profile, and cannot write the address. The
/// review page submits only with the request's current `ifMatch`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_drafts_and_the_review_page_submits_with_the_current_if_match() {
    let fixture = RunningFixture::start().await;
    let citizen = fixture.seed_citizen("P-0001", CITIZEN_A).await;
    let agent = fixture.agent_token(CITIZEN_A);
    let review = fixture.review_page_token(CITIZEN_A);

    let own_address = fixture
        .call(
            Method::GET,
            &format!(
                "/v1/records/person-addresses/{}?accessProfile=citizen-agent",
                citizen.address
            ),
            None,
            &[],
            &agent,
        )
        .await;
    assert_eq!(own_address.status, StatusCode::OK, "{}", own_address.body);
    assert_eq!(
        own_address.body["data"]["domainData"],
        json!({"addressLine": "1 Harbour Road", "locality": "Port Selene", "postalCode": "PS-100"})
    );

    let draft = fixture
        .create_draft(&agent, &citizen.address, "agent-create", "2 Quarry Lane")
        .await;
    let patched = fixture
        .call(
            Method::PATCH,
            &format!("{}?accessProfile=citizen-agent", draft.path),
            Some(json!([{"op":"replace","path":"/data/newLocality","value":"Selene Heights"}])),
            &[
                ("idempotency-key", "agent-patch"),
                ("if-match", &draft.etag),
            ],
            &agent,
        )
        .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.body);

    let agent_view = fixture
        .call(
            Method::GET,
            &format!("{}?accessProfile=citizen-agent", draft.path),
            None,
            &[],
            &agent,
        )
        .await;
    assert_eq!(agent_view.status, StatusCode::OK, "{}", agent_view.body);
    assert!(
        !offered_operations(&agent_view.body).contains(&"submit_request".to_owned()),
        "the agent profile is never offered submission: {}",
        agent_view.body
    );

    let before = fixture
        .request_view(&draft, "citizen-review", &review)
        .await;
    let submit = action(&before, "submit_request");
    let agent_submit = fixture
        .call(
            Method::POST,
            &with_profile(&submit.href, "citizen-agent"),
            Some(json!({})),
            &[
                ("idempotency-key", "agent-submit"),
                ("if-match", &submit.if_match),
            ],
            &agent,
        )
        .await;
    assert_refused(&agent_submit, "agent submission");
    let borrowed_submit = fixture
        .call(
            Method::POST,
            &submit.href,
            Some(json!({})),
            &[
                ("idempotency-key", "agent-borrowed-submit"),
                ("if-match", &submit.if_match),
            ],
            &agent,
        )
        .await;
    assert_refused(&borrowed_submit, "agent selecting the review page profile");

    let direct_patch = fixture
        .call(
            Method::PATCH,
            &format!(
                "/v1/records/person-addresses/{}?accessProfile=citizen-agent",
                citizen.address
            ),
            Some(json!([{"op":"replace","path":"/data/addressLine","value":"9 Elsewhere"}])),
            &[
                ("idempotency-key", "agent-direct-patch"),
                ("if-match", &own_address.etag),
            ],
            &agent,
        )
        .await;
    assert_refused(&direct_patch, "agent direct address write");
    let direct_create = fixture
        .call(
            Method::POST,
            "/v1/records/person-addresses?accessProfile=citizen-agent",
            Some(json!({"data": {
                "subject": citizen.person, "addressLine": "9 Elsewhere",
                "locality": "Port Selene", "postalCode": "PS-999",
            }})),
            &[("idempotency-key", "agent-direct-create")],
            &agent,
        )
        .await;
    assert_refused(&direct_create, "agent direct address create");

    // The agent edits the draft after the review page read it, so the
    // review page's precondition is stale and submission is refused.
    let second_patch = fixture
        .call(
            Method::PATCH,
            &format!("{}?accessProfile=citizen-agent", draft.path),
            Some(json!([{"op":"replace","path":"/data/newPostalCode","value":"PS-205"}])),
            &[
                ("idempotency-key", "agent-second-patch"),
                ("if-match", &agent_view.etag),
            ],
            &agent,
        )
        .await;
    assert_eq!(second_patch.status, StatusCode::OK, "{}", second_patch.body);
    let stale = fixture
        .call(
            Method::POST,
            &submit.href,
            Some(json!({})),
            &[
                ("idempotency-key", "review-stale-submit"),
                ("if-match", &submit.if_match),
            ],
            &review,
        )
        .await;
    assert_eq!(
        stale.status,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        stale.body
    );
    assert_eq!(fixture.review_submission_count(&draft.id).await, 0);

    let current = fixture
        .request_view(&draft, "citizen-review", &review)
        .await;
    let submit = action(&current, "submit_request");
    let submitted = fixture
        .call(
            Method::POST,
            &submit.href,
            Some(json!({})),
            &[
                ("idempotency-key", "review-submit"),
                ("if-match", &submit.if_match),
            ],
            &review,
        )
        .await;
    assert_eq!(submitted.status, StatusCode::OK, "{}", submitted.body);
    assert_eq!(fixture.review_submission_count(&draft.id).await, 1);
    let reviewed = fixture
        .request_view(
            &draft,
            "reviewer",
            &fixture.staff_token("synthetic-reviewer", REVIEW_SCOPE),
        )
        .await;
    assert_eq!(
        reviewed["data"]["domainData"],
        json!({
            "address": citizen.address, "newAddressLine": "2 Quarry Lane",
            "newLocality": "Selene Heights", "newPostalCode": "PS-205",
        })
    );
    fixture.finish().await;
}

/// Another citizen's agent and review page share the profiles but not the
/// principal, so the draft does not exist for them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_citizen_cannot_read_patch_or_submit_the_draft() {
    let fixture = RunningFixture::start().await;
    let citizen_a = fixture.seed_citizen("P-0001", CITIZEN_A).await;
    fixture.seed_citizen("P-0002", CITIZEN_B).await;
    let draft = fixture
        .create_draft(
            &fixture.agent_token(CITIZEN_A),
            &citizen_a.address,
            "a-create",
            "2 Quarry Lane",
        )
        .await;
    let owner_view = fixture
        .request_view(
            &draft,
            "citizen-review",
            &fixture.review_page_token(CITIZEN_A),
        )
        .await;
    let submit = action(&owner_view, "submit_request");

    let other_agent = fixture.agent_token(CITIZEN_B);
    let other_review = fixture.review_page_token(CITIZEN_B);
    for (profile, token) in [
        ("citizen-agent", &other_agent),
        ("citizen-review", &other_review),
    ] {
        let read = fixture
            .call(
                Method::GET,
                &format!("{}?accessProfile={profile}", draft.path),
                None,
                &[],
                token,
            )
            .await;
        assert_eq!(
            read.status,
            StatusCode::NOT_FOUND,
            "{profile} read: {}",
            read.body
        );
        let patch = fixture
            .call(
                Method::PATCH,
                &format!("{}?accessProfile={profile}", draft.path),
                Some(json!([{"op":"replace","path":"/data/newAddressLine","value":"7 Taken Street"}])),
                &[("idempotency-key", &format!("{profile}-other-patch")), ("if-match", &draft.etag)],
                token,
            )
            .await;
        // The draft is answered exactly like a record that does not exist.
        let unknown = fixture
            .call(
                Method::PATCH,
                &format!(
                    "/v1/records/address-correction-requests/{}?accessProfile={profile}",
                    Uuid::new_v4()
                ),
                Some(json!([{"op":"replace","path":"/data/newAddressLine","value":"7 Taken Street"}])),
                &[("idempotency-key", &format!("{profile}-unknown-patch")), ("if-match", &draft.etag)],
                token,
            )
            .await;
        assert_eq!(
            patch.status,
            StatusCode::PRECONDITION_FAILED,
            "{profile} patch: {}",
            patch.body
        );
        assert_eq!(
            (patch.status, &patch.body["code"]),
            (unknown.status, &unknown.body["code"]),
            "{profile} patch: {} unknown: {}",
            patch.body,
            unknown.body
        );
        // The other citizen's agent never reads its neighbour's address.
        let address = fixture
            .call(
                Method::GET,
                &format!(
                    "/v1/records/person-addresses/{}?accessProfile=citizen-agent",
                    citizen_a.address
                ),
                None,
                &[],
                &other_agent,
            )
            .await;
        assert_eq!(address.status, StatusCode::NOT_FOUND, "{}", address.body);
    }
    let other_submit = fixture
        .call(
            Method::POST,
            &submit.href,
            Some(json!({})),
            &[
                ("idempotency-key", "other-submit"),
                ("if-match", &submit.if_match),
            ],
            &other_review,
        )
        .await;
    let unknown_submit = fixture
        .call(
            Method::POST,
            &submit.href.replace(&draft.id, &Uuid::new_v4().to_string()),
            Some(json!({})),
            &[
                ("idempotency-key", "unknown-submit"),
                ("if-match", &submit.if_match),
            ],
            &other_review,
        )
        .await;
    assert_eq!(
        other_submit.status,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        other_submit.body
    );
    assert_eq!(
        (other_submit.status, &other_submit.body["code"]),
        (unknown_submit.status, &unknown_submit.body["code"]),
        "submit: {} unknown: {}",
        other_submit.body,
        unknown_submit.body
    );
    assert_eq!(fixture.review_submission_count(&draft.id).await, 0);

    // The owner's draft is untouched by the refused attempts.
    let unchanged = fixture
        .request_view(
            &draft,
            "citizen-review",
            &fixture.review_page_token(CITIZEN_A),
        )
        .await;
    assert_eq!(
        unchanged["data"]["domainData"]["newAddressLine"],
        "2 Quarry Lane"
    );
    fixture.finish().await;
}

/// Submission freezes the proposal and leaves the address alone; only the
/// applier, after the review authority's approval is reconciled, changes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn address_changes_only_after_approval_and_apply() {
    let fixture = RunningFixture::start().await;
    let citizen = fixture.seed_citizen("P-0001", CITIZEN_A).await;
    let draft = fixture
        .create_draft(
            &fixture.agent_token(CITIZEN_A),
            &citizen.address,
            "create",
            "2 Quarry Lane",
        )
        .await;
    let review = fixture.review_page_token(CITIZEN_A);
    let view = fixture
        .request_view(&draft, "citizen-review", &review)
        .await;
    let submit = action(&view, "submit_request");
    let submitted = fixture
        .call(
            Method::POST,
            &submit.href,
            Some(json!({})),
            &[
                ("idempotency-key", "submit"),
                ("if-match", &submit.if_match),
            ],
            &review,
        )
        .await;
    assert_eq!(submitted.status, StatusCode::OK, "{}", submitted.body);
    let digest = submitted.body["request"]["effectDigest"]
        .as_str()
        .unwrap_or_else(|| panic!("submission freezes the effect digest: {}", submitted.body))
        .to_owned();
    let original = json!({"subject": citizen.person, "addressLine": "1 Harbour Road", "locality": "Port Selene", "postalCode": "PS-100"});
    assert_eq!(fixture.steward_address(&citizen.address).await, original);

    let applier = fixture.staff_token("synthetic-applier", APPLY_SCOPE);
    let pending = fixture.request_view(&draft, "applier", &applier).await;
    let early = action(&pending, "apply_request");
    let refused = fixture
        .call(
            Method::POST,
            &early.href,
            Some(json!({"proposalVersion": 1, "effectDigest": digest})),
            &[
                ("idempotency-key", "early-apply"),
                ("if-match", &early.if_match),
            ],
            &applier,
        )
        .await;
    assert_eq!(
        (refused.status, refused.body["code"].as_str()),
        (StatusCode::PRECONDITION_FAILED, Some("precondition.failed")),
        "apply before approval: {}",
        refused.body
    );
    assert_eq!(fixture.steward_address(&citizen.address).await, original);

    fixture.approve(&draft.id).await;
    assert_eq!(fixture.steward_address(&citizen.address).await, original);
    let approved = fixture.request_view(&draft, "applier", &applier).await;
    let apply = action(&approved, "apply_request");
    let applied = fixture
        .call(
            Method::POST,
            &apply.href,
            Some(json!({"proposalVersion": 1, "effectDigest": digest})),
            &[("idempotency-key", "apply"), ("if-match", &apply.if_match)],
            &applier,
        )
        .await;
    assert_eq!(applied.status, StatusCode::OK, "{}", applied.body);
    assert_eq!(
        fixture.steward_address(&citizen.address).await,
        json!({"subject": citizen.person, "addressLine": "2 Quarry Lane", "locality": "Port Selene", "postalCode": "PS-100"})
    );
    fixture.finish().await;
}

/// The review page reads a draft's target under the citizen's own token and
/// offers submission only when that read succeeds. The citizen review profile
/// therefore reads the citizen's linked address and nobody else's, even when a
/// draft the citizen owns names another person's address.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_page_reads_only_the_linked_target_of_a_draft() {
    let fixture = RunningFixture::start().await;
    let citizen_a = fixture.seed_citizen("P-0001", CITIZEN_A).await;
    let citizen_b = fixture.seed_citizen("P-0002", CITIZEN_B).await;
    let review_a = fixture.review_page_token(CITIZEN_A);
    let review_b = fixture.review_page_token(CITIZEN_B);

    let own = fixture
        .review_address_read(&citizen_a.address, &review_a)
        .await;
    assert_eq!(own.status, StatusCode::OK, "{}", own.body);
    assert_eq!(
        own.body["data"]["domainData"],
        json!({"addressLine": "1 Harbour Road", "locality": "Port Selene", "postalCode": "PS-100"})
    );
    let own_b = fixture
        .review_address_read(&citizen_b.address, &review_b)
        .await;
    assert_eq!(own_b.status, StatusCode::OK, "{}", own_b.body);
    let foreign = fixture
        .review_address_read(&citizen_a.address, &review_b)
        .await;
    assert_refused(&foreign, "review page reading another citizen's address");

    // The registry does not bind a draft's target to the owner's link, so a
    // draft naming another person's address may be accepted. Whether it is
    // or not, that target must stay unreadable to the draft's owner.
    let created = fixture
        .call(
            Method::POST,
            "/v1/records/address-correction-requests?accessProfile=citizen-agent",
            Some(json!({"data": draft_data(&citizen_a.address, CITIZEN_B, "8 Mismatch Road")})),
            &[("idempotency-key", "foreign-target")],
            &fixture.agent_token(CITIZEN_B),
        )
        .await;
    if created.status == StatusCode::CREATED {
        let id = created.body["data"]["recordIdentifier"]
            .as_str()
            .expect("draft has an identifier");
        let draft = fixture
            .call(
                Method::GET,
                &format!(
                    "/v1/records/address-correction-requests/{id}?accessProfile=citizen-review"
                ),
                None,
                &[],
                &review_b,
            )
            .await;
        assert_eq!(draft.status, StatusCode::OK, "{}", draft.body);
        let target = draft.body["data"]["domainData"]["address"]
            .as_str()
            .expect("the draft names its target");
        assert_eq!(target, citizen_a.address);
        let target_read = fixture.review_address_read(target, &review_b).await;
        assert_refused(&target_read, "review page reading a draft's foreign target");
    } else {
        assert!(
            created.status.is_client_error(),
            "{} {}",
            created.status,
            created.body
        );
    }
    fixture.finish().await;
}

/// The agent finds the citizen's address by listing under the self-service
/// link, so the list is bounded exactly like the read: the caller's own
/// linked address, its three readable fields, and nothing of another citizen.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn citizen_agent_list_returns_only_the_linked_address() {
    let fixture = RunningFixture::start().await;
    let citizen_a = fixture.seed_citizen("P-0001", CITIZEN_A).await;
    let citizen_b = fixture.seed_citizen("P-0002", CITIZEN_B).await;

    for (principal, citizen, own) in [
        (
            CITIZEN_B,
            &citizen_b,
            json!({"addressLine": "4 Mill Street", "locality": "Port Selene", "postalCode": "PS-400"}),
        ),
        (
            CITIZEN_A,
            &citizen_a,
            json!({"addressLine": "1 Harbour Road", "locality": "Port Selene", "postalCode": "PS-100"}),
        ),
    ] {
        let listed = fixture
            .call(
                Method::GET,
                "/v1/records/person-addresses?accessProfile=citizen-agent",
                None,
                &[],
                &fixture.agent_token(principal),
            )
            .await;
        assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
        let items = listed.body["items"]
            .as_array()
            .expect("the list answers with items");
        assert_eq!(items.len(), 1, "{principal}: {}", listed.body);
        assert_eq!(
            items[0]["recordIdentifier"].as_str(),
            Some(citizen.address.as_str())
        );
        assert_eq!(items[0]["domainData"], own, "{principal}");
    }
    fixture.finish().await;
}

/// A retried create and a retried submission, each under its own key, answer
/// with the first result and leave exactly one draft and one submission.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_and_submit_retries_produce_one_effect() {
    let fixture = RunningFixture::start().await;
    let citizen = fixture.seed_citizen("P-0001", CITIZEN_A).await;
    let agent = fixture.agent_token(CITIZEN_A);
    let first = fixture
        .create_draft(&agent, &citizen.address, "retried-create", "2 Quarry Lane")
        .await;
    let retry = fixture
        .create_draft(&agent, &citizen.address, "retried-create", "2 Quarry Lane")
        .await;
    assert_eq!(retry.id, first.id);
    let reviewer = fixture.staff_token("synthetic-reviewer", REVIEW_SCOPE);
    let listed = fixture
        .call(
            Method::GET,
            "/v1/records/address-correction-requests?accessProfile=reviewer",
            None,
            &[],
            &reviewer,
        )
        .await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
    assert_eq!(
        listed.body["items"].as_array().map(Vec::len),
        Some(1),
        "{}",
        listed.body
    );

    let review = fixture.review_page_token(CITIZEN_A);
    let view = fixture
        .request_view(&first, "citizen-review", &review)
        .await;
    let submit = action(&view, "submit_request");
    let mut answers = Vec::new();
    for _ in 0..2 {
        let answer = fixture
            .call(
                Method::POST,
                &submit.href,
                Some(json!({})),
                &[
                    ("idempotency-key", "retried-submit"),
                    ("if-match", &submit.if_match),
                ],
                &review,
            )
            .await;
        assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
        answers.push(answer.body);
    }
    assert_eq!(answers[0], answers[1]);
    assert_eq!(fixture.review_submission_count(&first.id).await, 1);
    fixture.finish().await;
}

/// A standing agent profile requires the registered actor for its client. A
/// gateway token without `act` is refused before any record is touched, and
/// the admission reason is the missing trusted actor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_profile_token_without_act_is_refused_as_trusted_actor_missing() {
    let fixture = RunningFixture::start().await;
    let citizen = fixture.seed_citizen("P-0001", CITIZEN_A).await;
    let mut claims = agent_claims(CITIZEN_A);
    claims
        .as_object_mut()
        .expect("agent claims are an object")
        .remove("act");
    let without_act = fixture.token(claims);
    let read = fixture
        .call(
            Method::GET,
            &format!(
                "/v1/records/person-addresses/{}?accessProfile=citizen-agent",
                citizen.address
            ),
            None,
            &[],
            &without_act,
        )
        .await;
    assert_refused(&read, "agent read without act");
    let create = fixture
        .call(
            Method::POST,
            "/v1/records/address-correction-requests?accessProfile=citizen-agent",
            Some(json!({"data": draft_data(&citizen.address, CITIZEN_A, "2 Quarry Lane")})),
            &[("idempotency-key", "no-act-create")],
            &without_act,
        )
        .await;
    assert_refused(&create, "agent create without act");

    let preview = registry_breg::access_preview::preview_access(
        &fixture.registry,
        serde_json::from_value(json!({
            "entity": REQUEST_ENTITY,
            "accessProfile": "citizen-agent",
            "operation": "create",
            "claims": {
                "principalClaim": "sub", "principal": CITIZEN_A, "scopes": [SELF_SCOPE],
                "actorKind": "agent", "requesterClient": GATEWAY_CLIENT,
            },
        }))
        .expect("synthetic scenario parses"),
    )
    .expect("synthetic scenario previews");
    assert!(!preview.admitted);
    assert_eq!(preview.reason, "trusted_actor_missing");
    fixture.finish().await;
}

struct Citizen {
    person: String,
    address: String,
}

struct Draft {
    id: String,
    path: String,
    etag: String,
}

struct RequestAction {
    href: String,
    if_match: String,
}

struct Answer {
    status: StatusCode,
    etag: String,
    body: Value,
}

struct RunningFixture {
    runtime_guard: tokio::sync::MutexGuard<'static, ()>,
    database: TestDatabase,
    registry: Arc<CompiledRegistry>,
    prepared: PreparedServer,
    idp: MockIdp,
    package: TestPackage,
    sources: ProjectSources,
    authority: ReviewAuthorityStub,
}

impl RunningFixture {
    async fn start() -> Self {
        let runtime_guard = WASM_RUNTIME_TEST_LOCK.lock().await;
        let sources = ProjectSources::load();
        let registry = Arc::new(sources.compiled.clone());
        let database = TestDatabase::create(8).await;
        let (migration, migration_task) = database.connect_migration().await;
        let expected_catalog = ExpectedManagedCatalog::compiled(&registry);
        install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .expect("administrator installs the compiler-owned schema");
        let schema_fingerprint =
            managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
                .await
                .expect("managed schema fingerprint computes");
        let package = TestPackage::build(&sources, &schema_fingerprint);
        initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            &registry,
            RegistryStateTestIdentity {
                package_id: &package.package.manifest().package_id,
                environment: &package.package.manifest().environment,
                instance_id: &package.package.manifest().instance_id,
                database_id: &package.package.manifest().database_id,
                package_revision: &package.package.manifest().package_revision,
                package_sequence: 1,
            },
        )
        .await
        .expect("database initializes from the exact signed package identity");
        drop(migration);
        migration_task.abort();

        let authority = ReviewAuthorityStub::start().await;
        let idp = MockIdp::start().await;
        let config_path = package.write_runtime_config(&database, &idp, &authority.endpoint);
        let prepared =
            prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
                .await
                .expect("verified startup constructs the authenticated runtime");

        Self {
            runtime_guard,
            database,
            registry,
            prepared,
            idp,
            package,
            sources,
            authority,
        }
    }

    /// Validate, run, and receipt every journey; return the receipt's
    /// successful journey ids.
    async fn run_journeys(&self) -> Vec<String> {
        let suite = validate_fixture_journeys(&self.sources.journeys, &self.registry)
            .unwrap_or_else(|error| {
                panic!(
                    "journeys preflight against the Production registry: {}",
                    fixture_error_with_source_context(&self.sources.journeys, &error)
                )
            });
        let tokens = self.journey_tokens(&suite);
        let runner = PostgresFixtureTestRunner::prepare(
            &self.package.package,
            &SchemaTestSources {
                project: FixtureSourceFile {
                    path: "registry.yaml",
                    bytes: &self.sources.project_bytes,
                },
                project_assets: &[],
                modules: &[],
                migration_plan: FixtureSourceFile {
                    path: "database/migration-plan.json",
                    bytes: &self.package.migration_plan,
                },
            },
            &suite,
            &self.prepared,
            tokens,
        )
        .await
        .unwrap_or_else(|error| {
            panic!(
                "runner derives exact package and same-database facts: {}",
                fixture_error_with_source_context(&self.sources.journeys, &error)
            )
        });
        let completed = runner.run_all().await.unwrap_or_else(|error| {
            panic!(
                "journeys execute through the authenticated PostgreSQL router: {}",
                fixture_error_with_source_context(&self.sources.journeys, &error)
            )
        });
        let receipt = completed
            .build_receipt(&suite)
            .expect("execution emits a bound schema-test receipt");
        let receipt_bytes = receipt.canonical_bytes().expect("receipt canonicalizes");
        validate_schema_test_receipt_for_package(&receipt_bytes, &self.package.prepared, &suite)
            .expect("receipt revalidates against the exact prepared package");
        receipt.successful_journey_ids().to_vec()
    }

    /// Mint one bearer token per journey step, in source order, from the
    /// step's declared claims: its principal, scopes, actor kind, requester
    /// client, and, for the agent, the configured actor.
    fn journey_tokens(&self, suite: &ValidatedFixtureJourneys) -> Vec<String> {
        let source: Value = serde_norway::from_slice(&self.sources.journeys)
            .expect("journey source converts to a JSON value");
        let journeys = source["journeys"]
            .as_array()
            .expect("journey source lists journeys");
        assert_eq!(
            journeys
                .iter()
                .map(|journey| journey["id"].as_str().expect("journey id"))
                .collect::<Vec<_>>(),
            suite.journey_ids(),
            "source and validated journey order must match before assigning bearer tokens"
        );
        journeys
            .iter()
            .flat_map(|journey| journey["steps"].as_array().expect("journey lists steps"))
            .map(|step| {
                let claims = &step["claims"];
                let mut token = json!({
                    "sub": claims["principal"].as_str().expect("every step names a principal"),
                    "registry_actor_kind": claims["actorKind"].as_str().expect("every step names an actor kind"),
                    "azp": claims["requesterClient"].as_str().expect("every step names its client"),
                    "scope": claims["scopes"]
                        .as_array()
                        .expect("every step names its scopes")
                        .iter()
                        .map(|scope| scope.as_str().expect("scope is a string"))
                        .collect::<Vec<_>>()
                        .join(" "),
                });
                if let Some(actor) = claims["actorSubject"].as_str() {
                    token["act"] = json!({"sub": actor});
                }
                // The owner row boundary binds `sub`, the principal claim, so
                // a step's direct claim can only restate the same principal.
                if let Some(direct) = claims["directClaims"].as_object() {
                    assert!(
                        direct.iter().all(|(name, value)| name == "sub" && *value == token["sub"]),
                        "a journey direct claim restates the step principal"
                    );
                }
                self.token(token)
            })
            .collect()
    }

    fn token(&self, mut claims: Value) -> String {
        claims["aud"] = json!(AUDIENCE);
        self.idp.mint_token(claims)
    }

    fn agent_token(&self, citizen: &str) -> String {
        self.token(agent_claims(citizen))
    }

    fn review_page_token(&self, citizen: &str) -> String {
        self.token(json!({
            "sub": citizen,
            "azp": REVIEW_PAGE_CLIENT,
            "registry_actor_kind": "human",
            "scope": SELF_SCOPE,
        }))
    }

    fn staff_token(&self, principal: &str, scope: &str) -> String {
        self.token(json!({
            "sub": principal,
            "azp": STAFF_CLIENT,
            "registry_actor_kind": "human",
            "scope": scope,
        }))
    }

    async fn call(
        &self,
        method: Method,
        uri: &str,
        body: Option<Value>,
        headers: &[(&str, &str)],
        token: &str,
    ) -> Answer {
        let content_type = if method == Method::PATCH {
            "application/json-patch+json"
        } else {
            "application/json"
        };
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"));
        if body.is_some() {
            request = request.header("content-type", content_type);
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let request = request
            .body(body.map_or_else(Body::empty, |body| {
                Body::from(serde_json::to_vec(&body).expect("body serializes"))
            }))
            .expect("request builds");
        let response = self
            .prepared
            .app()
            .call(request)
            .await
            .expect("router answers");
        let status = response.status();
        let etag = response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("response body reads");
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("response body is JSON")
        };
        Answer { status, etag, body }
    }

    async fn create(&self, route: &str, key: &str, data: Value) -> String {
        let steward = self.staff_token("synthetic-steward", STEWARD_SCOPE);
        let created = self
            .call(
                Method::POST,
                &format!("/v1/records/{route}?accessProfile=steward"),
                Some(json!({"data": data})),
                &[("idempotency-key", key)],
                &steward,
            )
            .await;
        assert_eq!(
            created.status,
            StatusCode::CREATED,
            "{route}: {}",
            created.body
        );
        created.body["data"]["recordIdentifier"]
            .as_str()
            .expect("created record has an identifier")
            .to_owned()
    }

    /// The steward registers a person with an address and links the
    /// citizen's principal to that person.
    async fn seed_citizen(&self, code: &str, principal: &str) -> Citizen {
        let person = self
            .create(
                "persons",
                &format!("person-{code}"),
                json!({"personCode": code, "familyName": "Okafor", "givenName": "Ada"}),
            )
            .await;
        let (line, postal) = if principal == CITIZEN_A {
            ("1 Harbour Road", "PS-100")
        } else {
            ("4 Mill Street", "PS-400")
        };
        let address = self
            .create(
                "person-addresses",
                &format!("address-{code}"),
                json!({"subject": person, "addressLine": line, "locality": "Port Selene", "postalCode": postal}),
            )
            .await;
        self.create(
            "self-service-links",
            &format!("link-{code}"),
            json!({"subject": person, "principal": principal, "active": true}),
        )
        .await;
        Citizen { person, address }
    }

    async fn create_draft(&self, agent: &str, address: &str, key: &str, line: &str) -> Draft {
        let created = self
            .call(
                Method::POST,
                "/v1/records/address-correction-requests?accessProfile=citizen-agent",
                Some(json!({"data": draft_data(address, CITIZEN_A, line)})),
                &[("idempotency-key", key)],
                agent,
            )
            .await;
        assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
        let id = created.body["data"]["recordIdentifier"]
            .as_str()
            .expect("draft has an identifier")
            .to_owned();
        Draft {
            path: format!("/v1/records/address-correction-requests/{id}"),
            id,
            etag: created.etag,
        }
    }

    async fn review_address_read(&self, address: &str, token: &str) -> Answer {
        self.call(
            Method::GET,
            &format!("/v1/records/person-addresses/{address}?accessProfile=citizen-review"),
            None,
            &[],
            token,
        )
        .await
    }

    async fn request_view(&self, draft: &Draft, profile: &str, token: &str) -> Value {
        let view = self
            .call(
                Method::GET,
                &format!("{}?accessProfile={profile}", draft.path),
                None,
                &[],
                token,
            )
            .await;
        assert_eq!(view.status, StatusCode::OK, "{profile}: {}", view.body);
        view.body
    }

    async fn steward_address(&self, address: &str) -> Value {
        let read = self
            .call(
                Method::GET,
                &format!("/v1/records/person-addresses/{address}?accessProfile=steward"),
                None,
                &[],
                &self.staff_token("synthetic-steward", STEWARD_SCOPE),
            )
            .await;
        assert_eq!(read.status, StatusCode::OK, "{}", read.body);
        read.body["data"]["domainData"].clone()
    }

    async fn review_submission_count(&self, request_id: &str) -> i64 {
        let request_id = Uuid::parse_str(request_id).expect("request id is a UUID");
        self.database
            .admin
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_request_review_submissions
                  WHERE request_entity_id=$1 AND request_id=$2",
                &[&REQUEST_ENTITY, &request_id],
            )
            .await
            .expect("review submissions count")
            .get(0)
    }

    /// Record the review authority's approval the way reconciliation does,
    /// and serve the same result from the authority for the fresh check
    /// application makes.
    async fn approve(&self, request_id: &str) {
        let request_id = Uuid::parse_str(request_id).expect("request id is a UUID");
        let row = self
            .database
            .admin
            .query_one(
                "SELECT create_request,expected_submission_digest
                   FROM registry_internal.registry_request_review_submissions
                  WHERE request_entity_id=$1 AND request_id=$2",
                &[&REQUEST_ENTITY, &request_id],
            )
            .await
            .expect("queued review submission");
        let create: Value = row.get(0);
        let submission_digest: String = row.get(1);
        let review_request_id = Uuid::new_v4();
        let result_id = Uuid::new_v4();
        let accepted = json!({
            "requestId": review_request_id,
            "subject": create["subject"].clone(),
            "policy": {
                "id": create["kind"].clone(),
                "version": "1",
                "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            },
            "submissionDigest": submission_digest,
        });
        let result = json!({
            "resultId": result_id,
            "requestId": review_request_id,
            "subject": accepted["subject"].clone(),
            "policy": accepted["policy"].clone(),
            "submissionDigest": accepted["submissionDigest"].clone(),
            "status": "approved",
            "completedAt": "2026-09-01T00:00:00Z",
            "availableUntil": "2099-09-02T00:00:00Z"
        });
        self.database
            .admin
            .execute(
                "UPDATE registry_internal.registry_request_review_submissions
                    SET state='accepted',accepted_binding=$3
                  WHERE request_entity_id=$1 AND request_id=$2",
                &[&REQUEST_ENTITY, &request_id, &accepted],
            )
            .await
            .expect("review submission accepted");
        self.database
            .admin
            .execute(
                "INSERT INTO registry_internal.registry_request_review_results
                 (request_entity_id,request_id,proposal_version,authority,result_id,result,status,
                  completed_at,available_until)
                 VALUES ($1,$2,1,$3,$4,$5,'approved',
                         '2026-09-01T00:00:00Z','2099-09-02T00:00:00Z')",
                &[
                    &REQUEST_ENTITY,
                    &request_id,
                    &REVIEW_AUTHORITY,
                    &result_id,
                    &result,
                ],
            )
            .await
            .expect("reconciled review result");
        *self.authority.result.lock().expect("stub result") = Some(result);
    }

    async fn finish(self) {
        let Self {
            runtime_guard,
            database,
            registry,
            prepared,
            idp,
            package,
            sources,
            authority,
        } = self;
        drop(prepared);
        drop(registry);
        drop(package);
        drop(sources);
        authority.task.abort();
        idp.stop().await;
        database.cleanup().await;
        drop(runtime_guard);
    }
}

fn agent_claims(citizen: &str) -> Value {
    json!({
        "sub": citizen,
        "azp": GATEWAY_CLIENT,
        "registry_actor_kind": "agent",
        "act": {"sub": GATEWAY_ACTOR},
        "scope": SELF_SCOPE,
    })
}

fn draft_data(address: &str, owner: &str, line: &str) -> Value {
    json!({
        "address": address,
        "newAddressLine": line,
        "newLocality": "Port Selene",
        "newPostalCode": "PS-100",
        "owner": owner,
    })
}

fn action(body: &Value, operation: &str) -> RequestAction {
    let actions = body["data"]["request"]["actions"]
        .as_array()
        .unwrap_or_else(|| panic!("request read exposes action links: {body}"));
    let action = actions
        .iter()
        .find(|action| action["operation"] == operation)
        .unwrap_or_else(|| panic!("missing {operation} action in {actions:?}"));
    RequestAction {
        href: action["href"].as_str().expect("action has href").to_owned(),
        if_match: action["ifMatch"]
            .as_str()
            .expect("action has precondition")
            .to_owned(),
    }
}

fn offered_operations(body: &Value) -> Vec<String> {
    body["data"]["request"]["actions"]
        .as_array()
        .map(|actions| {
            actions
                .iter()
                .filter_map(|action| action["operation"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Replace the access profile an advertised action link selects.
fn with_profile(href: &str, profile: &str) -> String {
    let (path, _) = href.split_once('?').unwrap_or((href, ""));
    format!("{path}?accessProfile={profile}")
}

/// A refused standing-agent call is concealed: the profile does not admit the
/// token, so the record is answered as absent rather than forbidden.
fn assert_refused(answer: &Answer, what: &str) {
    assert_eq!(
        (answer.status, answer.body["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("resource.not_found")),
        "{what}: {}",
        answer.body
    );
}

struct ReviewAuthorityStub {
    endpoint: String,
    result: Arc<Mutex<Option<Value>>>,
    task: JoinHandle<()>,
}

impl ReviewAuthorityStub {
    /// Serve the one accepted result, once approval is recorded, from the
    /// review authority's result route; every other lookup is unavailable.
    async fn start() -> Self {
        let result = Arc::new(Mutex::new(None::<Value>));
        let app = axum::Router::new()
            .route(
                "/v1/review-requests/{request_id}/result",
                axum::routing::get(
                    |State(result): State<Arc<Mutex<Option<Value>>>>,
                     UrlPath(request_id): UrlPath<Uuid>| async move {
                        match result.lock().expect("stub result").clone() {
                            Some(result) if result["requestId"] == request_id.to_string() => (
                                StatusCode::OK,
                                // The review client requires a W3C trace context on every answer.
                                [(
                                    "traceparent",
                                    "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
                                )],
                                axum::Json(result),
                            )
                                .into_response(),
                            _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                        }
                    },
                ),
            )
            .with_state(Arc::clone(&result));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("review authority stub listens");
        let endpoint = format!("http://{}/", listener.local_addr().expect("stub address"));
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("review authority stub serves");
        });
        Self {
            endpoint,
            result,
            task,
        }
    }
}

struct ProjectSources {
    project: RegistryProject,
    project_bytes: Vec<u8>,
    journeys: Vec<u8>,
    compiled: CompiledRegistry,
}

impl ProjectSources {
    fn load() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/acceptance")
            .join(PROJECT);
        let project_bytes =
            fs::read(root.join("registry.yaml")).expect("acceptance registry is readable");
        let project = parse_project_yaml(&project_bytes)
            .expect("acceptance registry follows the strict authoring contract");
        assert!(
            project.modules.is_empty(),
            "the project declares its entities inline"
        );
        let compiled = compile_project_with_assets(&project, &[], &[], CompileProfile::Production)
            .expect("acceptance project closes under the Production compiler");
        let journeys =
            fs::read(root.join("tests/journeys.yaml")).expect("acceptance journeys are readable");
        Self {
            project,
            project_bytes,
            journeys,
            compiled,
        }
    }
}

struct TestPackage {
    _root: TempDir,
    directory: PathBuf,
    package_root: PathBuf,
    anchor: PathBuf,
    revision: String,
    prepared: PreparedPackage,
    package: VerifiedPackage,
    migration_plan: Vec<u8>,
}

impl TestPackage {
    fn build(sources: &ProjectSources, schema_fingerprint: &str) -> Self {
        let identity = sources
            .project
            .package
            .as_ref()
            .expect("acceptance project declares package identity");
        let database_id = format!("{}-database", sources.project.registry.id);
        let signing = generate_private_jwk(GeneratedKeyAlgorithm::Es384)
            .expect("package signing key generates");
        let key_id = signing.public().kid.expect("generated signing key has kid");
        let prepared = prepare_package(PackageBuildRequest {
            environment: identity.environment.clone(),
            instance_id: identity.instance_id.clone(),
            database_id: database_id.clone(),
            sequence: identity.sequence,
            prior_revision: None,
            compiler_source_revision: identity.source_revision.clone(),
            schema_fingerprint: schema_fingerprint.to_owned(),
            signature_policy: SignaturePolicy {
                threshold: 1,
                key_ids: vec![key_id.clone()],
            },
            project: PackageSourceFile {
                path: "registry.yaml".to_owned(),
                bytes: sources.project_bytes.clone(),
            },
            modules: Vec::new(),
            fixture_journeys: PackageSourceFile {
                path: FIXTURE_JOURNEYS_PATH.to_owned(),
                bytes: sources.journeys.clone(),
            },
            migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
        })
        .expect("package prepares from exact sources");
        let migration_plan = prepared
            .file_bytes()
            .get("database/migration-plan.json")
            .expect("prepared package includes migration plan")
            .clone();
        let root = tempfile::tempdir().expect("temporary package root creates");
        let directory = root
            .path()
            .canonicalize()
            .expect("temporary package root canonicalizes");
        let package_root = directory.join("package");
        let revision = prepared.package_revision().to_owned();
        let signature =
            sign(prepared.canonical_signed_bytes(), &signing).expect("package bytes sign");
        prepared
            .publish_to_directory(
                &package_root,
                vec![PackageSignature {
                    key_id: key_id.clone(),
                    signature_hex: hex(&signature),
                }],
            )
            .expect("signed package publishes");
        let anchor = directory.join("trust-anchor.json");
        write_json(
            &anchor,
            &PackageTrustAnchor {
                api_version: TRUST_ANCHOR_API_VERSION.to_owned(),
                environment: identity.environment.clone(),
                instance_id: identity.instance_id.clone(),
                database_id: database_id.clone(),
                threshold: 1,
                keys: vec![TrustAnchorKey {
                    key_id,
                    jwk: serde_json::to_value(signing.public())
                        .expect("public signing JWK serializes"),
                }],
            },
        );
        let package = load_package(
            &package_root,
            &PackageLoadContext {
                environment: &identity.environment,
                instance_id: &identity.instance_id,
                database_id: &database_id,
                database_initialization_environment: &identity.environment,
                compiler_source_revision: &identity.source_revision,
                trust_anchor: Some(&anchor),
                intent: PackageIntent::InitialActivation,
            },
        )
        .expect("published package rederives and verifies");
        assert_eq!(package.registry(), &sources.compiled);
        Self {
            _root: root,
            directory,
            package_root,
            anchor,
            revision,
            prepared,
            package,
            migration_plan,
        }
    }

    fn write_runtime_config(
        &self,
        database: &TestDatabase,
        idp: &MockIdp,
        review_endpoint: &str,
    ) -> PathBuf {
        let secrets = self.directory.join("secrets");
        fs::create_dir_all(&secrets).expect("secret root creates");
        write_private(&secrets.join("database-url"), b"unused-by-test-startup");
        write_private(&secrets.join("audit-key"), &[0x71; 32]);
        write_private(&secrets.join("cursor-key"), &[0x52; 32]);
        write_private(
            &secrets.join("review-authority-token"),
            b"synthetic-review-token",
        );
        write_private(
            &secrets.join("oidc-jwks"),
            &serde_json::to_vec(&jwks_from_private_jwk(
                &PrivateJwk::parse(testing_fixtures::ED25519_PRIVATE_JWK)
                    .expect("test IdP key parses"),
            ))
            .expect("static JWKS serializes"),
        );
        let identity = self.package.manifest();
        let path = self.directory.join("runtime.yaml");
        fs::write(
            &path,
            format!(
                r#"apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: 127.0.0.1:9
identity:
  environment: {}
  instanceId: {}
  databaseId: {}
  databaseInitializationEnvironment: {}
secretProviders:
  file:
    root: {}
database:
  runtimeUrlRef: secret:file/database-url
  migrationUrlRef: secret:file/migration-database-url
  pool:
    maxSize: 8
    waitTimeoutMilliseconds: 2000
    createTimeoutMilliseconds: 2000
    recycleTimeoutMilliseconds: 2000
  roles:
    migration: {}
    runtime: {}
package:
  root: {}
  trustAnchorPath: {}
  compilerSourceRevision: {}
  activeRevision: {}
  activeSequence: {}
authentication:
  oidc:
    issuer: {}
    audience: {AUDIENCE}
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [{GATEWAY_CLIENT}, {REVIEW_PAGE_CLIENT}, {STAFF_CLIENT}]
    maxTokenLifetimeSeconds: 3600
    leewayMilliseconds: 60000
    jwksSource:
      kind: static
      documentRef: secret:file/oidc-jwks
    jwksCache:
      cacheTtlSeconds: 60
      negativeCacheTtlSeconds: 1
      refreshCooldownSeconds: 1
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 5000
      outageToleranceSeconds: 0
  authorityClaims:
    principal: sub
    trustedActors:
      {GATEWAY_CLIENT}: {GATEWAY_ACTOR}
reviewAuthorities:
  {REVIEW_AUTHORITY}:
    endpoint: {review_endpoint}
    profile: registry-producer
    producerId: citizen-address-registry
    recoveryDays: 7
    tokenRef: secret:file/review-authority-token
audit:
  hashKeyRef: secret:file/audit-key
cursor:
  secretRef: secret:file/cursor-key
  maxAgeSeconds: 300
operationalTimeouts:
  httpRequestMilliseconds: 5000
  shutdownGraceMilliseconds: 1000
  recordLockMilliseconds: 2000
  migrationLockMilliseconds: 2000
  migrationStatementMilliseconds: 5000
"#,
                identity.environment,
                identity.instance_id,
                identity.database_id,
                identity.environment,
                secrets.display(),
                database.migration_role.as_str(),
                database.runtime_role.as_str(),
                self.package_root.display(),
                self.anchor.display(),
                identity.compiler.source_revision,
                self.revision,
                identity.sequence,
                idp.issuer(),
            ),
        )
        .expect("strict runtime configuration writes");
        set_private_permissions(&path);
        path
    }
}

fn fixture_error_with_source_context(journey_source: &[u8], error: &FixtureError) -> String {
    if let FixtureError::StepFailed {
        journey_index,
        step_index,
        ..
    } = error
    {
        let source: Value =
            serde_norway::from_slice(journey_source).expect("journey source converts");
        if let Some(step) = source["journeys"][*journey_index]["steps"][*step_index]["id"].as_str()
        {
            let journey = source["journeys"][*journey_index]["id"]
                .as_str()
                .unwrap_or("?");
            return format!("{journey}.{step}: {error}");
        }
    }
    error.to_string()
}

fn write_json(path: &Path, value: &impl Serialize) {
    let bytes = canonicalize_json(&serde_json::to_value(value).expect("value serializes"))
        .expect("value canonicalizes");
    write_private(path, &bytes);
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("private file writes");
    set_private_permissions(path);
}

fn set_private_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("private file permissions set");
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}
