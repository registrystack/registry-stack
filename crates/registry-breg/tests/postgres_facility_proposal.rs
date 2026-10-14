// SPDX-License-Identifier: Apache-2.0
//! The canonical named Rhai correction as a durable, reviewed PostgreSQL journey.
#![cfg(feature = "postgres-test")]
#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use registry_breg::{
    api::{VerifiedClaimValue, VerifiedRequestClaims},
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_yaml, ModuleAssetSource},
    model::{CompiledActionExecution, CompiledProposalReview},
    proposal_workflow::{EntityId, FrozenPlannerKind, ProposalKey, ProposalSnapshot, RecordId},
};
use registry_breg_client::{
    BRegActionInvocationRequest, BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey,
    BRegProblemCode, BRegProposal, BRegProposalState, BRegRecordFormat,
};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};
use uuid::Uuid;

fn claims(scope: &str, purpose: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "facility-author",
        BTreeSet::from([scope.into()]),
        Some(purpose.into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string("zone-a").unwrap(),
        )]),
    )
    .unwrap()
}
fn map(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}
fn key(value: &str) -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(value).unwrap()
}

fn registry() -> registry_breg::CompiledRegistry {
    let yaml = include_str!("../../../products/breg/examples/refactor/facility/registry.yaml");
    let correction = yaml
        .split("  - id: correct-address\n")
        .nth(1)
        .unwrap()
        .split("  - id: deactivate-facility\n")
        .next()
        .unwrap();
    assert!(
        !correction.contains("application:"),
        "exercise the canonical omitted application default"
    );
    // Use the exact authored grants, including operator maintenance. The test
    // must not give itself a seeding permission an adopter's project lacks.
    let source = parse_project_yaml(yaml.as_bytes()).unwrap();
    let registry = compile_project_with_assets(
        &source,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "plans/correct-address.rhai".into(),
            bytes: include_bytes!(
                "../../../products/breg/examples/refactor/facility/plans/correct-address.rhai"
            )
            .to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .unwrap();
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "correct-address")
        .unwrap();
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        panic!("Proposal mode")
    };
    assert!(proposal.application.is_automatic());
    assert!(
        matches!(&proposal.review, CompiledProposalReview::Required { authority, source, .. }
        if authority == "casework" && source == "facility-registry")
    );
    assert!(
        action.handler.is_some(),
        "canonical named function is compiled"
    );
    registry
}

struct NoToken;
#[async_trait::async_trait]
impl registry_platform_httputil::TokenProvider for NoToken {
    async fn bearer_token(
        &self,
    ) -> Result<registry_platform_httputil::BearerToken, registry_platform_httputil::TokenError>
    {
        Err(registry_platform_httputil::TokenError::Unavailable)
    }
}
fn review_binding() -> Arc<registry_breg::review_store::ReviewAuthorityRegistry> {
    use registry_breg::review_store::{ReviewAuthorityClient, ReviewAuthorityRegistry};
    let client = registry_review_client::ReviewClient::new(
        registry_review_client::ReviewClientConfig::new("http://127.0.0.1:9/".parse().unwrap()),
    )
    .unwrap();
    let authority = Arc::new(
        ReviewAuthorityClient::new(
            "casework".into(),
            client,
            Arc::new(NoToken),
            "fixture-review".into(),
            "facility-review-producer".into(),
            7,
            None,
            None,
        )
        .unwrap(),
    );
    Arc::new(
        ReviewAuthorityRegistry::new(BTreeMap::from([("casework".into(), authority)])).unwrap(),
    )
}
#[derive(Default)]
struct SyntheticApproval {
    calls: AtomicUsize,
    unavailable: AtomicBool,
}
impl SyntheticApproval {
    fn result(
        &self,
        accepted: &registry_review_client::ReviewRequestAccepted,
    ) -> registry_review_client::ReviewResult {
        let now = chrono::Utc::now();
        registry_review_client::ReviewResult {
            result_id: accepted.request_id,
            request_id: accepted.request_id,
            subject: accepted.subject.clone(),
            policy: accepted.policy.clone(),
            submission_digest: accepted.submission_digest.clone(),
            status: registry_review_client::ReviewResultStatus::Approved,
            outcome: None,
            result: None,
            completed_at: now - chrono::Duration::seconds(1),
            available_until: now + chrono::Duration::minutes(5),
        }
    }
}
#[async_trait::async_trait]
impl registry_breg::review_store::ReviewResultSource for SyntheticApproval {
    async fn approved_evidence(
        &self,
        authority: &str,
        accepted: &registry_review_client::ReviewRequestAccepted,
    ) -> Result<
        registry_breg::review_integration::AcceptedReviewEvidence,
        registry_breg::mutation::MutationError,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(registry_breg::mutation::MutationError::Unavailable);
        }
        registry_breg::review_integration::AcceptedReviewEvidence::from_protocol(
            authority,
            accepted,
            &self.result(accepted),
        )
        .map_err(|_| registry_breg::mutation::MutationError::PreconditionFailed)
    }
}
async fn fixture() -> (client_http::ClientFixture, Arc<SyntheticApproval>) {
    let review = Arc::new(SyntheticApproval::default());
    let injected = review.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(),
        claims("registry:operator:write", "facility-administration"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(review_binding(), injected)
        },
    )
    .await;
    (fixture, review)
}
fn correction_input(facility: &str, postal: &str) -> Value {
    json!({"facilityId":facility,"addressLine":"3 Civic Road","city":"Chiang Mai","postalCode":postal})
}
async fn start(
    fixture: &client_http::ClientFixture,
    postal: &str,
) -> (client_http::ClientHttp, String, BRegProposal) {
    let seed = fixture
        .http
        .client
        .registry_contract(Some("operator-editor"))
        .await
        .unwrap();
    let BRegDirectWrite::Create(create) = seed
        .value
        .select_direct_write("records.operator.create", "operator-editor")
        .unwrap()
    else {
        panic!("operator create grant")
    };
    let operator = fixture
        .http
        .client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(
                json!({"operatorCode":"OP-CANONICAL","status":"active","jurisdiction":"zone-a"}),
            ))
            .unwrap(),
            &key("facility-operator"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap()
        .value
        .data
        .record_identifier;
    let registrar = fixture
        .client_for(claims(
            "registry:facility:register",
            "facility-administration",
        ))
        .await;
    let metadata = registrar
        .client
        .registry_contract(Some("facility-registrar"))
        .await
        .unwrap();
    let action = metadata
        .value
        .select_action("register-facility", "facility-registrar")
        .unwrap();
    let input = BRegActionInvocationRequest::new(&action, map(json!({"facilityCode":"CANONICAL-1","name":"Civic clinic",
        "addressLine":"1 Main Road","city":"Bangkok","postalCode":"10200","operatorId":operator,"jurisdiction":"zone-a"})), None).unwrap();
    let registered = registrar
        .client
        .invoke_action(&action, &input, &key("facility-register"))
        .await
        .unwrap();
    let facility = registered.value.results()["facility"]
        .record_identifier()
        .to_string();
    assert_eq!(
        registered.value.results().len(),
        2,
        "the real Action creates the facility and assignment"
    );
    let author = fixture
        .client_for(claims(
            "registry:facility:correction:submit",
            "facility-administration",
        ))
        .await;
    let metadata = author
        .client
        .registry_contract(Some("facility-correction-author"))
        .await
        .unwrap();
    let action = metadata
        .value
        .select_action("correct-address", "facility-correction-author")
        .unwrap();
    let input =
        BRegActionInvocationRequest::new(&action, map(correction_input(&facility, postal)), None)
            .unwrap();
    let draft = author
        .client
        .start_proposal(&action, &input, &key("facility-correct-start"))
        .await
        .unwrap()
        .value;
    (author, facility, draft)
}
async fn approve(
    fixture: &client_http::ClientFixture,
    proposal: &BRegProposal,
    review: &SyntheticApproval,
) {
    let id = Uuid::parse_str(proposal.id()).unwrap();
    let version = i64::from(proposal.submission_version());
    let row = fixture.database.admin.query_one("SELECT create_request,expected_submission_digest
        FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1 AND submission_version=$2", &[&id, &version]).await.unwrap();
    let create: registry_review_client::ReviewCreateRequest =
        serde_json::from_value(row.get(0)).unwrap();
    let expected = registry_review_client::submission_digest(
        "facility-review-producer",
        "facility-registry",
        &create,
    )
    .unwrap();
    assert_eq!(expected.as_str(), row.get::<_, String>(1));
    assert_eq!(create.subject.id, proposal.id());
    assert_eq!(
        create.subject.version,
        proposal.submission_version().to_string()
    );
    assert_eq!(
        create.subject.digest.as_str(),
        proposal.effect_digest().unwrap()
    );
    assert_eq!(create.subject.source, "facility-registry");
    let action = fixture
        .registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "correct-address")
        .unwrap();
    let CompiledActionExecution::Proposal { proposal: policy } = &action.execution else {
        unreachable!()
    };
    let CompiledProposalReview::Required { policy, .. } = &policy.review else {
        unreachable!()
    };
    assert_eq!(create.policy, *policy);
    let accepted = registry_review_client::ReviewRequestAccepted {
        request_id: Uuid::new_v4(),
        subject: create.subject,
        policy: serde_json::from_value(serde_json::to_value(policy).unwrap()).unwrap(),
        submission_digest: expected,
    };
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$3
        WHERE proposal_id=$1 AND submission_version=$2", &[&id, &version, &serde_json::to_value(&accepted).unwrap()]).await.unwrap();
    let (mut migration, task) = fixture.database.connect_migration().await;
    let tx = migration.transaction().await.unwrap();
    registry_breg::review_store::reconcile_result(
        &tx,
        "casework",
        &accepted,
        &review.result(&accepted),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    drop(migration);
    task.abort();
}
async fn assert_frozen_plan(
    fixture: &client_http::ClientFixture,
    proposal: &BRegProposal,
    facility: &str,
) {
    let id = Uuid::parse_str(proposal.id()).unwrap();
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT snapshot FROM registry_internal.registry_proposal_submissions
        WHERE proposal_id=$1 AND submission_version=$2",
            &[&id, &i64::from(proposal.submission_version())],
        )
        .await
        .unwrap();
    let snapshot: ProposalSnapshot = serde_json::from_value(row.get(0)).unwrap();
    snapshot
        .verify_digest(&ProposalKey::new(
            EntityId::new("correct-address").unwrap(),
            RecordId::new(proposal.id()).unwrap(),
        ))
        .unwrap();
    let binding = snapshot.planning_binding().expect("durable Rhai binding");
    assert_eq!(binding.kind(), FrozenPlannerKind::Rhai);
    assert_eq!(binding.abi_identifier(), "registry.action-plan/v1");
    assert!(binding.script_digest().is_some());
    let action = fixture
        .registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "correct-address")
        .unwrap();
    assert_eq!(
        binding.script_digest().unwrap().as_str(),
        action
            .handler
            .as_ref()
            .unwrap()
            .script_sha256
            .as_deref()
            .unwrap()
    );
    assert_eq!(
        snapshot.contract_fingerprint().as_str(),
        action.definition_revision
    );
    assert!(snapshot.application_policy().is_automatic());
    assert!(snapshot.system_grant_revision().is_some());
    assert_eq!(snapshot.effects().len(), 1);
    let effect = &snapshot.effects()[0];
    assert_eq!(
        effect.operation(),
        registry_breg::contract::Operation::Patch
    );
    assert_eq!(effect.id().as_str(), "facility-address");
    assert_eq!(effect.target().entity_id().as_str(), "facility");
    assert_eq!(
        effect.target().existing_record_id().unwrap().as_str(),
        facility
    );
    let values = effect
        .field_changes()
        .iter()
        .map(|change| {
            (
                change.field().as_str(),
                serde_json::to_value(change.after()).unwrap()["value"].clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        values,
        BTreeMap::from([
            ("address-line", json!("3 Civic Road")),
            ("city", json!("Chiang Mai")),
            ("postal-code", json!("50000"))
        ])
    );
    assert_eq!(snapshot.inputs()["address-line"], "3 Civic Road");
    assert_eq!(
        snapshot.application_preconditions().unwrap().contract.len(),
        2
    );
}
async fn address(
    fixture: &client_http::ClientFixture,
    facility: &str,
) -> (String, String, String, i64) {
    let entity = &fixture.registry.entities()["facility"];
    let query = format!(
        "SELECT \"{}\",\"{}\",\"{}\",record_revision FROM registry_data.\"{}\" WHERE record_id=$1",
        entity.fields["address-line"].physical_name,
        entity.fields["city"].physical_name,
        entity.fields["postal-code"].physical_name,
        entity.physical_table
    );
    let row = fixture
        .database
        .admin
        .query_one(&query, &[&Uuid::parse_str(facility).unwrap()])
        .await
        .unwrap();
    (row.get(0), row.get(1), row.get(2), row.get(3))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canonical_rhai_correction_freezes_reviews_applies_and_recovers_locally() {
    let (fixture, review) = fixture().await;
    let (author, facility, draft) = start(&fixture, "10300").await;
    let edit = author
        .client
        .prepare_proposal(
            &draft,
            "edit",
            json!({"input":correction_input(&facility,"50000")}),
            &key("facility-edit"),
        )
        .unwrap();
    let edited = author.client.execute_proposal(&edit).await.unwrap().value;
    let submit = author
        .client
        .prepare_proposal(&edited, "submit", json!({}), &key("facility-submit"))
        .unwrap();
    let submitted = author.client.execute_proposal(&submit).await.unwrap().value;
    assert_frozen_plan(&fixture, &submitted, &facility).await;
    assert_eq!(
        address(&fixture, &facility).await.0,
        "1 Main Road",
        "pure planning never writes the target"
    );
    let reviewer = fixture
        .client_for(claims("registry:proposal:review", "facility-review"))
        .await;
    let response = reqwest::Client::new()
        .get(format!(
            "{}/v1/proposals/{}/review-context?accessProfile=proposal-reviewer",
            reviewer.base_url,
            submitted.id()
        ))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let context: Value = response.json().await.unwrap();
    assert_eq!(status, reqwest::StatusCode::OK, "{context}");
    assert_eq!(context["subject"]["source"], "facility-registry");
    assert_eq!(context["subject"]["subjectType"], "proposal");
    assert_eq!(context["subject"]["id"], submitted.id());
    assert_eq!(
        context["subject"]["version"],
        submitted.submission_version().to_string()
    );
    assert_eq!(
        context["subject"]["digest"],
        submitted.effect_digest().unwrap()
    );
    let action = fixture
        .registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "correct-address")
        .unwrap();
    let exported =
        registry_breg::compiler::review_context::compile_schema(&fixture.registry, action)
            .unwrap()
            .unwrap();
    assert_eq!(
        context["context"]["contract"],
        json!({"id":exported.id,"revision":exported.revision,"schemaDigest":exported.digest})
    );
    let typed: registry_breg_client::BRegProposalReviewDocument =
        serde_json::from_value(context.clone()).unwrap();
    assert_eq!(
        typed.context.contract.unwrap().schema_digest,
        exported.digest
    );
    assert!(context["context"].get("id").is_none());
    assert_eq!(
        context["context"]["fields"],
        json!({"facilityId":facility,"currentAddressLine":"1 Main Road",
        "proposedAddressLine":"3 Civic Road","proposedCity":"Chiang Mai","proposedPostalCode":"50000"})
    );
    let metadata = reviewer
        .client
        .registry_contract(Some("proposal-reviewer"))
        .await
        .unwrap()
        .value;
    let binding = metadata
        .select_proposal_review_context("proposal-reviewer", "correct-address")
        .unwrap();
    let purpose_read = reviewer
        .client
        .read_proposal_review_by_id(&binding, submitted.id())
        .await
        .unwrap()
        .value;
    assert_eq!(purpose_read.subject.id, submitted.id());
    assert_eq!(
        purpose_read.subject.digest,
        submitted.effect_digest().unwrap()
    );
    assert!(purpose_read.context.fields.is_some());
    approve(&fixture, &submitted, &review).await;
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    assert_eq!(
        review.calls.load(Ordering::SeqCst),
        1,
        "application obtains fresh approval"
    );
    let applied = author.client.read_proposal(&submitted).await.unwrap().value;
    assert_eq!(applied.state(), BRegProposalState::Applied);
    let job = fixture
        .database
        .admin
        .query_one(
            "SELECT executor,state,attempt_count,proposal_digest,application_id IS NOT NULL
        FROM registry_internal.registry_proposal_application_jobs WHERE proposal_id=$1",
            &[&Uuid::parse_str(submitted.id()).unwrap()],
        )
        .await
        .unwrap();
    assert_eq!(job.get::<_, String>(0), "builtin");
    assert_eq!(job.get::<_, String>(1), "applied");
    assert_eq!(job.get::<_, i32>(2), 1);
    assert_eq!(job.get::<_, String>(3), submitted.effect_digest().unwrap());
    assert!(job.get::<_, bool>(4));
    assert_eq!(
        address(&fixture, &facility).await,
        (
            "3 Civic Road".into(),
            "Chiang Mai".into(),
            "50000".into(),
            2
        )
    );
    review.unavailable.store(true, Ordering::SeqCst);
    assert!(!fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    // Recover the original exact submission receipt after automatic application,
    // with the authority offline. This must retain its original response bytes.
    let replay = author.client.execute_proposal(&submit).await.unwrap();
    assert_eq!(
        serde_json::to_value(&submitted).unwrap(),
        serde_json::to_value(replay.value).unwrap()
    );
    assert_eq!(
        review.calls.load(Ordering::SeqCst),
        1,
        "committed receipt recovery is local"
    );
    assert_eq!(
        fixture
            .database
            .admin
            .query_one(
                "SELECT count(*)::bigint FROM registry_internal.registry_proposal_applications",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    drop(author);
    drop(reviewer);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canonical_rhai_refusal_current_revision_and_status_guards_recover_by_resubmission() {
    for stale_revision in [true, false] {
        let (fixture, review) = fixture().await;
        let (author, facility, draft) = start(&fixture, " ").await;
        let invalid = author
            .client
            .prepare_proposal(&draft, "submit", json!({}), &key("facility-invalid-postal"))
            .unwrap();
        let refused = author.client.execute_proposal(&invalid).await.unwrap_err();
        assert_eq!(
            refused.problem_code(),
            Some(BRegProblemCode::ActionRefused),
            "{refused:?}"
        );
        assert_eq!(
            refused.field_path().map(|path| path.as_str()),
            Some("/input/postalCode")
        );
        assert_eq!(
            refused.refusal_code().map(|code| code.as_str()),
            Some("invalid-postal-code")
        );
        assert_eq!(
            fixture
                .database
                .admin
                .query_one(
                    "SELECT count(*)::bigint FROM registry_internal.registry_proposal_submissions",
                    &[]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        let edit = author
            .client
            .prepare_proposal(
                &draft,
                "edit",
                json!({"input":correction_input(&facility,"50000")}),
                &key("facility-valid-edit"),
            )
            .unwrap();
        let edited = author.client.execute_proposal(&edit).await.unwrap().value;
        let submit = author
            .client
            .prepare_proposal(&edited, "submit", json!({}), &key("facility-valid-submit"))
            .unwrap();
        let submitted = author.client.execute_proposal(&submit).await.unwrap().value;
        approve(&fixture, &submitted, &review).await;
        let entity = &fixture.registry.entities()["facility"];
        // Independent changes isolate the revision and field predicates. The
        // synthetic administrative update is deliberately outside runtime writes.
        let update = if stale_revision {
            "record_revision=record_revision+1".into()
        } else {
            format!("\"{}\"='inactive'", entity.fields["status"].physical_name)
        };
        fixture
            .database
            .admin
            .execute(
                &format!(
                    "UPDATE registry_data.\"{}\" SET {update} WHERE record_id=$1",
                    entity.physical_table
                ),
                &[&Uuid::parse_str(&facility).unwrap()],
            )
            .await
            .unwrap();
        assert!(fixture
            .mutations
            .run_automatic_proposal_once_for_test()
            .await
            .unwrap());
        assert_eq!(
            author
                .client
                .read_proposal(&submitted)
                .await
                .unwrap()
                .value
                .state(),
            BRegProposalState::Submitted
        );
        assert_eq!(
            address(&fixture, &facility).await.0,
            "1 Main Road",
            "failed current guard cannot apply frozen writes"
        );
        assert_eq!(
            fixture
                .database
                .admin
                .query_one(
                    "SELECT count(*)::bigint FROM registry_internal.registry_proposal_applications",
                    &[]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        if !stale_revision {
            fixture
                .database
                .admin
                .execute(
                    &format!(
                        "UPDATE registry_data.\"{}\" SET \"{}\"='active' WHERE record_id=$1",
                        entity.physical_table, entity.fields["status"].physical_name
                    ),
                    &[&Uuid::parse_str(&facility).unwrap()],
                )
                .await
                .unwrap();
        }
        let current = author.client.read_proposal(&submitted).await.unwrap().value;
        let revise = author
            .client
            .prepare_proposal(&current, "revise", json!({}), &key("facility-revise"))
            .unwrap();
        let revised = author.client.execute_proposal(&revise).await.unwrap().value;
        let rebase = author
            .client
            .prepare_proposal(
                &revised,
                "rebase",
                json!({"input":correction_input(&facility,"50000")}),
                &key("facility-rebase"),
            )
            .unwrap();
        let rebased = author.client.execute_proposal(&rebase).await.unwrap().value;
        let submit = author
            .client
            .prepare_proposal(&rebased, "submit", json!({}), &key("facility-resubmit"))
            .unwrap();
        let resubmitted = author.client.execute_proposal(&submit).await.unwrap().value;
        assert_eq!(resubmitted.submission_version(), 2);
        assert_ne!(resubmitted.effect_digest(), submitted.effect_digest());
        assert_frozen_plan(&fixture, &resubmitted, &facility).await;
        approve(&fixture, &resubmitted, &review).await;
        assert!(fixture
            .mutations
            .run_automatic_proposal_once_for_test()
            .await
            .unwrap());
        assert_eq!(
            author
                .client
                .read_proposal(&resubmitted)
                .await
                .unwrap()
                .value
                .state(),
            BRegProposalState::Applied
        );
        assert_eq!(address(&fixture, &facility).await.0, "3 Civic Road");
        drop(author);
        fixture.finish().await;
    }
}
