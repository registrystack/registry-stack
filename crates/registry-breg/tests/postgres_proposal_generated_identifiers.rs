// SPDX-License-Identifier: Apache-2.0
//! Generated business identifiers in durable Proposal submissions.
#![cfg(feature = "postgres-test")]

#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use registry_breg::api::{VerifiedClaimValue, VerifiedRequestClaims};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg_client::{
    BRegActionInvocationRequest, BRegIdempotencyKey, BRegProblemCode, BRegProposalState,
    BRegRecordOptions,
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

fn claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated_with_actor_kind(
        "sub",
        "proposal-author",
        BTreeSet::from(["proposal:manage".into()]),
        Some("registry-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string("zone-a").unwrap(),
        )]),
        registry_platform_oidc::ActorKind::Human,
    )
    .unwrap()
}

fn key(value: &str) -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(value).unwrap()
}

fn map(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn registry() -> registry_breg::CompiledRegistry {
    let source = json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
        "kind":"BRegProject",
        "project":{
            "id":"proposal-generated-identifiers",
            "version":"1",
            "defaultLanguage":"en",
            "canonicalBaseIri":"https://proposal-generated.example.test"
        },
        "package":{"sourceRevision":"proposal-generated-identifiers-test"},
        "datasets":[{"id":"directory"}],
        "recordTypes":[{
            "id":"target",
            "primaryDataset":"directory",
            "route":"targets",
            "mutationMode":"mutable",
            "mutationPolicy":{"create":"proposal-required"},
            "fields":[
                {"id":"code","type":"string","required":true,"maximumLength":32,
                    "classification":"internal","generate":{"type":"sequence","prefix":"SEQ-",
                    "minimumDigits":4,"scope":["jurisdiction"]}},
                {"id":"token","type":"string","required":true,"maximumLength":32,
                    "classification":"internal","generate":{"type":"random","prefix":"R-",
                    "length":8}},
                {"id":"name","type":"string","required":true,"maximumLength":64,
                    "classification":"internal"},
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,
                    "classification":"internal"}
            ]
        }],
        "actions":[
            {
                "id":"register-target",
                "execution":{"mode":"proposal","proposal":{
                    "review":{"type":"none"},
                    "application":{"mode":"automatic","maximumAttempts":3},
                    "retention":{"mode":"retain"}
                }},
                "inputs":[
                    {"id":"name","type":"string","required":true,"maximumLength":64,
                        "classification":"internal"},
                    {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,
                        "classification":"internal"}
                ],
                "plan":{"type":"fixed","effects":[{
                    "id":"create-target","target":{"recordType":"target"},"operation":"create",
                    "set":{"name":{"fromInput":"name"},
                        "jurisdiction":{"fromInput":"jurisdiction"}}
                }]}
            },
            {
                "id":"register-target-with-document",
                "execution":{"mode":"proposal","proposal":{
                    "review":{"type":"none"},
                    "application":{"mode":"manual"},
                    "retention":{"mode":"retain"},
                    "attachments":[{"id":"support","required":true,"maximumBytes":4096,
                        "contentTypes":["text/plain"],"classification":"restricted"}]
                }},
                "inputs":[
                    {"id":"name","type":"string","required":true,"maximumLength":64,
                        "classification":"internal"},
                    {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,
                        "classification":"internal"}
                ],
                "plan":{"type":"fixed","effects":[{
                    "id":"create-target","target":{"recordType":"target"},"operation":"create",
                    "set":{"name":{"fromInput":"name"},
                        "jurisdiction":{"fromInput":"jurisdiction"}}
                }]}
            }
        ],
        "accessProfiles":[{
            "id":"clerk","default":true,"principalClaim":"sub",
            "requiredScopes":["proposal:manage"],
            "requiredPurposes":["registry-administration"],
            "permissions":{
                "records":[{"recordType":"target","operations":["get"],
                    "readableFields":["code","token","name","jurisdiction"],
                    "writableFields":["name","jurisdiction"],
                    "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction",
                        "operator":"equals"}]}],
                "actions":[
                    {"action":"register-target","operations":["start"],
                        "targets":[{"recordType":"target","rowBoundaries":[{
                            "field":"jurisdiction","claim":"jurisdiction","operator":"equals"
                        }]}]},
                    {"action":"register-target-with-document","operations":["start"],
                        "targets":[{"recordType":"target","rowBoundaries":[{
                            "field":"jurisdiction","claim":"jurisdiction","operator":"equals"
                        }]}]}
                ],
                "proposals":[
                    {"action":"register-target",
                        "operations":["get","submit","revise","retry","apply"],"ownership":"caller",
                        "targets":[{"recordType":"target","rowBoundaries":[{
                            "field":"jurisdiction","claim":"jurisdiction","operator":"equals"
                        }]}]},
                    {"action":"register-target-with-document",
                        "operations":["get","edit","submit"],"ownership":"caller",
                        "readableAttachments":["support"],"writableAttachments":["support"],
                        "targets":[{"recordType":"target","rowBoundaries":[{
                            "field":"jurisdiction","claim":"jurisdiction","operator":"equals"
                        }]}]}
                ]
            }
        }]
    });
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("generated identifier Proposal project compiles")
}

async fn frozen_target(
    fixture: &client_http::ClientFixture,
    proposal_id: &str,
    submission_version: u32,
) -> (uuid::Uuid, Map<String, Value>) {
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT target_record_id, after_snapshot
             FROM registry_internal.registry_proposal_targets
             WHERE action_id='register-target' AND proposal_id=$1 AND submission_version=$2",
            &[
                &uuid::Uuid::parse_str(proposal_id).unwrap(),
                &i64::from(submission_version),
            ],
        )
        .await
        .unwrap();
    let Value::Object(after) = row.get::<_, Value>(1) else {
        panic!("Proposal target retains an object snapshot")
    };
    (row.get(0), after)
}

async fn allocation_state(fixture: &client_http::ClientFixture) -> (i64, i64, i64) {
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT
                (SELECT count(*)::bigint
                 FROM registry_internal.registry_generated_identifier_reservations),
                (SELECT count(*)::bigint
                 FROM registry_internal.registry_generated_identifier_counters),
                (SELECT COALESCE(max(next_value), 0)::bigint
                 FROM registry_internal.registry_generated_identifier_counters)",
            &[],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1), row.get(2))
}

async fn frozen_effect_fields(
    fixture: &client_http::ClientFixture,
    proposal_id: &str,
    submission_version: u32,
) -> BTreeMap<String, Value> {
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT snapshot
             FROM registry_internal.registry_proposal_submissions
             WHERE action_id='register-target' AND proposal_id=$1 AND submission_version=$2",
            &[
                &uuid::Uuid::parse_str(proposal_id).unwrap(),
                &i64::from(submission_version),
            ],
        )
        .await
        .unwrap();
    let snapshot = row.get::<_, Value>(0);
    snapshot["effects"][0]["fieldChanges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|change| {
            (
                change["field"].as_str().unwrap().to_owned(),
                change["after"]["value"].clone(),
            )
        })
        .collect()
}

#[test]
fn generated_identifier_proposal_fixture_compiles() {
    let registry = registry();
    let entity = &registry.entities()["target"];
    assert!(entity.fields["code"].generate.is_some());
    assert!(entity.fields["token"].generate.is_some());
    assert!(registry
        .actions()
        .actions
        .iter()
        .any(|action| { action.id == "register-target" && action.execution.is_proposal() }));
    assert!(registry.actions().actions.iter().any(|action| {
        action.id == "register-target-with-document" && action.execution.is_proposal()
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proposal_submit_freezes_generated_identifiers_and_recovery_never_allocates_again() {
    let fixture = client_http::ClientFixture::start(registry(), claims()).await;
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let action = metadata
        .value
        .select_action("register-target", "clerk")
        .unwrap();
    let document_action = metadata
        .value
        .select_action("register-target-with-document", "clerk")
        .unwrap();
    // Sequence increments survive transaction rollback, so this disposable
    // trigger proves the missing-attachment refusal happens after allocation.
    fixture
        .database
        .admin
        .batch_execute(
            "CREATE SEQUENCE registry_internal.generated_identifier_submit_probe;
             CREATE FUNCTION registry_internal.observe_generated_identifier_reservation()
             RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
             SET search_path=pg_catalog AS $body$
             BEGIN
               PERFORM nextval('registry_internal.generated_identifier_submit_probe');
               RETURN NEW;
             END $body$;
             REVOKE ALL ON FUNCTION registry_internal.observe_generated_identifier_reservation()
               FROM PUBLIC;
             CREATE TRIGGER observe_generated_identifier_reservation
             AFTER INSERT ON registry_internal.registry_generated_identifier_reservations
             FOR EACH ROW EXECUTE FUNCTION
               registry_internal.observe_generated_identifier_reservation()",
        )
        .await
        .unwrap();
    let missing_document = BRegActionInvocationRequest::new(
        &document_action,
        map(json!({"name":"Missing document","jurisdiction":"zone-a"})),
        None,
    )
    .unwrap();
    let missing_document_draft = client
        .start_proposal(
            &document_action,
            &missing_document,
            &key("generated-missing-document-start"),
        )
        .await
        .unwrap()
        .value;
    let missing_document_submit = client
        .prepare_proposal(
            &missing_document_draft,
            "submit",
            json!({}),
            &key("generated-missing-document-submit"),
        )
        .unwrap();
    assert_eq!(
        client
            .execute_proposal(&missing_document_submit)
            .await
            .unwrap_err()
            .problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    assert_eq!(
        fixture
            .database
            .admin
            .query_one(
                "SELECT last_value
                 FROM registry_internal.generated_identifier_submit_probe",
                &[],
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        2,
        "both generated fields were reserved before Submit failed"
    );
    assert_eq!(
        allocation_state(&fixture).await,
        (0, 0, 0),
        "a post-allocation Submit failure rolls back reservations and sequence state"
    );
    fixture
        .database
        .admin
        .batch_execute(
            "DROP TRIGGER observe_generated_identifier_reservation ON
               registry_internal.registry_generated_identifier_reservations;
             DROP FUNCTION registry_internal.observe_generated_identifier_reservation();
             DROP SEQUENCE registry_internal.generated_identifier_submit_probe",
        )
        .await
        .unwrap();

    let input = BRegActionInvocationRequest::new(
        &action,
        map(json!({"name":"First target","jurisdiction":"zone-a"})),
        None,
    )
    .unwrap();
    let draft = client
        .start_proposal(&action, &input, &key("generated-start"))
        .await
        .unwrap()
        .value;

    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("generated-submit-one"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    assert_eq!(submitted.state(), BRegProposalState::Submitted);
    let (first_record_id, first) =
        frozen_target(&fixture, submitted.id(), submitted.submission_version()).await;
    assert_eq!(first["code"], "SEQ-0001");
    assert_eq!(first["jurisdiction"], "zone-a");
    let first_token = first["token"].as_str().unwrap();
    assert!(first_token.starts_with("R-"));
    assert_eq!(first_token.len(), 10);
    assert!(first_token[2..].bytes().all(|byte| {
        registry_breg::contract::DEFAULT_GENERATED_IDENTIFIER_ALPHABET
            .as_bytes()
            .contains(&byte)
    }));
    let first_frozen =
        frozen_effect_fields(&fixture, submitted.id(), submitted.submission_version()).await;
    assert_eq!(first_frozen["code"], first["code"]);
    assert_eq!(first_frozen["token"], first["token"]);
    assert_eq!(allocation_state(&fixture).await, (2, 1, 2));

    let replay = client.execute_proposal(&submit).await.unwrap().value;
    assert_eq!(
        serde_json::to_value(&replay).unwrap(),
        serde_json::to_value(&submitted).unwrap()
    );
    assert_eq!(allocation_state(&fixture).await, (2, 1, 2));

    let revise = client
        .prepare_proposal(&submitted, "revise", json!({}), &key("generated-revise"))
        .unwrap();
    let revised = client.execute_proposal(&revise).await.unwrap().value;
    assert_eq!(revised.state(), BRegProposalState::Draft);
    let second_submit = client
        .prepare_proposal(&revised, "submit", json!({}), &key("generated-submit-two"))
        .unwrap();
    let second = client.execute_proposal(&second_submit).await.unwrap().value;
    let (second_record_id, second_target) =
        frozen_target(&fixture, second.id(), second.submission_version()).await;
    assert_ne!(first_record_id, second_record_id);
    assert_eq!(second_target["code"], "SEQ-0002");
    assert_ne!(second_target["token"], first["token"]);
    assert_ne!(second.effect_digest(), submitted.effect_digest());
    let second_frozen =
        frozen_effect_fields(&fixture, second.id(), second.submission_version()).await;
    assert_eq!(second_frozen["code"], second_target["code"]);
    assert_eq!(second_frozen["token"], second_target["token"]);
    assert_eq!(allocation_state(&fixture).await, (4, 1, 3));

    let table = &fixture.registry.entities()["target"].physical_table;
    fixture
        .database
        .admin
        .batch_execute(&format!(
            "CREATE FUNCTION registry_internal.fail_generated_identifier_apply()
             RETURNS trigger LANGUAGE plpgsql AS $body$
             BEGIN RAISE EXCEPTION 'forced generated identifier Apply failure'; END $body$;
             CREATE TRIGGER fail_generated_identifier_apply
             BEFORE INSERT ON registry_data.\"{table}\"
             FOR EACH ROW EXECUTE FUNCTION registry_internal.fail_generated_identifier_apply()"
        ))
        .await
        .unwrap();
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let proposal_id = uuid::Uuid::parse_str(second.id()).unwrap();
    let failed_job = fixture
        .database
        .admin
        .query_one(
            "SELECT state, attempt_count, last_error_code
             FROM registry_internal.registry_proposal_application_jobs
             WHERE action_id='register-target' AND proposal_id=$1 AND submission_version=$2",
            &[&proposal_id, &i64::from(second.submission_version())],
        )
        .await
        .unwrap();
    assert_eq!(failed_job.get::<_, String>(0), "queued");
    assert_eq!(failed_job.get::<_, i32>(1), 1);
    assert_eq!(failed_job.get::<_, String>(2), "dependency-outage");
    assert_eq!(allocation_state(&fixture).await, (4, 1, 3));
    assert_eq!(
        frozen_target(&fixture, second.id(), second.submission_version()).await,
        (second_record_id, second_target.clone())
    );

    // Transient failures are normally retried automatically. Put the genuine
    // failed job into the operator-blocked state used when an operator elects
    // to resume it through the Proposal Retry operation.
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_application_jobs
             SET state='blocked'
             WHERE action_id='register-target' AND proposal_id=$1 AND submission_version=$2",
            &[&proposal_id, &i64::from(second.submission_version())],
        )
        .await
        .unwrap();
    let blocked = client.read_proposal(&second).await.unwrap().value;
    let retry = client
        .prepare_proposal(&blocked, "retry", json!({}), &key("generated-retry"))
        .unwrap();
    let retried = client.execute_proposal(&retry).await.unwrap().value;
    assert_eq!(retried.state(), BRegProposalState::Submitted);
    assert_eq!(retried.submission_version(), second.submission_version());
    assert_eq!(retried.effect_digest(), second.effect_digest());
    assert_eq!(allocation_state(&fixture).await, (4, 1, 3));
    assert_eq!(
        frozen_target(&fixture, retried.id(), retried.submission_version()).await,
        (second_record_id, second_target.clone())
    );

    fixture
        .database
        .admin
        .batch_execute(&format!(
            "DROP TRIGGER fail_generated_identifier_apply ON registry_data.\"{table}\";
             DROP FUNCTION registry_internal.fail_generated_identifier_apply()"
        ))
        .await
        .unwrap();
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let applied = client.read_proposal(&retried).await.unwrap().value;
    assert_eq!(applied.state(), BRegProposalState::Applied);
    assert_eq!(applied.submission_version(), second.submission_version());
    assert_eq!(applied.effect_digest(), second.effect_digest());
    assert_eq!(allocation_state(&fixture).await, (4, 1, 3));

    let record = client
        .get_record(
            "targets",
            &second_record_id.to_string(),
            &BRegRecordOptions::default()
                .access_profile("clerk")
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(record.value.data.domain_data["code"], second_target["code"]);
    assert_eq!(
        record.value.data.domain_data["token"],
        second_target["token"]
    );
    assert_eq!(record.value.data.domain_data["name"], "First target");
    assert_eq!(
        record.value.data.record_identifier,
        second_record_id.to_string(),
        "generated business identifiers do not replace the canonical record UUID"
    );

    fixture.finish().await;
}
