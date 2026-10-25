// SPDX-License-Identifier: Apache-2.0
//! Successor activation preserves one usable public recovery path for pending Proposals.
#![cfg(feature = "postgres-test")]

#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;
#[cfg(feature = "tooling")]
#[path = "support/proposal_activation.rs"]
mod proposal_activation;

use registry_breg::api::{VerifiedClaimValue, VerifiedRequestClaims};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::proposal_retention::ProposalRetentionError;
use registry_breg_client::{
    BRegActionInvocationRequest, BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey,
    BRegProposal, BRegProposalQuery, BRegProposalState, BRegRecordFormat,
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

fn claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated_with_actor_kind(
        "sub",
        "author",
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

fn registry_source() -> Value {
    json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
        "kind":"BRegProject",
        "project":{
            "id":"proposal-recovery-permissions",
            "version":"1",
            "defaultLanguage":"en",
            "canonicalBaseIri":"https://proposal-recovery.example.test"
        },
        "datasets":[{"id":"directory"}],
        "recordTypes":[{
            "id":"target",
            "primaryDataset":"directory",
            "route":"targets",
            "mutationMode":"mutable",
            "mutationPolicy":{"patch":"proposal-required"},
            "fields":[
                {"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,"classification":"internal"}
            ]
        }],
        "actions":[{
            "id":"correct-name",
            "execution":{"mode":"proposal","proposal":{
                "review":{"type":"none"},
                "application":{"mode":"manual"},
                "retention":{"mode":"retain"}
            }},
            "inputs":[
                {"id":"target","type":"reference","target":"target","required":true,"classification":"internal"},
                {"id":"value","type":"string","required":true,"maximumLength":64,"classification":"internal"}
            ],
            "commitGuards":{"targets":[{"input":"target","revision":"unchanged"}]},
            "plan":{"type":"fixed","effects":[{
                "id":"name",
                "target":{"fromInput":"target"},
                "operation":"patch",
                "set":{"name":{"fromInput":"value"}}
            }]}
        }],
        "accessProfiles":[{
            "id":"clerk",
            "default":true,
            "principalClaim":"sub",
            "requiredScopes":["proposal:manage"],
            "requiredPurposes":["registry-administration"],
            "permissions":{
                "records":[{
                    "recordType":"target",
                    "operations":["create","get","list"],
                    "readableFields":["name","jurisdiction"],
                    "writableFields":["name","jurisdiction"],
                    "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
                }],
                "actions":[{
                    "action":"correct-name",
                    "operations":["start"],
                    "targets":[{
                        "recordType":"target",
                        "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
                    }]
                }],
                "proposals":[{
                    "action":"correct-name",
                    "operations":["get","list","edit","submit","revise","rebase","retry","cancel","apply"],
                    "ownership":"caller",
                    "targets":[{
                        "recordType":"target",
                        "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
                    }]
                }]
            }
        }]
    })
}

fn compile(source: &Value) -> registry_breg::CompiledRegistry {
    let project = parse_project_json(&serde_json::to_vec(source).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("Proposal recovery fixture compiles")
}

fn set_operations(profile: &mut Value, operations: Value) {
    profile["permissions"]["proposals"][0]["operations"] = operations;
}

fn add_profile(source: &mut Value, id: &str, operations: Value) {
    let mut profile = source["accessProfiles"][0].clone();
    profile["id"] = json!(id);
    profile["default"] = json!(false);
    profile["permissions"]["records"] = json!([]);
    profile["permissions"]["actions"] = json!([]);
    set_operations(&mut profile, operations);
    source["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .push(profile);
}

fn split_recovery_source(source: &Value) -> Value {
    let mut candidate = source.clone();
    set_operations(&mut candidate["accessProfiles"][0], json!(["get"]));
    add_profile(&mut candidate, "canceller", json!(["cancel"]));
    candidate
}

fn listed_recovery_source(source: &Value) -> Value {
    let mut candidate = source.clone();
    set_operations(&mut candidate["accessProfiles"][0], json!(["get"]));
    add_profile(
        &mut candidate,
        "recovery-operator",
        json!(["list", "cancel"]),
    );
    candidate
}

async fn start_proposal(fixture: &client_http::ClientFixture) -> BRegProposal {
    let metadata = fixture
        .http
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("target create route must be direct");
    };
    let record = fixture
        .http
        .client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(json!({
                "name":"Before",
                "jurisdiction":"zone-a"
            })))
            .unwrap(),
            &key("recovery-permissions-record"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        map(json!({
            "target":record.value.data.record_identifier,
            "value":"After"
        })),
        None,
    )
    .unwrap();
    fixture
        .http
        .client
        .start_proposal(&action, &input, &key("recovery-permissions-start"))
        .await
        .unwrap()
        .value
}

async fn submit_proposal(
    fixture: &client_http::ClientFixture,
    draft: &BRegProposal,
) -> BRegProposal {
    let submit = fixture
        .http
        .client
        .prepare_proposal(
            draft,
            "submit",
            json!({}),
            &key("recovery-permissions-submit"),
        )
        .unwrap();
    fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value
}

fn assert_same_action_revision(
    original: &registry_breg::CompiledRegistry,
    candidate: &registry_breg::CompiledRegistry,
) {
    assert_eq!(
        original.actions().actions[0].definition_revision,
        candidate.actions().actions[0].definition_revision,
        "permission-only successors must not reinterpret the frozen Action"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn successor_recovery_requires_one_profile_with_a_condition_source_and_cancel() {
    let source = registry_source();
    let original = compile(&source);
    let fixture = client_http::ClientFixture::start(original.clone(), claims()).await;
    let _draft = start_proposal(&fixture).await;

    let mut get_and_cancel = source.clone();
    set_operations(
        &mut get_and_cancel["accessProfiles"][0],
        json!(["get", "cancel"]),
    );
    let get_and_cancel = compile(&get_and_cancel);
    assert_same_action_revision(&original, &get_and_cancel);
    registry_breg::proposal_retention::guard_successor_activation(
        &fixture.database.admin,
        &get_and_cancel,
    )
    .await
    .expect("one profile can recover through Get and Cancel");

    let list_and_cancel = compile(&listed_recovery_source(&source));
    assert_same_action_revision(&original, &list_and_cancel);
    registry_breg::proposal_retention::guard_successor_activation(
        &fixture.database.admin,
        &list_and_cancel,
    )
    .await
    .expect("one profile can recover through a promoted List condition and Cancel");

    let split = compile(&split_recovery_source(&source));
    assert_same_action_revision(&original, &split);
    assert_eq!(
        registry_breg::proposal_retention::guard_successor_activation(
            &fixture.database.admin,
            &split,
        )
        .await,
        Err(ProposalRetentionError::ActiveProposalRecoveryUnavailable),
        "Get and Cancel in different authority contexts cannot produce a usable condition"
    );

    fixture.finish().await;
}

#[cfg(feature = "tooling")]
struct ActiveReady;

#[cfg(feature = "tooling")]
impl registry_breg::api::ReadinessProbe for ActiveReady {
    fn is_ready(&self) -> registry_breg::api::ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

#[cfg(feature = "tooling")]
async fn successor_client(
    fixture: &client_http::ClientFixture,
    registry: registry_breg::CompiledRegistry,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
) -> client_http::ClientHttp {
    use registry_breg::api::{HttpService, ReadRuntimeIdentity};
    use registry_breg::postgres::{
        PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    };
    use std::sync::Arc;

    let registry = Arc::new(registry);
    let lock = RegistryLockKey::derive(registry.registry_id()).unwrap();
    let audit = registry_breg::audit::test_support::capturing(
        registry_platform_audit::AuditProfile::production_from_secret_bytes(vec![0x61; 32].into())
            .unwrap(),
    )
    .0;
    let cursors = Arc::new(
        registry_breg::cursor::CursorCodec::new(
            zeroize::Zeroizing::new(vec![0x62; 32]),
            std::time::Duration::from_secs(300),
        )
        .unwrap(),
    );
    let records = PostgresRecordReadService::new(
        fixture.pool.clone(),
        registry.clone(),
        identity.clone(),
        lock,
        std::time::Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    );
    let mutations = PostgresRecordMutationService::new(
        fixture.pool.clone(),
        registry.clone(),
        identity.clone(),
        "proposal-recovery-permissions-test",
        lock,
        std::time::Duration::from_secs(2),
        audit,
    );
    let service = HttpService::new(
        registry,
        ReadRuntimeIdentity {
            package_revision: identity.activation_id,
            schema_fingerprint: identity.schema_fingerprint,
        },
        Arc::new(records),
        Arc::new(ActiveReady),
        cursors,
    )
    .with_postgres_mutations(Arc::new(mutations));
    client_http::ClientHttp::start(registry_breg::api::router(Arc::new(service)), claims()).await
}

#[cfg(feature = "tooling")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refused_split_recovery_successor_preserves_activation_and_pending_work() {
    use registry_breg::migration::{
        apply_verified_package, ActivationDeployment, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
        ApplyVerifiedPackageRequest, MigrationError,
    };
    use std::time::Duration;

    let source = registry_source();
    let original = compile(&source);
    let fixture = client_http::ClientFixture::start(original.clone(), claims()).await;
    let draft = start_proposal(&fixture).await;
    let submitted = submit_proposal(&fixture, &draft).await;
    let split = split_recovery_source(&source);
    assert_same_action_revision(&original, &compile(&split));
    let package = proposal_activation::verified_successor(
        &fixture,
        &fixture.registry,
        &fixture.identity,
        &split,
    )
    .await;
    let before = fixture
        .database
        .admin
        .query_one(
            "SELECT maintenance_status,maintenance_target_package_digest,
                (SELECT count(*)::bigint FROM registry_internal.registry_migrations)
             FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .unwrap();
    let before_status: String = before.get(0);
    let before_target: Option<String> = before.get(1);
    let before_activations: i64 = before.get(2);

    let request = ApplyVerifiedPackageRequest::new(
        &fixture.database.migration_config,
        &package,
        ActivationDeployment::new(
            "local",
            "proposal-recovery-permissions-test",
            &fixture.identity.database_id,
        ),
        ApplyPrecondition::Successor {
            current: &fixture.identity,
        },
        ApplyRoles::new(
            &fixture.database.migration_role,
            &fixture.database.runtime_role,
        ),
        ApplyTimeouts::new(Duration::from_secs(2), Duration::from_secs(10)).unwrap(),
        fixture.database.activation_audit(),
    );
    assert_eq!(
        apply_verified_package(request).await,
        Err(MigrationError::ActiveProposalRecoveryUnavailable)
    );

    let after = fixture
        .database
        .admin
        .query_one(
            "SELECT maintenance_status,maintenance_target_package_digest,
                (SELECT count(*)::bigint FROM registry_internal.registry_migrations),
                EXISTS (SELECT 1 FROM registry_internal.registry_migrations WHERE package_digest=$1)
             FROM registry_internal.registry_state WHERE singleton",
            &[&package.package_digest()],
        )
        .await
        .unwrap();
    assert_eq!(after.get::<_, String>(0), before_status);
    assert_eq!(after.get::<_, Option<String>>(1), before_target);
    assert_eq!(after.get::<_, i64>(2), before_activations);
    assert!(
        !after.get::<_, bool>(3),
        "refusal must not install a ledger row"
    );

    let current = fixture
        .http
        .client
        .read_proposal(&submitted)
        .await
        .unwrap()
        .value;
    assert_eq!(current.state(), BRegProposalState::Submitted);
    assert_eq!(current.revision(), submitted.revision());
    assert_eq!(current.effect_digest(), submitted.effect_digest());
    assert!(current.blocked_reason().is_none());

    fixture.finish().await;
}

#[cfg(feature = "tooling")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn listed_recovery_profile_cancels_after_real_successor_activation() {
    let source = registry_source();
    let original = compile(&source);
    let fixture = client_http::ClientFixture::start(original.clone(), claims()).await;
    let draft = start_proposal(&fixture).await;
    let submitted = submit_proposal(&fixture, &draft).await;
    let candidate = listed_recovery_source(&source);
    assert_same_action_revision(&original, &compile(&candidate));

    let (registry, identity) = proposal_activation::activate_successor(&fixture, &candidate).await;
    assert_ne!(identity.activation_id, fixture.identity.activation_id);
    let current = successor_client(&fixture, registry, identity).await;
    let metadata = current
        .client
        .registry_contract(Some("recovery-operator"))
        .await
        .unwrap();
    let collection = metadata
        .value
        .select_proposals("recovery-operator")
        .unwrap();
    let listed = current
        .client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap()
        .value
        .items
        .into_iter()
        .find(|proposal| proposal.id() == submitted.id())
        .expect("List returns the pending Proposal under the recovery profile");
    assert!(
        listed
            .link("cancel")
            .and_then(|link| link.availability())
            .is_none_or(|availability| availability.available),
        "List promotes a usable same-profile Cancel condition"
    );
    let cancel = current
        .client
        .prepare_proposal(
            &listed,
            "cancel",
            json!({}),
            &key("recovery-permissions-cancel"),
        )
        .unwrap();
    let cancelled = current
        .client
        .execute_proposal(&cancel)
        .await
        .unwrap()
        .value;
    assert_eq!(cancelled.state(), BRegProposalState::Cancelled);
    assert_eq!(cancelled.revision(), submitted.revision() + 1);

    let clerk_metadata = current
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let get = clerk_metadata.value.select_proposal_get("clerk").unwrap();
    let observed = current
        .client
        .get_proposal(&get, submitted.id())
        .await
        .unwrap()
        .value;
    assert_eq!(observed.state(), BRegProposalState::Cancelled);
    assert_eq!(observed.revision(), cancelled.revision());

    drop(current);
    fixture.finish().await;
}
