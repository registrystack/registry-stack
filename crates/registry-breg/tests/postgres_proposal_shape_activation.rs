// SPDX-License-Identifier: Apache-2.0
//! Reviewed record shapes remain bound across governed successor activation.
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
    BRegActionInvocationRequest, BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey,
    BRegRecordFormat,
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
fn claims(subject: &str, jurisdiction: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated_with_actor_kind(
        "sub",
        subject,
        BTreeSet::from(["proposal:manage".into()]),
        Some("registry-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string(jurisdiction).unwrap(),
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
fn registry_source(automatic: bool) -> Value {
    let source = json!({"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"proposal-test","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://proposal.example.test"},
        "datasets":[{"id":"directory"}],
        "recordTypes":[{"id":"target","primaryDataset":"directory","route":"targets","mutationMode":"mutable",
            "mutationPolicy":{"patch":"proposal-required"},
            "fields":[{"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,"classification":"internal"}]}],
        "actions":[{"id":"correct-name","execution":{"mode":"proposal","proposal":{
            "review":{"type":"none"},"application":if automatic{json!({"mode":"automatic","maximumAttempts":3})}else{json!({"mode":"manual"})},
            "retention":{"mode":"operator-erase"},"attachments":[{"id":"support","required":false,"maximumBytes":4096,
                "contentTypes":["text/plain"],"classification":"restricted"}]}},
            "inputs":[{"id":"target","type":"reference","target":"target","required":true,"classification":"internal"},
                {"id":"value","type":"string","required":true,"maximumLength":64,"classification":"internal"}],
            "commitGuards":{"targets":[{"input":"target","revision":"unchanged"}]},
            "plan":{"type":"fixed","effects":[{"id":"name","target":{"fromInput":"target"},"operation":"patch","set":{"name":{"fromInput":"value"}}}]}}],
        "accessProfiles":[{"id":"clerk","default":true,"principalClaim":"sub","requiredScopes":["proposal:manage"],
            "requiredPurposes":["registry-administration"],"permissions":{
                "records":[{"recordType":"target","operations":["create","get","list"],"readableFields":["name","jurisdiction"],
                    "writableFields":["name","jurisdiction"],"rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}],
                "actions":[{"action":"correct-name","operations":["start"],"targets":[{"recordType":"target",
                    "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]}],
                "proposals":[{"action":"correct-name","operations":["get","list","edit","submit","revise","rebase","retry","cancel","apply"],
                    "ownership":"caller","readableAttachments":["support"],"writableAttachments":["support"],"targets":[{"recordType":"target",
                    "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]}]}}]});
    source
}
fn compile(source: Value) -> registry_breg::CompiledRegistry {
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).expect("standalone Proposal compiles")
}
async fn start(
    fixture: &client_http::ClientFixture,
    value: &str,
    key_name: &str,
) -> registry_breg_client::BRegProposal {
    start_action(fixture, "correct-name", value, key_name).await
}

async fn start_action(
    fixture: &client_http::ClientFixture,
    action_id: &str,
    value: &str,
    key_name: &str,
) -> registry_breg_client::BRegProposal {
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create");
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(json!({"name":"Before","jurisdiction":"zone-a"}))).unwrap(),
            &key(&format!("{key_name}-record")),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let action = metadata.value.select_action(action_id, "clerk").unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        map(json!({"target":record.value.data.record_identifier,"value":value})),
        None,
    )
    .unwrap();
    client
        .start_proposal(&action, &input, &key(key_name))
        .await
        .unwrap()
        .value
}

struct ActiveReady;
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
    authorities: std::sync::Arc<registry_breg::review_store::ReviewAuthorityRegistry>,
) -> client_http::ClientHttp {
    client_with_audit_key(
        fixture,
        registry,
        identity,
        0x61,
        claims("author", "zone-a"),
        authorities,
    )
    .await
}
async fn client_with_audit_key(
    fixture: &client_http::ClientFixture,
    registry: registry_breg::CompiledRegistry,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    audit_key: u8,
    caller: VerifiedRequestClaims,
    authorities: std::sync::Arc<registry_breg::review_store::ReviewAuthorityRegistry>,
) -> client_http::ClientHttp {
    use registry_breg::api::{HttpService, ReadRuntimeIdentity};
    use registry_breg::postgres::{
        PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    };
    use std::sync::Arc;
    let registry = Arc::new(registry);
    let lock = RegistryLockKey::derive(registry.registry_id()).unwrap();
    let audit = registry_breg::audit::test_support::capturing(
        registry_platform_audit::AuditProfile::production_from_secret_bytes(
            vec![audit_key; 32].into(),
        )
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
        "client-capability-test",
        lock,
        std::time::Duration::from_secs(2),
        audit,
    )
    .with_review_result_source(authorities);
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
    client_http::ClientHttp::start(registry_breg::api::router(Arc::new(service)), caller).await
}

#[derive(Clone, Copy, Debug)]
enum Change {
    OptionalField,
    Pattern,
    Type,
    Classification,
    Required,
    PolicyOnly,
    DisplayOnly,
}

async fn shape_journey(change: Change) {
    use registry_breg::migration::*;
    let mut source = registry_source(false);
    source["accessProfiles"][0]["permissions"]["proposals"][0]["readableInputs"] =
        json!(["target", "value"]);
    source["recordTypes"][0]["fields"][0]["required"] = json!(false);
    source["recordTypes"][0]["fields"][0]["pattern"] = json!("^.*$");
    source["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"note","type":"boolean","required":false,"classification":"internal"}));
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let policy =
        json!({"id":"name-correction","version":"1","digest":format!("sha256:{}", "b".repeat(64))});
    let review_source = if matches!(&change, Change::DisplayOnly) {
        "shared.facility.registry:v1"
    } else {
        "proposal-test"
    };
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":review_source,"policy":policy});
    let authority = shape_authority::LocalAuthority::start_for_registry(
        serde_json::from_value(policy).unwrap(),
        review_source,
    )
    .await;
    let configured = authority.registry.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source.clone()),
        claims("author", "zone-a"),
        move |m| m.with_review_result_source(configured),
    )
    .await;
    let approved = start(&fixture, "After approved", "approved-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&approved, "submit", json!({}), &key("approved-submit"))
        .unwrap();
    let approved = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    for _ in 0..2 {
        assert!(
            registry_breg::review_store::run_review_authority_once_for_test(
                &fixture.pool,
                &authority.registry,
                &fixture.mutations
            )
            .await
            .unwrap()
        );
    }
    let reviewing = start(&fixture, "After reviewing", "reviewing-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&reviewing, "submit", json!({}), &key("reviewing-submit"))
        .unwrap();
    let reviewing = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    assert!(
        registry_breg::review_store::run_review_authority_once_for_test(
            &fixture.pool,
            &authority.registry,
            &fixture.mutations
        )
        .await
        .unwrap()
    );
    let counts = fixture.database.admin.query_one("SELECT (SELECT count(*) FROM registry_internal.registry_proposal_review_submissions WHERE state='accepted'), (SELECT count(*) FROM registry_internal.registry_proposal_review_results WHERE status='approved'), (SELECT count(*) FROM registry_internal.registry_proposal_applications)", &[]).await.unwrap();
    assert_eq!(
        counts.get::<_, i64>(0),
        2,
        "both reviews reached the authority"
    );
    assert_eq!(
        counts.get::<_, i64>(1),
        1,
        "only the first request is approved"
    );
    assert_eq!(counts.get::<_, i64>(2), 0, "neither request applied");
    if !matches!(change, Change::DisplayOnly) {
        source["actions"][0]["execution"]["proposal"]["review"]["policy"]["digest"] =
            json!(format!("sha256:{}", "c".repeat(64)));
    }
    match change {
        Change::OptionalField => source["recordTypes"][0]["fields"]
            .as_array_mut()
            .unwrap()
            .push(
                json!({"id":"extra","type":"boolean","required":false,"classification":"internal"}),
            ),
        Change::Pattern => source["recordTypes"][0]["fields"][0]["pattern"] = json!("^[AB].*$"),
        Change::Type => source["recordTypes"][0]["fields"][2]["type"] = json!("int64"),
        Change::Classification => {
            source["recordTypes"][0]["fields"][2]["classification"] = json!("restricted")
        }
        Change::Required => source["recordTypes"][0]["fields"][0]["required"] = json!(true),
        Change::PolicyOnly => {}
        Change::DisplayOnly => {
            source["actions"][0]["display"] = json!({"label":"A display-only update"})
        }
    }
    let candidate = shape_package::candidate(&fixture, &source).await;
    let inventory = registry_breg::proposal_retention::prepare_proposal_activation_compatibility(
        &fixture.pool,
        &fixture.identity,
        &candidate,
        &authority.registry,
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let binding_file = shape_package::backup(directory.path(), &fixture.identity);
    let evidence: Vec<_> = candidate
        .reviewed_migration_plan()
        .into_iter()
        .flat_map(|p| p.migrations())
        .filter_map(|m| m.descriptor.backup_binding_path.as_deref())
        .map(|path| DestructiveBackupEvidence::new(path, &binding_file))
        .collect();
    let plan = ApplyVerifiedPackageRequest::plan(
        &fixture.database.migration_config,
        &candidate,
        ActivationDeployment::new("local", "shape-test", &fixture.identity.database_id),
        ApplyPrecondition::Successor {
            current: &fixture.identity,
        },
        ApplyRoles::new(
            &fixture.database.migration_role,
            &fixture.database.runtime_role,
        ),
        ApplyTimeouts::new(Duration::from_secs(2), Duration::from_secs(10)).unwrap(),
    )
    .with_destructive_backup_evidence(&evidence)
    .with_proposal_activation_compatibility(&inventory);
    plan_verified_package(plan)
        .await
        .expect("shape successor plans without changing waiting work");
    let before: i64 = fixture.database.admin.query_one("SELECT count(*) FROM registry_internal.registry_proposal_state WHERE blocked_reason IS NOT NULL", &[]).await.unwrap().get(0);
    assert_eq!(before, 0, "planning does not block requests");
    let active = apply_verified_package(
        ApplyVerifiedPackageRequest::new(
            &fixture.database.migration_config,
            &candidate,
            ActivationDeployment::new("local", "shape-test", &fixture.identity.database_id),
            ApplyPrecondition::Successor {
                current: &fixture.identity,
            },
            ApplyRoles::new(
                &fixture.database.migration_role,
                &fixture.database.runtime_role,
            ),
            ApplyTimeouts::new(Duration::from_secs(2), Duration::from_secs(10)).unwrap(),
            fixture.database.activation_audit(),
        )
        .with_destructive_backup_evidence(&evidence)
        .with_proposal_activation_compatibility(&inventory),
    )
    .await
    .expect("valid shape successor activates");
    let current = successor_client(
        &fixture,
        candidate.registry().clone(),
        active,
        authority.registry.clone(),
    )
    .await;
    let metadata = current
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let get = metadata.value.select_proposal_get("clerk").unwrap();
    let shape_changed = !matches!(change, Change::PolicyOnly | Change::DisplayOnly);
    for original in [&approved, &reviewing] {
        let request = current
            .client
            .get_proposal(&get, original.id())
            .await
            .unwrap()
            .value;
        assert_eq!(
            request.blocked_reason(),
            shape_changed.then_some("package-changed"),
            "{change:?}"
        );
        assert_eq!(
            request.effect_digest(),
            original.effect_digest(),
            "activation preserves the frozen effects"
        );
        if shape_changed {
            let apply = request.link("apply").unwrap().availability().unwrap();
            assert!(!apply.available);
            assert_eq!(
                apply.reason,
                Some(registry_breg_client::BRegAvailabilityReason::ContractChanged)
            );
            let rebase = current
                .client
                .prepare_proposal(
                    &request,
                    "rebase",
                    json!({"input":request.input().unwrap()}),
                    &key(&format!("rebase-{}", original.id())),
                )
                .unwrap();
            let rebased = current
                .client
                .execute_proposal(&rebase)
                .await
                .unwrap()
                .value;
            assert_ne!(rebased.action_revision(), original.action_revision());
            assert_eq!(
                rebased.state(),
                registry_breg_client::BRegProposalState::Draft
            );
            let submit = current
                .client
                .prepare_proposal(
                    &rebased,
                    "submit",
                    json!({}),
                    &key(&format!("resubmit-{}", original.id())),
                )
                .unwrap();
            let resubmitted = current
                .client
                .execute_proposal(&submit)
                .await
                .unwrap()
                .value;
            assert_eq!(
                resubmitted.submission_version(),
                original.submission_version() + 1
            );
            let row = fixture.database.admin.query_one("SELECT q.state, q.accepted_binding, q.expected_policy, (SELECT count(*) FROM registry_internal.registry_proposal_review_results r WHERE r.proposal_id=q.proposal_id AND r.submission_version=q.submission_version) FROM registry_internal.registry_proposal_review_submissions q WHERE q.proposal_id=$1 ORDER BY q.submission_version DESC LIMIT 1", &[&uuid::Uuid::parse_str(rebased.id()).unwrap()]).await.unwrap();
            assert_eq!(
                row.get::<_, String>(0),
                "pending",
                "submitting the rebased draft queues fresh Review"
            );
            assert!(row.get::<_, Option<Value>>(1).is_none());
            assert_eq!(
                row.get::<_, Value>(2),
                source["actions"][0]["execution"]["proposal"]["review"]["policy"]
            );
            assert_eq!(row.get::<_, i64>(3), 0, "old approval cannot follow Rebase");
        }
    }
    let applications: i64 = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_proposal_applications",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(applications, 0);
    let entity = &fixture.registry.entities()["target"];
    let rows = fixture
        .database
        .admin
        .query(
            &format!(
                "SELECT \"{}\" FROM registry_data.\"{}\"",
                entity.fields["name"].physical_name, entity.physical_table
            ),
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter().all(|row| row.get::<_, String>(0) == "Before"),
        "no reviewed effect applied"
    );
    drop(current);
    fixture.finish().await;
}

#[tokio::test]
async fn optional_field_and_policy_change_cannot_retain_old_shape_approval() {
    shape_journey(Change::OptionalField).await;
}
#[tokio::test]
async fn tighter_pattern_and_policy_change_require_fresh_review() {
    shape_journey(Change::Pattern).await;
}
#[tokio::test]
async fn field_type_and_policy_change_require_fresh_review() {
    shape_journey(Change::Type).await;
}
#[tokio::test]
async fn classification_and_policy_change_require_fresh_review() {
    shape_journey(Change::Classification).await;
}
#[tokio::test]
async fn required_field_and_policy_change_require_fresh_review() {
    shape_journey(Change::Required).await;
}
#[tokio::test]
async fn policy_only_change_retains_review_compatibility() {
    shape_journey(Change::PolicyOnly).await;
}
#[tokio::test]
async fn unrelated_display_change_does_not_block_waiting_requests() {
    shape_journey(Change::DisplayOnly).await;
}
// The fixture authors reviewed migrations from public compiled change records.
// It rehearses real DDL and binds the resulting catalog before publication.
mod shape_package {
    use super::*;
    use registry_breg::migration_plan::*;
    use registry_breg::package::*;
    use registry_breg::postgres::*;
    use sha2::{Digest, Sha256};
    fn canonical(value: &impl serde::Serialize) -> Vec<u8> {
        registry_platform_canonical_json::canonicalize_json(&serde_json::to_value(value).unwrap())
            .unwrap()
    }
    fn digest(bytes: &[u8]) -> String {
        format!(
            "sha256:{}",
            Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    }

    fn reviewed(
        prior: &registry_breg::CompiledRegistry,
        candidate: &registry_breg::CompiledRegistry,
        current: &ExpectedRegistryIdentity,
        fingerprint: &str,
    ) -> Vec<ReviewedMigrationSource> {
        let changes = compiled_registry_change_set(prior, candidate, &current.package_digest);
        changes.changes.iter().filter(|c| c.class != CompiledRegistryChangeClass::CompatibleAdditive)
            .enumerate().map(|(index, change)| {
            let id = format!("shape-{index}");
            let base = format!("modules/core/migrations/{id}");
            let mut steps = vec![];
            let mut files = vec![];
            let mut sql_bindings = vec![];
            if matches!(change.code, CompiledRegistryChangeCode::FieldTypeChanged | CompiledRegistryChangeCode::FieldRequirednessChanged | CompiledRegistryChangeCode::FieldPatternChanged) {
                let entity = &candidate.entities()["target"];
                let field_id = change.target.member_id.as_ref().unwrap();
                let field = &entity.fields[field_id];
                let table = &entity.physical_table;
                let column = &field.physical_name;
                let (sql, kind, member_id, physical_name) = match change.code {
                    CompiledRegistryChangeCode::FieldRequirednessChanged => (
                        format!("ALTER TABLE registry_data.\"{table}\" ALTER COLUMN \"{column}\" SET NOT NULL"),
                        ReviewedMigrationObjectKind::Field, field_id.clone(), column.clone()),
                    CompiledRegistryChangeCode::FieldTypeChanged => (
                        format!("ALTER TABLE registry_data.\"{table}\" ALTER COLUMN \"{column}\" TYPE bigint USING NULL::bigint"),
                        ReviewedMigrationObjectKind::Field, field_id.clone(), column.clone()),
                    CompiledRegistryChangeCode::FieldPatternChanged => {
                        let name = registry_breg::generated_ddl::field_pattern_constraint_name("target", field_id);
                        let statement = candidate.ddl().statements.iter().find(|s| s.id == format!("entity.target.field.{field_id}.pattern")).unwrap();
                        let (_, constraint) = statement.sql.split_once(" ADD CONSTRAINT ").unwrap();
                        (format!("ALTER TABLE registry_data.\"{table}\" DROP CONSTRAINT \"{name}\", ADD CONSTRAINT {constraint}"),
                         ReviewedMigrationObjectKind::Constraint, format!("pattern:{field_id}"), name)
                    },
                    _ => unreachable!(),
                };
                let path = format!("{base}/steps/shape.sql");
                steps.push(ReviewedMigrationStepDescriptor::TransactionalSql { id: "shape".into(), sql_path: path.clone(),
                    objects: vec![ReviewedMigrationObject { schema: "registry_data".into(), table: table.clone(), entity_id: "target".into(), kind, member_id: Some(member_id), physical_name }], affected_rows: None });
                sql_bindings.push(ArtifactDigestBinding {path: path.clone(), sha256: digest(sql.as_bytes())});
                files.push(ReviewedMigrationFile {path, bytes: sql.into_bytes()});
            }
            let mut assertions = vec![];
            let mut assertion_bindings = vec![];
            if !steps.is_empty() {
                let entity = &candidate.entities()["target"];
                let sql = format!("SELECT pg_catalog.count(*) = 2 FROM registry_data.\"{}\" WHERE \"{}\" = 'Before' AND \"{}\" IS NULL", entity.physical_table, entity.fields["name"].physical_name, entity.fields["note"].physical_name);
                for id in ["pre", "post"] {
                    let path = format!("{base}/assertions/{id}.sql");
                    assertions.push(ReviewedMigrationAssertionDescriptor {id:id.into(),sql_path:path.clone()});
                    assertion_bindings.push(ArtifactDigestBinding {path:path.clone(),sha256:digest(sql.as_bytes())});
                    files.push(ReviewedMigrationFile {path,bytes:sql.as_bytes().to_vec()});
                }
            }
            let descriptor = ReviewedMigrationDescriptor { id, change_class: change.class,
                covers: vec![ReviewedChangeCover::from(change)], recovery: ReviewedMigrationRecovery::ExactTargetResume,
                lock_timeout_ms: 2000, statement_timeout_ms: 10000, steps, pre_assertions: assertions.iter().take(1).cloned().collect(), post_assertions: assertions.iter().skip(1).cloned().collect(),
                rehearsal_receipt_path: format!("{base}/rehearsal.json"),
                backup_binding_path: (change.class == CompiledRegistryChangeClass::DestructiveOrIrreversible).then(|| format!("{base}/backup.json")), history: None };
            let bytes = canonical(&descriptor);
            let fixture_bytes = b"{\"canary\":\"shape\"}\n";
            let fixture_path = format!("{base}/fixtures/shape.jsonl");
            let receipt = MigrationRehearsalReceipt { prior_package_digest: current.package_digest.clone(),
                prior_schema_fingerprint: current.schema_fingerprint.clone(), plan_sha256: digest(&bytes), sql_sha256: sql_bindings,
                assertion_sha256: assertion_bindings, fixture_inventory: vec![RehearsalFixture {id:"shape".into(), path: fixture_path.clone(), sha256: digest(fixture_bytes), row_count: 1}],
                postgres_major: 17, row_assertions: vec![], final_schema_fingerprint: fingerprint.into() };
            files.push(ReviewedMigrationFile {path: fixture_path, bytes: fixture_bytes.to_vec()});
            files.push(ReviewedMigrationFile {path: descriptor.rehearsal_receipt_path.clone(), bytes: canonical(&receipt)});
            ReviewedMigrationSource {module_id:"core".into(), descriptor: ReviewedMigrationFile {path:format!("{base}/descriptor.json"), bytes}, files}
        }).collect()
    }
    fn prepare(
        fixture: &client_http::ClientFixture,
        source: &Value,
        fingerprint: &str,
    ) -> PreparedPackage {
        let mut source = source.clone();
        source["package"] = json!({"sourceRevision":"0".repeat(40)});
        let bytes = serde_json::to_vec(&source).unwrap();
        let candidate = compile_project(
            &parse_project_json(&bytes).unwrap(),
            &[],
            CompileProfile::Production,
        )
        .unwrap();
        let migrations = reviewed(
            &fixture.registry,
            &candidate,
            &fixture.identity,
            fingerprint,
        );
        let migration_plan = if migrations.is_empty() {
            PackageMigrationPlanInput::Successor {
                prior_registry: Box::new((*fixture.registry).clone()),
            }
        } else {
            PackageMigrationPlanInput::ReviewedSuccessor {
                prior_registry: Box::new((*fixture.registry).clone()),
                prior_schema_fingerprint: fixture.identity.schema_fingerprint.clone(),
                migrations,
            }
        };
        let journeys = json!({"apiVersion":"id.registrystack.org/formats/breg/journeys/v1","kind":"BRegJourneys","journeys":[{"id":"list-targets","steps":[{"id":"list","recordType":"target","accessProfile":"clerk","claims":{"principal":"canary","scopes":["proposal:manage"],"purpose":"registry-administration","directClaims":{"jurisdiction":"zone-a"}},"request":{"type":"list"},"expect":{"outcome":"success","status":200,"count":0}}]}]});
        prepare_package(PackageBuildRequest {
            from_package_digest: Some(fixture.identity.package_digest.clone()),
            compiler_source_revision: "0".repeat(40),
            schema_fingerprint: fingerprint.into(),
            project: PackageSourceFile {
                path: "source/registry.yaml".into(),
                bytes,
            },
            modules: vec![],
            fixture_journeys: PackageSourceFile {
                path: "tests/journeys.yaml".into(),
                bytes: serde_json::to_vec(&journeys).unwrap(),
            },
            migration_plan,
        })
        .expect("shape successor prepares")
    }
    pub async fn candidate(
        fixture: &client_http::ClientFixture,
        source: &Value,
    ) -> VerifiedPackage {
        let prepared = prepare(fixture, source, &fixture.identity.schema_fingerprint);
        let (mut migration, task) = fixture.database.connect_migration().await;
        let tx = migration.transaction().await.unwrap();
        // The migration executor rebuilds compiler-owned views around reviewed SQL.
        for view in &fixture.registry.ddl().views {
            tx.batch_execute(&format!(
                "DROP VIEW \"{}\".\"{}\" RESTRICT",
                view.schema, view.name
            ))
            .await
            .unwrap();
        }
        let candidate = prepared.registry();
        let changes = reviewed(
            &fixture.registry,
            candidate,
            &fixture.identity,
            &fixture.identity.schema_fingerprint,
        );
        for change in changes {
            for file in change.files.iter().filter(|f| f.path.contains("/steps/")) {
                tx.batch_execute(std::str::from_utf8(&file.bytes).unwrap())
                    .await
                    .expect("reviewed shape DDL rehearses");
            }
        }
        for statement in &prepared.manifest().migration_plan.statements {
            // Views are recreated below after both reviewed and additive changes.
            if statement.kind != registry_breg::generated_ddl::DdlStatementKind::View {
                tx.batch_execute(&statement.sql)
                    .await
                    .expect("additive DDL rehearses");
            }
        }
        for statement in candidate
            .ddl()
            .statements
            .iter()
            .filter(|s| s.kind == registry_breg::generated_ddl::DdlStatementKind::View)
        {
            tx.batch_execute(&statement.sql).await.unwrap();
        }
        reconcile_compiled_runtime_acl_for_test(&tx, candidate, &fixture.database.runtime_role)
            .await
            .unwrap();
        let fingerprint = managed_schema_fingerprint(
            &tx,
            &fixture.database.runtime_role,
            &ExpectedManagedCatalog::compiled(candidate),
        )
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        drop(migration);
        task.abort();
        let prepared = prepare(fixture, source, &fingerprint);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().canonicalize().unwrap().join("package");
        prepared.publish_to_directory(&path).unwrap();
        load_package(
            &path,
            &PackageLoadContext {
                database_initialization_environment: "local",
            },
        )
        .unwrap()
    }
    pub fn backup(
        directory: &std::path::Path,
        current: &ExpectedRegistryIdentity,
    ) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let bytes = b"-- canary disposable shape fixture backup\n";
        let path = directory.join("canary.backup");
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let binding = ExternalBackupBinding {
            database_id: current.database_id.clone(),
            prior_package_digest: current.package_digest.clone(),
            prior_schema_fingerprint: current.schema_fingerprint.clone(),
            backup_file: path.to_str().unwrap().into(),
            sha256: digest(bytes),
            byte_length: bytes.len() as u64,
            created_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            max_age_seconds: 3600,
        };
        let path = directory.join("binding.json");
        std::fs::write(&path, canonical(&binding)).unwrap();
        path
    }
}
mod shape_authority {
    use axum::{
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::get,
        Json, Router,
    };
    use registry_review_client::{
        PolicyBinding, ReviewCreateRequest, ReviewRequestAccepted, ReviewRequestLifecycle,
        ReviewRequestView, ReviewResult, ReviewResultStatus,
    };
    use serde_json::{json, Value};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    use uuid::Uuid;

    struct Token;
    #[async_trait::async_trait]
    impl registry_platform_httputil::TokenProvider for Token {
        async fn bearer_token(
            &self,
        ) -> Result<registry_platform_httputil::BearerToken, registry_platform_httputil::TokenError>
        {
            registry_platform_httputil::BearerToken::new("canary-shape-review-token")
        }
    }
    struct StateData {
        policy: PolicyBinding,
        registry_id: String,
        accepted: Mutex<std::collections::BTreeMap<Uuid, ReviewRequestAccepted>>,
        result: Mutex<std::collections::BTreeMap<Uuid, ReviewResult>>,
        creates: AtomicUsize,
    }
    pub struct LocalAuthority {
        pub registry: Arc<registry_breg::review_store::ReviewAuthorityRegistry>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for LocalAuthority {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    impl LocalAuthority {
        pub async fn start_for_registry(policy: PolicyBinding, registry_id: &str) -> Self {
            let state = Arc::new(StateData {
                policy,
                registry_id: registry_id.into(),
                accepted: Mutex::new(Default::default()),
                result: Mutex::new(Default::default()),
                creates: 0.into(),
            });
            let router = Router::new()
                .route("/v1/review-requests", axum::routing::post(create))
                .route("/v1/review-requests/{id}", get(request))
                .route("/v1/review-requests/{id}/result", get(result))
                .route("/v1/review-results", get(feed))
                .with_state(state.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                axum::serve(listener, router).await.unwrap();
            });
            let client = registry_review_client::ReviewClient::new(
                registry_review_client::ReviewClientConfig::new(
                    format!("http://{address}/").parse().unwrap(),
                ),
            )
            .unwrap();
            let authority = Arc::new(
                registry_breg::review_store::ReviewAuthorityClient::new(
                    "local-review".into(),
                    client,
                    Arc::new(Token),
                    "producer".into(),
                    "proposal-producer".into(),
                    7,
                    None,
                    None,
                )
                .unwrap(),
            );
            let registry = Arc::new(
                registry_breg::review_store::ReviewAuthorityRegistry::new(
                    std::collections::BTreeMap::from([("local-review".into(), authority)]),
                )
                .unwrap(),
            );
            Self { registry, task }
        }
    }
    fn authenticated(headers: &HeaderMap) -> bool {
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            == Some("Bearer canary-shape-review-token")
            && headers
                .get(registry_review_protocol::REVIEW_PROFILE_HEADER)
                .and_then(|value| value.to_str().ok())
                == Some("producer")
    }
    fn response(status: StatusCode, value: Value) -> Response {
        let mut response = (status, Json(value)).into_response();
        response.headers_mut().insert(
            "traceparent",
            axum::http::HeaderValue::from_static(
                "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
            ),
        );
        response
    }
    async fn create(
        State(state): State<Arc<StateData>>,
        headers: HeaderMap,
        Json(request): Json<ReviewCreateRequest>,
    ) -> Response {
        assert!(authenticated(&headers));
        assert!(headers.contains_key("idempotency-key"));
        request.check().unwrap();
        assert!(
            request.policy.matches(&state.policy),
            "select the configured policy"
        );
        let sequence = state.creates.fetch_add(1, Ordering::SeqCst);
        let digest = registry_review_client::submission_digest(
            "proposal-producer",
            &state.registry_id,
            &request,
        )
        .unwrap();
        let accepted = ReviewRequestAccepted {
            request_id: Uuid::new_v4(),
            subject: request.subject,
            policy: state.policy.clone(),
            submission_digest: digest,
        };
        let now = chrono::Utc::now();
        let result = ReviewResult {
            result_id: Uuid::new_v4(),
            request_id: accepted.request_id,
            subject: accepted.subject.clone(),
            policy: accepted.policy.clone(),
            submission_digest: accepted.submission_digest.clone(),
            status: ReviewResultStatus::Approved,
            outcome: Some("approved".to_owned()),
            public_reason: None,
            result: None,
            completed_at: now - chrono::Duration::seconds(1),
            available_until: now + chrono::Duration::minutes(30),
        };
        state
            .accepted
            .lock()
            .unwrap()
            .insert(accepted.request_id, accepted.clone());
        if sequence == 0 {
            state
                .result
                .lock()
                .unwrap()
                .insert(accepted.request_id, result);
        }
        response(StatusCode::CREATED, json!(accepted))
    }
    async fn request(
        State(state): State<Arc<StateData>>,
        Path(id): Path<Uuid>,
        headers: HeaderMap,
    ) -> Response {
        assert!(authenticated(&headers));
        let accepted = state.accepted.lock().unwrap().get(&id).unwrap().clone();
        assert_eq!(id, accepted.request_id);
        let approved = state.result.lock().unwrap().contains_key(&id);
        let completed = chrono::Utc::now() - chrono::Duration::seconds(1);
        response(
            StatusCode::OK,
            json!(ReviewRequestView {
                request_id: id,
                subject: accepted.subject,
                policy: accepted.policy,
                submission_digest: accepted.submission_digest,
                requester_reference: "synthetic-producer-reference".into(),
                lifecycle: if approved {
                    ReviewRequestLifecycle::Approved
                } else {
                    ReviewRequestLifecycle::Reviewing
                },
                active_stage: (!approved).then(|| "review".into()),
                created_at: completed,
                updated_at: completed
            }),
        )
    }
    async fn result(
        State(state): State<Arc<StateData>>,
        Path(id): Path<Uuid>,
        headers: HeaderMap,
    ) -> Response {
        assert!(authenticated(&headers));
        let Some(result) = state.result.lock().unwrap().get(&id).cloned() else {
            return response(StatusCode::NOT_FOUND, json!({}));
        };
        assert_eq!(id, result.request_id);
        response(StatusCode::OK, json!(result))
    }
    async fn feed(headers: HeaderMap) -> Response {
        assert!(authenticated(&headers));
        response(StatusCode::OK, json!({"items":[]}))
    }
}
