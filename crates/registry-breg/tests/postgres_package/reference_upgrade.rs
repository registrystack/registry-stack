// SPDX-License-Identifier: Apache-2.0

use super::derived_upgrade_tests::assert_startup;
use super::policy_upgrade_tests::fresh_fingerprint;
use super::*;
use registry_breg::migration::DestructiveBackupEvidence;
use registry_breg::migration_plan::{
    ArtifactDigestBinding, ExternalBackupBinding, RehearsalFixture,
    ReviewedMigrationAssertionDescriptor, ReviewedMigrationObject, ReviewedMigrationObjectKind,
    ReviewedMigrationStepDescriptor,
};
use std::os::unix::fs::PermissionsExt;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pre_integrity_reference_schema_upgrades_once() {
    let fixture = LegacyReferenceRegistry::activate().await;
    let (successor_root, successor) = fixture.successor();
    let support_ids = successor
        .manifest()
        .migration_plan
        .statements
        .iter()
        .filter(|statement| {
            statement.id.ends_with(".reference-lifecycle.column")
                || statement.id.ends_with(".reference-lifecycle.key")
                || statement.id.ends_with(".active-reference")
        })
        .map(|statement| statement.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        support_ids,
        [
            "entity.asset.reference-lifecycle.column",
            "entity.site.reference-lifecycle.key",
            "entity.asset.field.site.active-reference",
        ]
    );

    let upgraded = apply_package(
        &fixture.database,
        &successor,
        ApplyPrecondition::Successor {
            current: &fixture.active,
        },
        Duration::from_secs(1),
        Duration::from_secs(5),
    )
    .await
    .expect("the successor installs live-reference support");
    assert_eq!(upgraded.schema_fingerprint, fixture.current_fingerprint);
    assert_eq!(fixture.support_object_count().await, 3);
    assert_startup(&fixture.database, &successor_root, &successor).await;

    let installed = load_predecessor_package(successor_root.path(), &local_context())
        .expect("the upgraded package remains a planning baseline");
    let mut unchanged = reference_request();
    unchanged.from_package_digest = Some(upgraded.package_digest.clone());
    unchanged
        .schema_fingerprint
        .clone_from(&fixture.current_fingerprint);
    unchanged.migration_plan = PackageMigrationPlanInput::SuccessorFromBaseline {
        prior_baseline: Box::new(installed.migration_baseline().clone()),
    };
    let (_root, unchanged) = publish_and_load(unchanged);
    assert!(registry_breg::migration::successor_plan_is_empty(
        &unchanged
    ));

    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pre_integrity_schema_with_an_active_reference_to_a_tombstone_refuses_atomically() {
    let fixture = LegacyReferenceRegistry::activate().await;
    fixture.insert_inconsistent_reference().await;
    let (_successor_root, successor) = fixture.successor();

    let refused = apply_package(
        &fixture.database,
        &successor,
        ApplyPrecondition::Successor {
            current: &fixture.active,
        },
        Duration::from_secs(1),
        Duration::from_secs(5),
    )
    .await
    .expect_err("the active reference to a tombstone refuses the upgrade");
    let MigrationError::StatementFailed(failure) = refused else {
        panic!("upgrade returned the wrong value-free error: {refused:?}");
    };
    assert_eq!(failure.sqlstate.as_deref(), Some("23503"));
    assert_eq!(
        failure.table.as_deref(),
        Some(fixture.source_table.as_str())
    );
    assert_eq!(
        failure.constraint.as_deref(),
        Some(fixture.active_constraint.as_str())
    );
    assert_eq!(
        fixture.support_object_count().await,
        0,
        "the failed FK validation rolls back its support column and key"
    );
    assert!(
        fixture.source_force_row_security().await,
        "the failed validation restores FORCE ROW LEVEL SECURITY"
    );
    assert_eq!(
        fixture.recorded_identity().await,
        (
            fixture.active.package_digest.clone(),
            fixture.active.activation_id.clone(),
            fixture.active.schema_fingerprint.clone(),
        ),
        "the refused upgrade does not activate the successor identity"
    );
    assert_eq!(
        fixture
            .database
            .admin
            .query_one(
                &format!(
                    "SELECT count(*) FROM registry_data.{}",
                    quote_identifier(&fixture.source_table)
                ),
                &[],
            )
            .await
            .expect("legacy source row remains readable")
            .get::<_, i64>(0),
        1,
        "a refused upgrade does not mutate legacy rows"
    );

    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reviewed_reference_retarget_and_removal_match_fresh_catalogs() {
    let initial_request = reference_request_for(Some("site"));
    let initial_registry = prepare_package(initial_request.clone())
        .expect("initial reference model compiles")
        .registry()
        .clone();
    let initial_fingerprint = fresh_fingerprint(&initial_registry).await;
    let mut initial_request = initial_request;
    initial_request
        .schema_fingerprint
        .clone_from(&initial_fingerprint);
    let (initial_root, initial) = publish_and_load(initial_request);
    let database = TestDatabase::create(1).await;
    let active_initial = apply_package(
        &database,
        &initial,
        ApplyPrecondition::InitialActivation,
        Duration::from_secs(1),
        Duration::from_secs(5),
    )
    .await
    .expect("initial reference package activates");

    let source_names = &initial_registry.physical_names().entities["asset"];
    let site_names = &initial_registry.physical_names().entities["site"];
    let active_constraint = source_names.constraints["active-reference:site"].clone();
    let site_key = site_names.constraints["active-reference-key:record-lifecycle"].clone();

    let retarget_request = reference_request_for(Some("location"));
    let retarget_registry = prepare_package(retarget_request.clone())
        .expect("retarget model compiles")
        .registry()
        .clone();
    let retarget_fingerprint = fresh_fingerprint(&retarget_registry).await;
    let retarget_change_set = compiled_registry_change_set(
        &initial_registry,
        &retarget_registry,
        &active_initial.package_digest,
    );
    let source = &retarget_registry.entities()["asset"];
    let field = &source.fields["site"];
    let location_key = retarget_registry.physical_names().entities["location"].constraints
        ["active-reference-key:record-lifecycle"]
        .clone();
    let raw_constraint =
        &retarget_registry.physical_names().entities["asset"].constraints["reference:site"];
    let raw_object = ReviewedMigrationObject {
        schema: "registry_data".to_owned(),
        table: source.physical_table.clone(),
        entity_id: "asset".to_owned(),
        kind: ReviewedMigrationObjectKind::Constraint,
        member_id: Some("reference:site".to_owned()),
        physical_name: raw_constraint.clone(),
    };
    let retarget_review = reference_review_source(
        "retarget-reference",
        CompiledRegistryChangeClass::DestructiveOrIrreversible,
        &retarget_change_set.changes,
        &active_initial,
        &retarget_fingerprint,
        vec![
            (
                "drop-reference",
                format!(
                    "ALTER TABLE registry_data.{} DROP CONSTRAINT {}",
                    source.physical_table, raw_constraint
                ),
                raw_object.clone(),
            ),
            (
                "add-reference",
                format!(
                    "ALTER TABLE registry_data.{} ADD CONSTRAINT {} FOREIGN KEY ({}) REFERENCES registry_data.{} (record_id) ON DELETE RESTRICT",
                    source.physical_table,
                    raw_constraint,
                    field.physical_name,
                    retarget_registry.entities()["location"].physical_table,
                ),
                raw_object,
            ),
        ],
        &source.physical_table,
    );
    let mut retarget_request = retarget_request;
    retarget_request.from_package_digest = Some(active_initial.package_digest.clone());
    retarget_request
        .schema_fingerprint
        .clone_from(&retarget_fingerprint);
    retarget_request.migration_plan = PackageMigrationPlanInput::ReviewedSuccessor {
        prior_registry: Box::new(initial_registry.clone()),
        prior_schema_fingerprint: active_initial.schema_fingerprint.clone(),
        migrations: vec![retarget_review],
    };
    let (retarget_root, retarget) = publish_and_load(retarget_request);
    let active_retarget = apply_reviewed_package(
        &database,
        &retarget,
        &active_initial,
        "modules/core/migrations/retarget-reference/backup.json",
    )
    .await
    .expect("reviewed reference retarget applies");
    assert_eq!(active_retarget.schema_fingerprint, retarget_fingerprint);
    assert_eq!(
        live_reference_support_count(
            &database,
            &source.physical_table,
            &[&active_constraint, &site_key, &location_key]
        )
        .await,
        3,
        "the source projection and retargeted active FK remain while the old target key retires"
    );
    assert_startup(&database, &retarget_root, &retarget).await;

    let removal_request = reference_request_for(None);
    let removal_registry = prepare_package(removal_request.clone())
        .expect("reference removal model compiles")
        .registry()
        .clone();
    let removal_fingerprint = fresh_fingerprint(&removal_registry).await;
    let removal_change_set = compiled_registry_change_set(
        &retarget_registry,
        &removal_registry,
        &active_retarget.package_digest,
    );
    let removed_field = &retarget_registry.entities()["asset"].fields["site"];
    let removal_review = reference_review_source(
        "remove-reference",
        CompiledRegistryChangeClass::DestructiveOrIrreversible,
        &removal_change_set.changes,
        &active_retarget,
        &removal_fingerprint,
        vec![(
            "drop-reference-field",
            format!(
                "ALTER TABLE registry_data.{} DROP COLUMN {}",
                source.physical_table, removed_field.physical_name
            ),
            ReviewedMigrationObject {
                schema: "registry_data".to_owned(),
                table: source.physical_table.clone(),
                entity_id: "asset".to_owned(),
                kind: ReviewedMigrationObjectKind::Field,
                member_id: Some("site".to_owned()),
                physical_name: removed_field.physical_name.clone(),
            },
        )],
        &source.physical_table,
    );
    let mut removal_request = removal_request;
    removal_request.from_package_digest = Some(active_retarget.package_digest.clone());
    removal_request
        .schema_fingerprint
        .clone_from(&removal_fingerprint);
    removal_request.migration_plan = PackageMigrationPlanInput::ReviewedSuccessor {
        prior_registry: Box::new(retarget_registry.clone()),
        prior_schema_fingerprint: active_retarget.schema_fingerprint.clone(),
        migrations: vec![removal_review],
    };
    let (removal_root, removal) = publish_and_load(removal_request);
    let active_removal = apply_reviewed_package(
        &database,
        &removal,
        &active_retarget,
        "modules/core/migrations/remove-reference/backup.json",
    )
    .await
    .expect("reviewed removal of the last outgoing reference applies");
    assert_eq!(active_removal.schema_fingerprint, removal_fingerprint);
    assert_eq!(
        live_reference_support_count(
            &database,
            &source.physical_table,
            &[&active_constraint, &site_key, &location_key]
        )
        .await,
        0,
        "the last reference removal retires its active FK, target key, and source projection"
    );
    assert_startup(&database, &removal_root, &removal).await;

    drop(initial_root);
    database.cleanup().await;
}

struct LegacyReferenceRegistry {
    database: TestDatabase,
    migration_task: tokio::task::JoinHandle<()>,
    active: ExpectedRegistryIdentity,
    current_fingerprint: String,
    baseline: registry_breg::package::CompiledRegistryMigrationBaseline,
    source_table: String,
    target_table: String,
    source_field: String,
    active_constraint: String,
    target_key: String,
}

impl LegacyReferenceRegistry {
    async fn activate() -> Self {
        let mut request = reference_request();
        let registry = prepare_package(request.clone())
            .expect("reference model compiles")
            .registry()
            .clone();
        let current_fingerprint = fresh_fingerprint(&registry).await;
        request.schema_fingerprint.clone_from(&current_fingerprint);
        let (_root, package) = publish_and_load(request);

        let database = TestDatabase::create(1).await;
        let mut active = apply_package(
            &database,
            &package,
            ApplyPrecondition::InitialActivation,
            Duration::from_secs(1),
            Duration::from_secs(5),
        )
        .await
        .expect("current reference package activates");

        let source_names = &registry.physical_names().entities["asset"];
        let target_names = &registry.physical_names().entities["site"];
        let source_table = source_names.table.clone();
        let target_table = target_names.table.clone();
        let source_field = source_names.fields["site"].clone();
        let active_constraint = source_names.constraints["active-reference:site"].clone();
        let target_key = target_names.constraints["active-reference-key:record-lifecycle"].clone();

        let (migration, migration_task) = database.connect_migration().await;
        migration
            .batch_execute(&format!(
                "ALTER TABLE registry_data.{source_table} DROP CONSTRAINT {active_constraint};
                 ALTER TABLE registry_data.{target_table} DROP CONSTRAINT {target_key};
                 ALTER TABLE registry_data.{source_table} DROP COLUMN record_reference_lifecycle",
                source_table = quote_identifier(&source_table),
                active_constraint = quote_identifier(&active_constraint),
                target_table = quote_identifier(&target_table),
                target_key = quote_identifier(&target_key),
            ))
            .await
            .expect("fixture restores the pre-integrity schema");
        let earlier_fingerprint = managed_schema_fingerprint(
            &migration,
            &database.runtime_role,
            &ExpectedManagedCatalog::compiled(&registry),
        )
        .await
        .expect("pre-integrity schema fingerprint derives");
        assert_ne!(earlier_fingerprint, current_fingerprint);
        migration
            .execute(
                "UPDATE registry_internal.registry_state
                    SET schema_fingerprint = $1
                  WHERE singleton",
                &[&earlier_fingerprint],
            )
            .await
            .expect("fixture records the pre-integrity schema fingerprint");
        active.schema_fingerprint = earlier_fingerprint;
        drop(migration);

        let mut baseline = registry_breg::package::CompiledRegistryMigrationBaseline::from_compiled(
            &active.package_digest,
            &registry,
        );
        for names in baseline.physical_names.entities.values_mut() {
            names.constraints.retain(|key, _| {
                !key.starts_with("active-reference:")
                    && key != "active-reference-key:record-lifecycle"
            });
        }
        baseline.generated_ddl_sha256 = None;

        Self {
            database,
            migration_task,
            active,
            current_fingerprint,
            baseline,
            source_table,
            target_table,
            source_field,
            active_constraint,
            target_key,
        }
    }

    fn successor(&self) -> (TempRoot, registry_breg::package::VerifiedPackage) {
        let mut request = reference_request();
        request.from_package_digest = Some(self.active.package_digest.clone());
        request
            .schema_fingerprint
            .clone_from(&self.current_fingerprint);
        request.migration_plan = PackageMigrationPlanInput::SuccessorFromBaseline {
            prior_baseline: Box::new(self.baseline.clone()),
        };
        publish_and_load(request)
    }

    async fn insert_inconsistent_reference(&self) {
        let target_id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        self.database
            .admin
            .batch_execute(&format!(
                "INSERT INTO registry_data.{target_table}
                    (record_id, record_lifecycle, active_package_revision)
                 VALUES ('{target_id}', 'tombstoned', 'legacy-fixture');
                 INSERT INTO registry_data.{source_table}
                    (record_id, active_package_revision, {source_field})
                 VALUES ('{source_id}', 'legacy-fixture', '{target_id}')",
                target_table = quote_identifier(&self.target_table),
                source_table = quote_identifier(&self.source_table),
                source_field = quote_identifier(&self.source_field),
            ))
            .await
            .expect("legacy rows allow a live reference to a tombstone");
    }

    async fn support_object_count(&self) -> i64 {
        self.database
            .admin
            .query_one(
                "SELECT
                    (SELECT count(*) FROM pg_catalog.pg_attribute attribute
                      JOIN pg_catalog.pg_class class ON class.oid = attribute.attrelid
                      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = class.relnamespace
                     WHERE namespace.nspname = 'registry_data'
                       AND class.relname = $1
                       AND attribute.attname = 'record_reference_lifecycle'
                       AND NOT attribute.attisdropped)
                    + (SELECT count(*) FROM pg_catalog.pg_constraint
                        WHERE conname IN ($2, $3))",
                &[
                    &self.source_table,
                    &self.active_constraint,
                    &self.target_key,
                ],
            )
            .await
            .expect("reference support inventory reads")
            .get(0)
    }

    async fn source_force_row_security(&self) -> bool {
        self.database
            .admin
            .query_one(
                "SELECT class.relforcerowsecurity
                   FROM pg_catalog.pg_class class
                   JOIN pg_catalog.pg_namespace namespace ON namespace.oid = class.relnamespace
                  WHERE namespace.nspname = 'registry_data' AND class.relname = $1",
                &[&self.source_table],
            )
            .await
            .expect("source row-security state reads")
            .get(0)
    }

    async fn recorded_identity(&self) -> (String, String, String) {
        let row = self
            .database
            .admin
            .query_one(
                "SELECT active_package_digest, active_activation_id::text, schema_fingerprint
                   FROM registry_internal.registry_state
                  WHERE singleton",
                &[],
            )
            .await
            .expect("active identity reads");
        (row.get(0), row.get(1), row.get(2))
    }

    async fn finish(self) {
        self.migration_task.abort();
        self.database.cleanup().await;
    }
}

fn reference_request() -> PackageBuildRequest {
    reference_request_for(Some("site"))
}

fn reference_request_for(target: Option<&str>) -> PackageBuildRequest {
    let module_bytes = reference_module_bytes(target);
    let module = parse_module_yaml(&module_bytes).expect("reference module parses");
    build_request(BuildRequestParts {
        prior_revision: None,
        schema_fingerprint: fingerprint(1),
        project_bytes: project_bytes(&module_digest(&module)),
        module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    })
}

fn reference_module_bytes(target: Option<&str>) -> Vec<u8> {
    let reference_field = target.map_or_else(String::new, |target| {
        format!(
            r#",{{"id":"site","type":"reference","target":"{target}","classification":"internal"}}"#
        )
    });
    format!(
        r#"{{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"core","version":"1","recordTypes":[{{"id":"site","primaryDataset":"neutral-registry","route":"sites","mutationMode":"mutable","fields":[{{"id":"code","type":"string","maximumLength":16,"classification":"internal"}}],"accessProfiles":[{{"id":"reader","principalClaim":"principal","requiredScopes":"unrestricted","rowBoundaries":"unrestricted","operations":["create","get","list","patch"],"readableFields":["code"],"writableFields":["code"]}}]}},{{"id":"location","primaryDataset":"neutral-registry","route":"locations","mutationMode":"mutable","fields":[{{"id":"code","type":"string","maximumLength":16,"classification":"internal"}}],"accessProfiles":[{{"id":"reader","principalClaim":"principal","requiredScopes":"unrestricted","rowBoundaries":"unrestricted","operations":["create","get","list","patch"],"readableFields":["code"],"writableFields":["code"]}}]}},{{"id":"asset","primaryDataset":"neutral-registry","route":"assets","mutationMode":"mutable","fields":[{{"id":"code","type":"string","maximumLength":16,"classification":"internal"}}{reference_field}],"accessProfiles":[{{"id":"reader","principalClaim":"principal","requiredScopes":"unrestricted","rowBoundaries":"unrestricted","operations":["create","get","list","patch"],"readableFields":["code"],"writableFields":["code"]}}]}}]}}"#
    )
    .into_bytes()
}

fn reference_review_source(
    id: &str,
    change_class: CompiledRegistryChangeClass,
    changes: &[registry_breg::package::CompiledRegistryChange],
    current: &ExpectedRegistryIdentity,
    final_fingerprint: &str,
    steps: Vec<(&str, String, ReviewedMigrationObject)>,
    assertion_table: &str,
) -> ReviewedMigrationSource {
    let base = format!("modules/core/migrations/{id}");
    let pre_path = format!("{base}/assertions/pre.sql");
    let post_path = format!("{base}/assertions/post.sql");
    let fixture_path = format!("{base}/fixtures/representative.jsonl");
    let assertion_sql =
        format!("SELECT pg_catalog.count(*) >= 0 FROM registry_data.{assertion_table}");
    let fixture_bytes = b"{\"fixture\":\"representative\"}\n".to_vec();
    let step_bindings = steps
        .iter()
        .map(|(step_id, sql, object)| {
            let path = format!("{base}/steps/{step_id}.sql");
            (
                ReviewedMigrationStepDescriptor::TransactionalSql {
                    id: (*step_id).to_owned(),
                    sql_path: path.clone(),
                    objects: vec![object.clone()],
                    affected_rows: None,
                },
                path,
                sql.clone(),
            )
        })
        .collect::<Vec<_>>();
    let descriptor = ReviewedMigrationDescriptor {
        id: id.to_owned(),
        change_class,
        covers: changes
            .iter()
            .filter(|change| change.class != CompiledRegistryChangeClass::CompatibleAdditive)
            .map(ReviewedChangeCover::from)
            .collect(),
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        history: None,
        lock_timeout_ms: 1_000,
        statement_timeout_ms: 5_000,
        steps: step_bindings
            .iter()
            .map(|(descriptor, _, _)| descriptor.clone())
            .collect(),
        pre_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "pre".to_owned(),
            sql_path: pre_path.clone(),
        }],
        post_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "post".to_owned(),
            sql_path: post_path.clone(),
        }],
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: Some(format!("{base}/backup.json")),
    };
    let descriptor_bytes = canonical_bytes(&descriptor);
    let receipt = MigrationRehearsalReceipt {
        prior_package_digest: current.package_digest.clone(),
        prior_schema_fingerprint: current.schema_fingerprint.clone(),
        plan_sha256: sha256(&descriptor_bytes),
        sql_sha256: step_bindings
            .iter()
            .map(|(_, path, sql)| ArtifactDigestBinding {
                path: path.clone(),
                sha256: sha256(sql.as_bytes()),
            })
            .collect(),
        assertion_sha256: vec![
            ArtifactDigestBinding {
                path: pre_path.clone(),
                sha256: sha256(assertion_sql.as_bytes()),
            },
            ArtifactDigestBinding {
                path: post_path.clone(),
                sha256: sha256(assertion_sql.as_bytes()),
            },
        ],
        fixture_inventory: vec![RehearsalFixture {
            id: "representative".to_owned(),
            path: fixture_path.clone(),
            sha256: sha256(&fixture_bytes),
            row_count: 1,
        }],
        postgres_major: 17,
        row_assertions: Vec::new(),
        final_schema_fingerprint: final_fingerprint.to_owned(),
    };
    let mut files = step_bindings
        .into_iter()
        .map(|(_, path, sql)| ReviewedMigrationFile {
            path,
            bytes: sql.into_bytes(),
        })
        .collect::<Vec<_>>();
    files.extend([
        ReviewedMigrationFile {
            path: pre_path,
            bytes: assertion_sql.as_bytes().to_vec(),
        },
        ReviewedMigrationFile {
            path: post_path,
            bytes: assertion_sql.into_bytes(),
        },
        ReviewedMigrationFile {
            path: descriptor.rehearsal_receipt_path.clone(),
            bytes: canonical_bytes(&receipt),
        },
        ReviewedMigrationFile {
            path: fixture_path,
            bytes: fixture_bytes,
        },
    ]);
    files.sort_by(|left, right| left.path.cmp(&right.path));
    ReviewedMigrationSource {
        module_id: "core".to_owned(),
        descriptor: ReviewedMigrationFile {
            path: format!("{base}/descriptor.json"),
            bytes: descriptor_bytes,
        },
        files,
    }
}

async fn apply_reviewed_package(
    database: &TestDatabase,
    package: &registry_breg::package::VerifiedPackage,
    current: &ExpectedRegistryIdentity,
    binding_path: &str,
) -> registry_breg::migration::Result<ExpectedRegistryIdentity> {
    let backup_root = TempRoot::create();
    fs::create_dir_all(backup_root.path()).expect("backup evidence directory creates");
    let backup_bytes = b"reference-upgrade-backup";
    let backup_file = backup_root.path().join("registry.backup");
    fs::write(&backup_file, backup_bytes).expect("synthetic backup writes");
    fs::set_permissions(&backup_file, fs::Permissions::from_mode(0o600))
        .expect("synthetic backup permissions close");
    let binding_file = backup_root.path().join("binding.json");
    fs::write(
        &binding_file,
        canonical_bytes(&ExternalBackupBinding {
            database_id: DATABASE.to_owned(),
            prior_package_digest: current.package_digest.clone(),
            prior_schema_fingerprint: current.schema_fingerprint.clone(),
            backup_file: backup_file
                .to_str()
                .expect("backup path is UTF-8")
                .to_owned(),
            sha256: sha256(backup_bytes),
            byte_length: backup_bytes.len() as u64,
            created_at: OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
            max_age_seconds: 3_600,
        }),
    )
    .expect("backup binding writes");
    let evidence = [DestructiveBackupEvidence::new(binding_path, &binding_file)];
    let timeouts = ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
        .expect("reviewed apply timeouts are bounded");
    apply_verified_package(
        ApplyVerifiedPackageRequest::new(
            &database.migration_config,
            package,
            ActivationDeployment::new("local", INSTANCE, DATABASE),
            ApplyPrecondition::Successor { current },
            ApplyRoles::new(&database.migration_role, &database.runtime_role),
            timeouts,
            database.activation_audit(),
        )
        .with_destructive_backup_evidence(&evidence),
    )
    .await
}

async fn live_reference_support_count(
    database: &TestDatabase,
    source_table: &str,
    constraint_names: &[&str],
) -> i64 {
    let constraint_names = constraint_names.to_vec();
    let column_count = database
        .admin
        .query_one(
            "SELECT count(*) FROM pg_catalog.pg_attribute attribute
              JOIN pg_catalog.pg_class class ON class.oid = attribute.attrelid
              JOIN pg_catalog.pg_namespace namespace ON namespace.oid = class.relnamespace
             WHERE namespace.nspname = 'registry_data'
               AND class.relname = $1
               AND attribute.attname = 'record_reference_lifecycle'
               AND NOT attribute.attisdropped",
            &[&source_table],
        )
        .await
        .expect("reference lifecycle column reads")
        .get::<_, i64>(0);
    let constraint_count = database
        .admin
        .query_one(
            "SELECT count(*) FROM pg_catalog.pg_constraint WHERE conname = ANY($1::text[])",
            &[&constraint_names],
        )
        .await
        .expect("live reference constraints read")
        .get::<_, i64>(0);
    column_count + constraint_count
}

fn canonical_bytes(value: &impl Serialize) -> Vec<u8> {
    canonicalize_json(&serde_json::to_value(value).expect("value serializes"))
        .expect("value canonicalizes")
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

fn publish_and_load(
    request: PackageBuildRequest,
) -> (TempRoot, registry_breg::package::VerifiedPackage) {
    let root = TempRoot::create();
    prepare_package(request)
        .expect("reference package prepares")
        .publish_to_directory(root.path())
        .expect("reference package publishes");
    let verified = load_package(root.path(), &local_context()).expect("reference package verifies");
    (root, verified)
}
