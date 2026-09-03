// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "runtime", feature = "tooling"))]

use std::fs;

use registry_breg::compiler::{compile_project, module_digest, CompileProfile};
use registry_breg::contract::{parse_module_yaml, parse_project_yaml};
use registry_breg::generated_ddl::DdlStatementKind;
use registry_breg::migration_plan::{
    ArtifactDigestBinding, ChunkCursorProtocol, ExternalBackupBinding, MigrationRehearsalReceipt,
    RehearsalFixture, RehearsalProofs, RehearsalRowAssertion, ReviewedChangeCover,
    ReviewedMigrationAssertionDescriptor, ReviewedMigrationDescriptor, ReviewedMigrationFile,
    ReviewedMigrationObject, ReviewedMigrationObjectKind, ReviewedMigrationRecovery,
    ReviewedMigrationSource, ReviewedMigrationStepDescriptor,
};
use registry_breg::package::{
    compiled_registry_change_set, inspect_package_integrity, prepare_package,
    CompiledRegistryChangeClass, CompiledRegistryChangeCode, PackageBuildRequest, PackageError,
    PackageFileRole, PackageMigrationPlanInput, PackageModuleSource, PackageSourceFile,
    SignaturePolicy,
};
use registry_breg::CompiledRegistry;
use registry_platform_canonical_json::canonicalize_json;
use serde::Serialize;
use sha2::{Digest, Sha256};

const INSTANCE: &str = "instance-under-test";
const DATABASE: &str = "database-under-test";
const SOURCE_REVISION: &str = "compiler-source-revision";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: registry.registrystack.org/breg-journeys/v1
journeys:
  - id: asset-list
    steps:
      - id: list-assets
        entity: asset
        accessProfile: reader
        claims: {principal: package-reader}
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 0}
"#;
const PRIOR_REVISION: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const PRIOR_FINGERPRINT: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const FINAL_FINGERPRINT: &str =
    "sha256:3333333333333333333333333333333333333333333333333333333333333333";

#[test]
fn reviewed_migration_plan_closes_ast_sql_and_bound_evidence() {
    let previous = compile_variant(Variant::Base, 1);
    let candidate = compile_variant(Variant::RequiredField, 2);
    let artifacts = backfill_artifacts("required-field", &previous, &candidate);
    let prepared =
        prepare_reviewed_package(Variant::RequiredField, previous, vec![artifacts.source()])
            .expect("reviewed successor package prepares");

    let statements = &prepared.manifest().migration_plan.statements;
    assert!(!statements.is_empty());
    let columns = statements
        .iter()
        .filter(|statement| statement.kind == DdlStatementKind::Column)
        .collect::<Vec<_>>();
    assert_eq!(
        columns.len(),
        2,
        "the added required field arrives as a nullable column plus a deferred NOT NULL"
    );
    assert!(columns[0].sql.contains(" ADD COLUMN ") && !columns[0].sql.contains("NOT NULL"));
    assert!(columns[1].sql.contains(" ALTER COLUMN ") && columns[1].sql.ends_with(" SET NOT NULL"));
    assert!(statements
        .iter()
        .all(|statement| statement.kind == DdlStatementKind::View
            || statement.kind == DdlStatementKind::Column));
    assert_eq!(
        prepared.manifest().migration_plan.reviewed_descriptors,
        vec!["modules/core/migrations/required-field/descriptor.json"]
    );
    assert_eq!(
        prepared
            .manifest()
            .migration_plan
            .prior_schema_fingerprint
            .as_deref(),
        Some(PRIOR_FINGERPRINT)
    );
    for role in [
        PackageFileRole::ReviewedMigrationDescriptor,
        PackageFileRole::ReviewedMigrationStepSql,
        PackageFileRole::ReviewedMigrationAssertionSql,
        PackageFileRole::MigrationRehearsalReceipt,
        PackageFileRole::MigrationRehearsalFixture,
    ] {
        assert!(prepared
            .manifest()
            .files
            .iter()
            .any(|file| file.role == role));
    }

    let root = tempfile::Builder::new()
        .prefix("registry-migration-plan-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("canonical temporary root"),
        )
        .expect("temporary package parent");
    let package = root.path().join("package");
    prepared
        .publish_to_directory(&package, Vec::new())
        .expect("reviewed package publishes");
    let inspected = inspect_package_integrity(&package).expect("reviewed package rederives");
    assert_eq!(inspected.package_revision(), prepared.package_revision());

    let destructive_candidate = compile_variant(Variant::FieldRemoved, 2);
    let destructive = destructive_artifacts(
        "remove-field",
        &compile_variant(Variant::Base, 1),
        &destructive_candidate,
    );
    let destructive_package = prepare_reviewed_package(
        Variant::FieldRemoved,
        compile_variant(Variant::Base, 1),
        vec![destructive.source()],
    )
    .expect("destructive plan with exact backup binding prepares");
    assert!(destructive_package
        .manifest()
        .files
        .iter()
        .any(|file| file.role == PackageFileRole::ExternalBackupBinding));
}

#[test]
fn reviewed_migration_plan_rejects_uncovered_changes_forbidden_sql_and_unbound_evidence() {
    let previous = compile_variant(Variant::Base, 1);
    let candidate = compile_variant(Variant::RequiredField, 2);
    let valid = backfill_artifacts("required-field", &previous, &candidate);

    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        Vec::new(),
        "uncovered non-additive change",
    );

    let mut uncovered = valid.clone();
    uncovered.descriptor.covers.clear();
    uncovered.rebind();
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![uncovered.source()],
        "missing covers set",
    );

    let mut orphan = valid.clone();
    orphan.descriptor.covers[0].code = CompiledRegistryChangeCode::EntityRemoved;
    orphan.rebind();
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![orphan.source()],
        "orphan cover",
    );

    let duplicate = backfill_artifacts("required-field-two", &previous, &candidate);
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![valid.source(), duplicate.source()],
        "duplicate cover",
    );

    let mut mismatch = valid.clone();
    mismatch.descriptor.change_class = CompiledRegistryChangeClass::DestructiveOrIrreversible;
    mismatch.rebind();
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![mismatch.source()],
        "class-mismatched cover",
    );

    let unsupported_previous = compile_variant(Variant::Base, 1);
    let unsupported_candidate = compile_variant(Variant::DifferentRegistry, 2);
    let mut unsupported = backfill_artifacts(
        "unsupported-identity",
        &unsupported_previous,
        &unsupported_candidate,
    );
    unsupported.descriptor.change_class = CompiledRegistryChangeClass::Unsupported;
    unsupported.descriptor.covers = vec![ReviewedChangeCover::from(
        &compiled_registry_change_set(
            &unsupported_previous,
            &unsupported_candidate,
            PRIOR_REVISION,
        )
        .changes[0],
    )];
    unsupported.rebind();
    assert_refused(
        Variant::DifferentRegistry,
        unsupported_previous,
        vec![unsupported.source()],
        "unsupported compiler change",
    );

    let table = candidate.entities()["asset"].physical_table.clone();
    let site_table = candidate.entities()["site"].physical_table.clone();
    let site_code = candidate.entities()["site"].fields["code"]
        .physical_name
        .clone();
    let asset_rank = candidate.entities()["asset"].fields["rank"]
        .physical_name
        .clone();
    for (label, sql) in [
        (
            "multiple statements",
            format!(
                "UPDATE registry_data.{table} SET f_batch = 'x' WHERE record_id = ANY($1::pg_catalog.uuid[]); UPDATE registry_data.{table} SET f_batch = 'y' WHERE record_id = ANY($1::pg_catalog.uuid[])"
            ),
        ),
        ("transaction", "BEGIN".to_owned()),
        ("set", "SET search_path = registry_data".to_owned()),
        ("role", "ALTER ROLE current_user SUPERUSER".to_owned()),
        ("database", "CREATE DATABASE forbidden".to_owned()),
        ("schema", "CREATE SCHEMA forbidden".to_owned()),
        (
            "extension",
            "CREATE EXTENSION IF NOT EXISTS pgcrypto".to_owned(),
        ),
        (
            "copy program",
            format!("COPY registry_data.{table} TO PROGRAM 'canary-secret'"),
        ),
        (
            "temporary table",
            "CREATE TEMP TABLE registry_data.forbidden(id integer)".to_owned(),
        ),
        (
            "function",
            "CREATE FUNCTION registry_data.forbidden() RETURNS void LANGUAGE sql AS 'SELECT 1'"
                .to_owned(),
        ),
        (
            "procedure",
            "CREATE PROCEDURE registry_data.forbidden() LANGUAGE sql AS 'SELECT 1'".to_owned(),
        ),
        (
            "trigger",
            format!(
                "CREATE TRIGGER forbidden BEFORE UPDATE ON registry_data.{table} EXECUTE FUNCTION registry_data.forbidden()"
            ),
        ),
        (
            "concurrent index",
            format!("CREATE INDEX CONCURRENTLY forbidden ON registry_data.{table}(record_id)"),
        ),
        (
            "unqualified object",
            format!(
                "UPDATE {table} SET f_batch = 'x' WHERE record_id = ANY($1::pg_catalog.uuid[])"
            ),
        ),
        (
            "product-owned schema",
            "UPDATE registry_internal.registry_state SET status = 'ready' WHERE record_id = ANY($1::pg_catalog.uuid[])".to_owned(),
        ),
        (
            "undeclared object",
            "UPDATE registry_data.not_declared SET value = 'x' WHERE record_id = ANY($1::pg_catalog.uuid[])".to_owned(),
        ),
        (
            "insert outside minimal DML",
            format!("INSERT INTO registry_data.{table}(record_id) VALUES (gen_random_uuid())"),
        ),
        (
            "wrong cursor parameter",
            format!(
                "UPDATE registry_data.{table} SET f_batch = 'x' WHERE record_id = ANY($2::pg_catalog.uuid[])"
            ),
        ),
        (
            "infrastructure record identifier write",
            format!(
                "UPDATE registry_data.{table} SET record_id = $1 WHERE record_id = ANY($1::pg_catalog.uuid[])"
            ),
        ),
        (
            "infrastructure lifecycle write",
            format!(
                "UPDATE registry_data.{table} SET record_revision = 4 WHERE record_id = ANY($1::pg_catalog.uuid[])"
            ),
        ),
        (
            "unrelated domain column",
            format!(
                "UPDATE registry_data.{table} SET {asset_rank} = 4 WHERE record_id = ANY($1::pg_catalog.uuid[])"
            ),
        ),
        (
            "cross-entity managed table substitution",
            format!(
                "UPDATE registry_data.{site_table} SET {site_code} = 'x' WHERE record_id = ANY($1::pg_catalog.uuid[])"
            ),
        ),
        (
            "unbound cursor type",
            format!(
                "UPDATE registry_data.{table} SET f_batch = 'x' WHERE record_id = ANY($1::uuid[])"
            ),
        ),
    ] {
        let mut forbidden = valid.clone();
        forbidden.step_sql = sql.into_bytes();
        forbidden.rebind();
        assert_refused(
            Variant::RequiredField,
            previous.clone(),
            vec![forbidden.source()],
            label,
        );
    }

    let mut unbounded_dml = valid.clone();
    let objects = unbounded_dml.descriptor.steps[0].objects().to_vec();
    unbounded_dml.descriptor.steps[0] = ReviewedMigrationStepDescriptor::TransactionalSql {
        id: "backfill".to_owned(),
        sql_path: unbounded_dml.descriptor.steps[0].sql_path().to_owned(),
        objects,
        affected_rows: None,
    };
    unbounded_dml.rebind();
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![unbounded_dml.source()],
        "DML without affected-row bounds",
    );

    let mut non_boolean_assertion = valid.clone();
    non_boolean_assertion.pre_sql = b"SELECT 1".to_vec();
    non_boolean_assertion.rebind();
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![non_boolean_assertion.source()],
        "assertion is not one declared read-only boolean SELECT",
    );

    let mut object_mismatch = valid.clone();
    object_mismatch.descriptor.steps[0].objects_mut()[0].member_id = Some("rank".to_owned());
    object_mismatch.rebind();
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![object_mismatch.source()],
        "descriptor cover and parsed object inventory mismatch",
    );

    let mut unbound = valid.clone();
    unbound.receipt.final_schema_fingerprint =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![unbound.source()],
        "rehearsal evidence bound to wrong target",
    );

    let destructive_candidate = compile_variant(Variant::FieldRemoved, 2);
    let destructive = destructive_artifacts("remove-field", &previous, &destructive_candidate);
    let mut no_backup = destructive.clone();
    no_backup.descriptor.backup_binding_path = None;
    no_backup.backup = None;
    no_backup.rebind();
    assert_refused(
        Variant::FieldRemoved,
        previous.clone(),
        vec![no_backup.source()],
        "destructive plan without external backup binding",
    );

    let mut wrong_backup = destructive;
    wrong_backup
        .backup
        .as_mut()
        .expect("destructive backup exists")
        .database_id = "wrong-database-canary".to_owned();
    wrong_backup.rebind();
    assert_refused(
        Variant::FieldRemoved,
        previous.clone(),
        vec![wrong_backup.source()],
        "external backup bound to a different database",
    );

    let mut missing_fixture = valid.source();
    missing_fixture
        .files
        .retain(|file| !file.path.ends_with("fixtures/representative.jsonl"));
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![missing_fixture],
        "missing rehearsal fixture bytes",
    );

    let mut substituted_fixture = valid.source();
    substituted_fixture
        .files
        .iter_mut()
        .find(|file| file.path.ends_with("fixtures/representative.jsonl"))
        .expect("fixture exists")
        .bytes = b"{\"fixture\":\"substituted-canary\"}\n".to_vec();
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![substituted_fixture],
        "substituted rehearsal fixture bytes",
    );

    let mut extra_fixture = valid.source();
    extra_fixture.files.push(ReviewedMigrationFile {
        path: "modules/core/migrations/required-field/fixtures/extra.jsonl".to_owned(),
        bytes: b"{\"fixture\":\"extra-canary\"}\n".to_vec(),
    });
    extra_fixture
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![extra_fixture],
        "unbound extra rehearsal fixture",
    );

    let prepared = prepare_reviewed_package(Variant::RequiredField, previous, vec![valid.source()])
        .expect("valid reviewed package prepares before tamper");
    let root = tempfile::Builder::new()
        .prefix("registry-migration-plan-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("canonical temporary root"),
        )
        .expect("temporary package parent");
    let package = root.path().join("package");
    prepared
        .publish_to_directory(&package, Vec::new())
        .expect("valid reviewed package publishes");
    fs::write(
        package.join("modules/core/migrations/required-field/steps/backfill.sql"),
        b"SELECT 'source-path-record-sql-canary'",
    )
    .expect("tamper reviewed SQL");
    assert_eq!(
        inspect_package_integrity(&package).err(),
        Some(PackageError::Integrity),
        "hash-covered reviewed SQL tampering must refuse before disclosure"
    );
}

#[derive(Clone)]
struct ReviewedArtifacts {
    descriptor: ReviewedMigrationDescriptor,
    receipt: MigrationRehearsalReceipt,
    step_sql: Vec<u8>,
    pre_sql: Vec<u8>,
    post_sql: Vec<u8>,
    backup: Option<ExternalBackupBinding>,
    fixture_bytes: Vec<u8>,
}

impl ReviewedArtifacts {
    fn rebind(&mut self) {
        let descriptor_bytes = canonical(&self.descriptor);
        self.receipt.fixture_inventory[0].path = format!(
            "modules/core/migrations/{}/fixtures/representative.jsonl",
            self.descriptor.id
        );
        self.receipt.plan_sha256 = digest(&descriptor_bytes);
        self.receipt.sql_sha256 = vec![ArtifactDigestBinding {
            path: self.descriptor.steps[0].sql_path().to_owned(),
            sha256: digest(&self.step_sql),
        }];
        self.receipt.assertion_sha256 = vec![
            ArtifactDigestBinding {
                path: self.descriptor.pre_assertions[0].sql_path.clone(),
                sha256: digest(&self.pre_sql),
            },
            ArtifactDigestBinding {
                path: self.descriptor.post_assertions[0].sql_path.clone(),
                sha256: digest(&self.post_sql),
            },
        ];
        self.receipt.fixture_inventory[0].sha256 = digest(&self.fixture_bytes);
        self.receipt.fixture_inventory[0].row_count = self
            .fixture_bytes
            .iter()
            .filter(|byte| **byte == b'\n')
            .count() as u64;
    }

    fn source(&self) -> ReviewedMigrationSource {
        let descriptor_path = format!(
            "modules/core/migrations/{}/descriptor.json",
            self.descriptor.id
        );
        let mut files = vec![
            ReviewedMigrationFile {
                path: self.descriptor.steps[0].sql_path().to_owned(),
                bytes: self.step_sql.clone(),
            },
            ReviewedMigrationFile {
                path: self.descriptor.pre_assertions[0].sql_path.clone(),
                bytes: self.pre_sql.clone(),
            },
            ReviewedMigrationFile {
                path: self.descriptor.post_assertions[0].sql_path.clone(),
                bytes: self.post_sql.clone(),
            },
            ReviewedMigrationFile {
                path: self.descriptor.rehearsal_receipt_path.clone(),
                bytes: canonical(&self.receipt),
            },
            ReviewedMigrationFile {
                path: self.receipt.fixture_inventory[0].path.clone(),
                bytes: self.fixture_bytes.clone(),
            },
        ];
        if let (Some(path), Some(binding)) = (&self.descriptor.backup_binding_path, &self.backup) {
            files.push(ReviewedMigrationFile {
                path: path.clone(),
                bytes: canonical(binding),
            });
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));
        ReviewedMigrationSource {
            module_id: "core".to_owned(),
            descriptor: ReviewedMigrationFile {
                path: descriptor_path,
                bytes: canonical(&self.descriptor),
            },
            files,
        }
    }
}

trait StepPath {
    fn sql_path(&self) -> &str;
    fn objects(&self) -> &[ReviewedMigrationObject];
    fn objects_mut(&mut self) -> &mut [ReviewedMigrationObject];
}

impl StepPath for ReviewedMigrationStepDescriptor {
    fn sql_path(&self) -> &str {
        match self {
            Self::TransactionalSql { sql_path, .. } | Self::ChunkedBackfill { sql_path, .. } => {
                sql_path
            }
        }
    }

    fn objects(&self) -> &[ReviewedMigrationObject] {
        match self {
            Self::TransactionalSql { objects, .. } | Self::ChunkedBackfill { objects, .. } => {
                objects
            }
        }
    }

    fn objects_mut(&mut self) -> &mut [ReviewedMigrationObject] {
        match self {
            Self::TransactionalSql { objects, .. } | Self::ChunkedBackfill { objects, .. } => {
                objects
            }
        }
    }
}

fn backfill_artifacts(
    id: &str,
    previous: &CompiledRegistry,
    candidate: &CompiledRegistry,
) -> ReviewedArtifacts {
    let change_set = compiled_registry_change_set(previous, candidate, PRIOR_REVISION);
    let change = change_set
        .changes
        .iter()
        .find(|change| change.code == CompiledRegistryChangeCode::FieldAddedRequired)
        .unwrap_or(&change_set.changes[0]);
    let entity = &candidate.entities()["asset"];
    let field = entity
        .fields
        .get("batch")
        .or_else(|| entity.fields.get("rank"))
        .expect("reviewed target field exists");
    let base = format!("modules/core/migrations/{id}");
    let step_path = format!("{base}/steps/backfill.sql");
    let pre_path = format!("{base}/assertions/pre.sql");
    let post_path = format!("{base}/assertions/post.sql");
    let step_sql = format!(
        "UPDATE registry_data.{} SET {} = 'reviewed-default' WHERE record_id = ANY($1::pg_catalog.uuid[])",
        entity.physical_table, field.physical_name
    )
    .into_bytes();
    let assertion_sql = format!(
        "SELECT pg_catalog.count(*) >= 0 FROM registry_data.{}",
        entity.physical_table
    )
    .into_bytes();
    let descriptor = ReviewedMigrationDescriptor {
        id: id.to_owned(),
        change_class: change.class,
        covers: vec![ReviewedChangeCover::from(change)],
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        lock_timeout_ms: 10_000,
        statement_timeout_ms: 60_000,
        steps: vec![ReviewedMigrationStepDescriptor::ChunkedBackfill {
            id: "backfill".to_owned(),
            entity_id: "asset".to_owned(),
            sql_path: step_path,
            objects: vec![ReviewedMigrationObject {
                schema: "registry_data".to_owned(),
                table: entity.physical_table.clone(),
                entity_id: "asset".to_owned(),
                kind: ReviewedMigrationObjectKind::Field,
                member_id: Some("batch".to_owned()),
                physical_name: field.physical_name.clone(),
            }],
            cursor: ChunkCursorProtocol::RecordIdUuidArray,
            chunk_size: 100,
            max_total_rows: 1_000,
            lock_timeout_ms: 1_000,
            statement_timeout_ms: 10_000,
            exact_affected_rows: true,
        }],
        pre_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "pre".to_owned(),
            sql_path: pre_path,
        }],
        post_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "post".to_owned(),
            sql_path: post_path,
        }],
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: None,
    };
    let mut artifacts = ReviewedArtifacts {
        descriptor,
        receipt: receipt(
            false,
            true,
            vec![RehearsalRowAssertion {
                step_id: "backfill".to_owned(),
                affected_rows: 10,
            }],
        ),
        step_sql,
        pre_sql: assertion_sql.clone(),
        post_sql: assertion_sql,
        backup: None,
        fixture_bytes: b"{\"fixture\":\"representative\"}\n".to_vec(),
    };
    artifacts.rebind();
    artifacts
}

fn destructive_artifacts(
    id: &str,
    previous: &CompiledRegistry,
    candidate: &CompiledRegistry,
) -> ReviewedArtifacts {
    let change_set = compiled_registry_change_set(previous, candidate, PRIOR_REVISION);
    let change = change_set
        .changes
        .iter()
        .find(|change| change.code == CompiledRegistryChangeCode::FieldRemoved)
        .expect("field removal is classified");
    let entity = &previous.entities()["asset"];
    let field = &entity.fields["rank"];
    let base = format!("modules/core/migrations/{id}");
    let step_path = format!("{base}/steps/drop-field.sql");
    let pre_path = format!("{base}/assertions/pre.sql");
    let post_path = format!("{base}/assertions/post.sql");
    let assertion_sql = format!(
        "SELECT pg_catalog.count(*) >= 0 FROM registry_data.{}",
        entity.physical_table
    )
    .into_bytes();
    let descriptor = ReviewedMigrationDescriptor {
        id: id.to_owned(),
        change_class: CompiledRegistryChangeClass::DestructiveOrIrreversible,
        covers: vec![ReviewedChangeCover::from(change)],
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        lock_timeout_ms: 10_000,
        statement_timeout_ms: 60_000,
        steps: vec![ReviewedMigrationStepDescriptor::TransactionalSql {
            id: "drop-field".to_owned(),
            sql_path: step_path,
            objects: vec![ReviewedMigrationObject {
                schema: "registry_data".to_owned(),
                table: entity.physical_table.clone(),
                entity_id: "asset".to_owned(),
                kind: ReviewedMigrationObjectKind::Field,
                member_id: Some("rank".to_owned()),
                physical_name: field.physical_name.clone(),
            }],
            affected_rows: None,
        }],
        pre_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "pre".to_owned(),
            sql_path: pre_path,
        }],
        post_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "post".to_owned(),
            sql_path: post_path,
        }],
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: Some(format!("{base}/backup.json")),
    };
    let mut artifacts = ReviewedArtifacts {
        descriptor,
        receipt: receipt(true, false, Vec::new()),
        step_sql: format!(
            "ALTER TABLE registry_data.{} DROP COLUMN {}",
            entity.physical_table, field.physical_name
        )
        .into_bytes(),
        pre_sql: assertion_sql.clone(),
        post_sql: assertion_sql,
        backup: Some(ExternalBackupBinding {
            database_id: DATABASE.to_owned(),
            prior_revision: PRIOR_REVISION.to_owned(),
            prior_schema_fingerprint: PRIOR_FINGERPRINT.to_owned(),
            sha256: "sha256:4444444444444444444444444444444444444444444444444444444444444444"
                .to_owned(),
            byte_length: 4096,
            created_at: "2026-08-30T00:00:00Z".to_owned(),
            max_age_seconds: 86_400,
        }),
        fixture_bytes: b"{\"fixture\":\"representative\"}\n".to_vec(),
    };
    artifacts.rebind();
    artifacts
}

fn receipt(
    destructive_resume: bool,
    chunk_resume: bool,
    row_assertions: Vec<RehearsalRowAssertion>,
) -> MigrationRehearsalReceipt {
    MigrationRehearsalReceipt {
        prior_revision: PRIOR_REVISION.to_owned(),
        prior_schema_fingerprint: PRIOR_FINGERPRINT.to_owned(),
        plan_sha256: String::new(),
        sql_sha256: Vec::new(),
        assertion_sha256: Vec::new(),
        fixture_inventory: vec![RehearsalFixture {
            id: "representative".to_owned(),
            path: String::new(),
            sha256: String::new(),
            row_count: 0,
        }],
        postgres_major: 17,
        row_assertions,
        final_schema_fingerprint: FINAL_FINGERPRINT.to_owned(),
        proofs: RehearsalProofs {
            lock_timeout: true,
            chunk_resume,
            destructive_resume,
        },
    }
}

fn assert_refused(
    candidate_variant: Variant,
    previous: CompiledRegistry,
    migrations: Vec<ReviewedMigrationSource>,
    label: &str,
) {
    let result = prepare_reviewed_package(candidate_variant, previous, migrations);
    assert_eq!(
        result.err(),
        Some(PackageError::MigrationPlan),
        "{label} must be refused with a value-free error"
    );
}

fn prepare_reviewed_package(
    candidate_variant: Variant,
    previous: CompiledRegistry,
    migrations: Vec<ReviewedMigrationSource>,
) -> registry_breg::package::Result<registry_breg::package::PreparedPackage> {
    let source = source_for_variant(candidate_variant, 2);
    prepare_package(PackageBuildRequest {
        environment: "local".to_owned(),
        instance_id: INSTANCE.to_owned(),
        database_id: DATABASE.to_owned(),
        sequence: 2,
        prior_revision: Some(PRIOR_REVISION.to_owned()),
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint: FINAL_FINGERPRINT.to_owned(),
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        },
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: source.project_bytes,
        },
        modules: vec![PackageModuleSource {
            id: "core".to_owned(),
            path: "source/modules/core/module.yaml".to_owned(),
            bytes: source.module_bytes,
            assets: Vec::new(),
        }],
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: FIXTURE_JOURNEYS.to_vec(),
        },
        migration_plan: PackageMigrationPlanInput::ReviewedSuccessor {
            prior_registry: Box::new(previous),
            prior_schema_fingerprint: PRIOR_FINGERPRINT.to_owned(),
            migrations,
        },
    })
}

#[derive(Clone, Copy)]
enum Variant {
    Base,
    RequiredField,
    FieldRemoved,
    DifferentRegistry,
}

struct SourceFixture {
    project_bytes: Vec<u8>,
    module_bytes: Vec<u8>,
}

fn compile_variant(variant: Variant, sequence: u64) -> CompiledRegistry {
    let source = source_for_variant(variant, sequence);
    let module = parse_module_yaml(&source.module_bytes).expect("fixture module parses");
    let project = parse_project_yaml(&source.project_bytes).expect("fixture project parses");
    compile_project(&project, &[module], CompileProfile::Production)
        .expect("fixture compiles in production")
}

fn source_for_variant(variant: Variant, sequence: u64) -> SourceFixture {
    let module_bytes = module_bytes(variant);
    let module = parse_module_yaml(&module_bytes).expect("fixture module parses for digest");
    let module_digest = module_digest(&module);
    let registry_id = if matches!(variant, Variant::DifferentRegistry) {
        "different-registry"
    } else {
        "neutral-registry"
    };
    SourceFixture {
        project_bytes: format!(
            r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"{registry_id}","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://package.example.test"}},"package":{{"environment":"local","instanceId":"{INSTANCE}","sequence":{sequence},"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"id":"neutral-registry-authority","name":"Package Test Publisher"}}}},"publicService":{{"id":"neutral-registry-service","title":"Neutral Registry Catalog"}},"datasets":[{{"id":"neutral-registry","title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}],"dataServices":[{{"id":"neutral-registry-data-service","title":"Neutral Registry Catalog","endpointUrl":"https://package.example.test","servesDatasets":["neutral-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
        )
        .into_bytes(),
        module_bytes,
    }
}

fn module_bytes(variant: Variant) -> Vec<u8> {
    let fields = match variant {
        Variant::RequiredField => {
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"batch","type":"string","maxLength":16,"required":true,"classification":"internal"}"#
        }
        Variant::FieldRemoved => {
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"}"#
        }
        Variant::Base | Variant::DifferentRegistry => {
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"}"#
        }
    };
    format!(
        r#"{{"id":"core","version":"1","entities":[{{"id":"asset","primaryDataset":"neutral-registry","route":"assets","mutationMode":"create_only","fields":[{fields}],"accessProfiles":[{{"id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]}}]}},{{"id":"site","primaryDataset":"neutral-registry","route":"sites","mutationMode":"create_only","fields":[{{"id":"code","type":"string","maxLength":8,"classification":"internal"}}],"accessProfiles":[{{"id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]}}]}}]}}"#
    )
    .into_bytes()
}

fn canonical(value: &impl Serialize) -> Vec<u8> {
    canonicalize_json(&serde_json::to_value(value).expect("test value serializes"))
        .expect("test value canonicalizes")
}

fn digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut result = String::with_capacity(71);
    result.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    result
}
