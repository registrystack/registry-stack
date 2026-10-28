// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "runtime", feature = "tooling"))]

use std::fs;

use registry_breg::compiler::{compile_project, module_digest, CompileProfile};
use registry_breg::contract::{parse_module_yaml, parse_project_yaml};
use registry_breg::generated_ddl::DdlStatementKind;
use registry_breg::migration_plan::{
    read_backup_binding_document, read_migration_descriptor, read_rehearsal_receipt,
    AffectedRowBounds, ArtifactDigestBinding, ChunkCursorProtocol, ExternalBackupBinding,
    MigrationRehearsalReceipt, RehearsalFixture, RehearsalRowAssertion, ReviewedChangeCover,
    ReviewedFieldEncryptionHistory, ReviewedMigrationAssertionDescriptor,
    ReviewedMigrationDescriptor, ReviewedMigrationError, ReviewedMigrationFile,
    ReviewedMigrationObject, ReviewedMigrationObjectKind, ReviewedMigrationRecovery,
    ReviewedMigrationSource, ReviewedMigrationStepDescriptor,
};
use registry_breg::package::{
    compiled_registry_change_set, inspect_package_integrity, prepare_package,
    CompiledRegistryChangeClass, CompiledRegistryChangeCode, PackageBuildRequest, PackageError,
    PackageFileRole, PackageMigrationPlanInput, PackageModuleSource, PackageSourceFile,
};
use registry_breg::CompiledRegistry;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::package::{
    write_sum_file, PackageLimits as SharedPackageLimits, REVISION_FILE, SUM_FILE,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const DATABASE: &str = "database-under-test";
const SOURCE_REVISION: &str = "compiler-source-revision";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: asset-list
    steps:
      - id: list-assets
        recordType: asset
        accessProfile: reader
        claims: {principal: package-reader}
        request: {type: list}
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
    let previous = compile_variant(Variant::Base);
    let candidate = compile_variant(Variant::RequiredField);
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
        .publish_to_directory(&package)
        .expect("reviewed package publishes");
    let inspected = inspect_package_integrity(&package).expect("reviewed package rederives");
    assert_eq!(
        inspected.package_digest(),
        prepared
            .package_digest()
            .expect("prepared package plans its digest")
    );

    let destructive_candidate = compile_variant(Variant::FieldRemoved);
    let destructive = destructive_artifacts(
        "remove-field",
        &compile_variant(Variant::Base),
        &destructive_candidate,
    );
    let destructive_package = prepare_reviewed_package(
        Variant::FieldRemoved,
        compile_variant(Variant::Base),
        vec![destructive.source()],
    )
    .expect("destructive plan naming its backup binding prepares");
    let backup_path = "modules/core/migrations/remove-field/backup.json";
    assert!(!destructive_package
        .manifest()
        .files
        .iter()
        .any(|file| file.path == backup_path));
    let destructive_plan = destructive_package
        .reviewed_migration_plan()
        .expect("destructive plan revalidates")
        .expect("destructive package carries a reviewed plan");
    assert_eq!(
        registry_breg::migration::required_backup_binding_paths(&destructive_plan),
        vec![backup_path]
    );
}

#[test]
fn reviewed_package_whose_receipt_carries_the_retired_proofs_is_refused() {
    let previous = compile_variant(Variant::Base);
    let candidate = compile_variant(Variant::RequiredField);
    let artifacts = backfill_artifacts("required-field", &previous, &candidate);
    let mut source = artifacts.source();
    let mut receipt = serde_json::to_value(&artifacts.receipt).expect("receipt serializes");
    receipt["proofs"] = serde_json::json!({
        "lockTimeout": true,
        "chunkResume": true,
        "destructiveResume": false,
    });
    let receipt_file = source
        .files
        .iter_mut()
        .find(|file| file.path == artifacts.descriptor.rehearsal_receipt_path)
        .expect("source carries the rehearsal receipt");
    receipt_file.bytes = canonical(&receipt);
    assert_refused(
        Variant::RequiredField,
        previous,
        vec![source],
        ReviewedMigrationError::Evidence,
        "a receipt carrying the retired proofs",
    );

    let report = read_rehearsal_receipt("rehearsal.json", &canonical(&receipt))
        .expect_err("the reader refuses the retired proofs");
    let diagnostics = report.diagnostics();
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    assert_eq!(diagnostics[0].code, "config.removed-key");
    assert_eq!(diagnostics[0].path, "/proofs");
    assert!(diagnostics[0].suggested_action.contains("Delete `proofs`"));
    assert!(diagnostics[0]
        .source
        .as_ref()
        .is_some_and(|source| source.line.is_some()));
}

#[test]
fn reviewed_migration_receipt_refuses_postgresql_16() {
    let previous = compile_variant(Variant::Base);
    let candidate = compile_variant(Variant::RequiredField);
    let artifacts = backfill_artifacts("required-field", &previous, &candidate);
    let mut source = artifacts.source();
    let mut receipt = serde_json::to_value(&artifacts.receipt).expect("receipt serializes");
    receipt["postgresMajor"] = serde_json::json!(16);
    let bytes = canonical(&receipt);
    source
        .files
        .iter_mut()
        .find(|file| file.path == artifacts.descriptor.rehearsal_receipt_path)
        .expect("source carries the rehearsal receipt")
        .bytes = bytes.clone();

    assert_refused(
        Variant::RequiredField,
        previous,
        vec![source],
        ReviewedMigrationError::Evidence,
        "a PostgreSQL 16 migration rehearsal receipt",
    );
    let report = read_rehearsal_receipt("rehearsal.json", &bytes)
        .expect_err("the receipt reader refuses PostgreSQL 16");
    assert_eq!(report.diagnostics().len(), 1, "{report:?}");
    assert_eq!(report.diagnostics()[0].code, "config.out-of-range");
    assert_eq!(report.diagnostics()[0].path, "/postgresMajor");
}

#[test]
fn reviewed_migration_record_type_references_have_one_positioned_spelling() {
    let previous = compile_variant(Variant::Base);
    let candidate = compile_variant(Variant::RequiredField);
    let artifacts = backfill_artifacts("required-field", &previous, &candidate);
    let descriptor = serde_json::to_value(&artifacts.descriptor).unwrap();
    for parent in ["/steps/0", "/steps/0/objects/0"] {
        assert_eq!(
            descriptor.pointer(&format!("{parent}/recordType")),
            Some(&serde_json::json!("asset"))
        );
        for old in ["entity", "entityId"] {
            for value in [serde_json::json!("asset"), serde_json::Value::Null] {
                let mut document = descriptor.clone();
                let members = document
                    .pointer_mut(parent)
                    .unwrap()
                    .as_object_mut()
                    .unwrap();
                members.remove("recordType");
                members.insert(old.to_owned(), value);
                let report = read_migration_descriptor("descriptor.json", &canonical(&document))
                    .expect_err("previous reference is refused");
                let diagnostic = report
                    .diagnostics()
                    .iter()
                    .find(|diagnostic| diagnostic.code == "config.removed-key")
                    .expect("migration guidance is present");
                assert_eq!(diagnostic.path, format!("{parent}/{old}"));
                assert!(diagnostic.suggested_action.contains("recordType"));
                assert!(diagnostic.source.as_ref().unwrap().line.is_some());
            }
        }
    }
}

#[test]
fn reviewed_migration_documents_refuse_their_previous_spellings_at_each_key() {
    let previous = compile_variant(Variant::Base);
    let candidate = compile_variant(Variant::RequiredField);
    let artifacts = backfill_artifacts("required-field", &previous, &candidate);
    let mut descriptor =
        serde_json::to_value(&artifacts.descriptor).expect("descriptor serializes");
    let lock_timeout = descriptor["lockTimeoutMilliseconds"].take();
    descriptor
        .as_object_mut()
        .expect("descriptor is an object")
        .remove("lockTimeoutMilliseconds");
    descriptor["lockTimeoutMs"] = lock_timeout;
    let step = &mut descriptor["steps"][0];
    let entity = step["recordType"].take();
    step.as_object_mut()
        .expect("step is an object")
        .remove("recordType");
    step["entity_id"] = entity;
    let report = read_migration_descriptor("descriptor.json", &canonical(&descriptor))
        .expect_err("the reader refuses the previous spellings");
    let removed: Vec<(&str, &str)> = report
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect();
    assert!(
        removed.contains(&("config.removed-key", "/lockTimeoutMs")),
        "{removed:?}"
    );
    assert!(
        removed.contains(&("config.removed-key", "/steps/0/entity_id")),
        "{removed:?}"
    );

    let mut receipt = serde_json::to_value(&artifacts.receipt).expect("receipt serializes");
    let item = &mut receipt["sqlDigests"][0];
    let sql_digest = item["digest"].take();
    item.as_object_mut()
        .expect("digest item is an object")
        .remove("digest");
    item["sha256"] = sql_digest;
    let report = read_rehearsal_receipt("rehearsal.json", &canonical(&receipt))
        .expect_err("the reader refuses the previous digest item spelling");
    assert!(report
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "config.removed-key"
            && diagnostic.path == "/sqlDigests/0/sha256"
            && diagnostic.suggested_action.contains("`digest`")));

    let mut binding = serde_json::json!({
        "apiVersion": registry_breg::migration_plan::BACKUP_BINDING_API_VERSION,
        "kind": registry_breg::migration_plan::BACKUP_BINDING_KIND,
        "databaseId": DATABASE,
    });
    binding["backupFile"] = serde_json::Value::String("/backups/prior.dump".to_owned());
    let report = read_backup_binding_document("binding.json", &canonical(&binding))
        .expect_err("the reader refuses the previous binding spelling");
    assert!(report
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "config.removed-key"
            && diagnostic.path == "/databaseId"
            && diagnostic.suggested_action.contains("`database`")));
}

#[test]
fn reviewed_migration_member_ids_refuse_separator_collisions_across_collections() {
    let previous = compile_variant(Variant::Base);
    let candidate = compile_variant(Variant::RequiredField);
    let artifacts = backfill_artifacts("required-field", &previous, &candidate);
    let descriptor = serde_json::to_value(&artifacts.descriptor).expect("descriptor serializes");

    for (first, second) in [
        ("/steps/0/id", "/preAssertions/0/id"),
        ("/steps/0/id", "/postAssertions/0/id"),
        ("/preAssertions/0/id", "/postAssertions/0/id"),
    ] {
        let mut changed = descriptor.clone();
        *changed.pointer_mut(first).expect("first identifier exists") =
            serde_json::Value::from("review-state");
        *changed
            .pointer_mut(second)
            .expect("second identifier exists") = serde_json::Value::from("review_state");
        let report = read_migration_descriptor(
            "descriptor.json",
            &serde_json::to_vec_pretty(&changed).unwrap(),
        )
        .expect_err("separator-lookalike step and assertion IDs are refused");
        let diagnostic = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "breg.migration.identifier-collision")
            .unwrap_or_else(|| panic!("missing identifier collision: {}", report.render_human()));
        assert_eq!(diagnostic.path, second);
        let source = diagnostic.source.as_ref().expect("second ID is positioned");
        assert_eq!(source.file, "descriptor.json");
        assert!(source.line.is_some());
        assert!(source.column.is_some());
        assert_eq!(diagnostic.related.len(), 1);
        assert_eq!(diagnostic.related[0].path, first);
        assert_eq!(diagnostic.related[0].file, "descriptor.json");
        assert!(diagnostic.related[0].line.is_some());
        assert!(diagnostic.related[0].column.is_some());
    }
}

/// Every word a descriptor enumerates is written in kebab-case (CFG-NAME-2).
/// A word in snake_case is refused where it is written, the refusal names
/// the accepted word, and it never repeats the refused one (CFG-SEC-3).
#[test]
fn reviewed_descriptor_refuses_the_snake_case_spelling_of_each_enumerated_word() {
    let previous = compile_variant(Variant::Base);
    let candidate = compile_variant(Variant::RequiredField);
    let artifacts = backfill_artifacts("required-field", &previous, &candidate);
    let descriptor = serde_json::to_value(&artifacts.descriptor).expect("descriptor serializes");
    assert_eq!(descriptor["changeClass"], "data-backfill-required");
    assert_eq!(descriptor["covers"][0]["code"], "field-added-required");
    assert_eq!(descriptor["covers"][0]["target"]["kind"], "field");
    assert_eq!(descriptor["recovery"], "exact-target-resume");
    read_migration_descriptor("descriptor.json", &canonical(&descriptor))
        .expect("the reader accepts the descriptor it wrote");

    for (pointer, refused, action) in [
        (
            "/changeClass",
            "data_backfill_required",
            "Use `data-backfill-required`, the closest accepted value.",
        ),
        (
            "/covers/0/code",
            "field_added_required",
            "Use `field-added-required`, the closest accepted value.",
        ),
        (
            "/covers/0/target/kind",
            "access_profile",
            "Use `access-profile`, the closest accepted value.",
        ),
        (
            "/recovery",
            "exact_target_resume",
            "Use `exact-target-resume`, the closest accepted value.",
        ),
    ] {
        let mut changed = descriptor.clone();
        *changed
            .pointer_mut(pointer)
            .expect("the descriptor holds the member") = serde_json::Value::from(refused);
        let report = read_migration_descriptor("descriptor.json", &canonical(&changed))
            .expect_err("the reader refuses a snake_case word");
        let diagnostics = report.diagnostics();
        assert_eq!(diagnostics.len(), 1, "{pointer}: {diagnostics:?}");
        assert_eq!(diagnostics[0].code, "config.unknown-variant", "{pointer}");
        assert_eq!(diagnostics[0].path, pointer);
        assert_eq!(diagnostics[0].suggested_action, action, "{pointer}");
        assert!(
            !format!("{diagnostics:?}").contains(refused),
            "{pointer}: the refusal repeats the refused word"
        );
    }

    let mut unknown = descriptor.clone();
    unknown["covers"][0]["target"]["unknownMember"] = serde_json::Value::from(true);
    let report = read_migration_descriptor("descriptor.json", &canonical(&unknown))
        .expect_err("the reader refuses an unknown member");
    let diagnostics = report.diagnostics();
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    assert_eq!(diagnostics[0].code, "config.unknown-key");
    assert_eq!(diagnostics[0].path, "/covers/0/target/unknownMember");
}

#[test]
fn reviewed_descriptor_reformatted_by_hand_keeps_its_rehearsal_binding() {
    let previous = compile_variant(Variant::Base);
    let candidate = compile_variant(Variant::RequiredField);
    let artifacts = backfill_artifacts("required-field", &previous, &candidate);
    let mut source = artifacts.source();
    let value = serde_json::to_value(&artifacts.descriptor).expect("descriptor serializes");
    let pretty = serde_json::to_vec_pretty(&value).expect("descriptor pretty prints");
    assert_ne!(
        pretty, source.descriptor.bytes,
        "the reformatted bytes differ"
    );
    source.descriptor.bytes = pretty;
    prepare_reviewed_package(Variant::RequiredField, previous, vec![source])
        .expect("the receipt binds the descriptor's canonical JSON, not its bytes");
}

#[test]
fn reviewed_migration_plan_rejects_uncovered_changes_forbidden_sql_and_unbound_evidence() {
    let previous = compile_variant(Variant::Base);
    let candidate = compile_variant(Variant::RequiredField);
    let valid = backfill_artifacts("required-field", &previous, &candidate);

    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        Vec::new(),
        ReviewedMigrationError::Coverage,
        "uncovered non-additive change",
    );

    let mut uncovered = valid.clone();
    uncovered.descriptor.covers.clear();
    uncovered.rebind();
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![uncovered.source()],
        ReviewedMigrationError::Descriptor,
        "missing covers set",
    );

    let mut orphan = valid.clone();
    orphan.descriptor.covers[0].code = CompiledRegistryChangeCode::EntityRemoved;
    orphan.rebind();
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![orphan.source()],
        ReviewedMigrationError::Coverage,
        "orphan cover",
    );

    let duplicate = backfill_artifacts("required-field-two", &previous, &candidate);
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![valid.source(), duplicate.source()],
        ReviewedMigrationError::Descriptor,
        "duplicate cover",
    );

    let mut mismatch = valid.clone();
    mismatch.descriptor.change_class = CompiledRegistryChangeClass::DestructiveOrIrreversible;
    mismatch.rebind();
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![mismatch.source()],
        ReviewedMigrationError::Coverage,
        "class-mismatched cover",
    );

    let unsupported_previous = compile_variant(Variant::Base);
    let unsupported_candidate = compile_variant(Variant::DifferentRegistry);
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
        ReviewedMigrationError::Coverage,
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
            ReviewedMigrationError::Sql,
            label,
        );
    }

    let mut unbounded_dml = valid.clone();
    let objects = unbounded_dml.descriptor.steps[0].objects().to_vec();
    unbounded_dml.descriptor.steps[0] = ReviewedMigrationStepDescriptor::TransactionalSql {
        id: "backfill".to_owned(),
        sql_path: unbounded_dml.descriptor.steps[0]
            .sql_path()
            .expect("the chunked artifact binds a SQL path")
            .to_owned(),
        objects,
        affected_rows: None,
    };
    unbounded_dml.rebind();
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![unbounded_dml.source()],
        ReviewedMigrationError::Sql,
        "DML without affected-row bounds",
    );

    let mut non_boolean_assertion = valid.clone();
    non_boolean_assertion.pre_sql = b"SELECT 1".to_vec();
    non_boolean_assertion.rebind();
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![non_boolean_assertion.source()],
        ReviewedMigrationError::Sql,
        "assertion is not one declared read-only boolean SELECT",
    );

    let mut object_mismatch = valid.clone();
    object_mismatch.descriptor.steps[0].objects_mut()[0].member_id = Some("rank".to_owned());
    object_mismatch.rebind();
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![object_mismatch.source()],
        ReviewedMigrationError::Sql,
        "descriptor cover and parsed object inventory mismatch",
    );

    let mut unbound = valid.clone();
    unbound.receipt.final_schema_fingerprint =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![unbound.source()],
        ReviewedMigrationError::Evidence,
        "rehearsal evidence bound to wrong target",
    );

    let destructive_candidate = compile_variant(Variant::FieldRemoved);
    let destructive = destructive_artifacts("remove-field", &previous, &destructive_candidate);
    let mut no_backup = destructive.clone();
    no_backup.descriptor.backup_binding_path = None;
    no_backup.rebind();
    assert_refused(
        Variant::FieldRemoved,
        previous.clone(),
        vec![no_backup.source()],
        ReviewedMigrationError::Evidence,
        "destructive plan without external backup binding",
    );

    let mut packaged_backup = destructive.source();
    packaged_backup.files.push(ReviewedMigrationFile {
        path: "modules/core/migrations/remove-field/backup.json".to_owned(),
        bytes: canonical(&ExternalBackupBinding {
            database_id: DATABASE.to_owned(),
            prior_package_digest: PRIOR_REVISION.to_owned(),
            prior_schema_fingerprint: PRIOR_FINGERPRINT.to_owned(),
            backup_file: "/var/backups/registry.dump".to_owned(),
            sha256: "sha256:4444444444444444444444444444444444444444444444444444444444444444"
                .to_owned(),
            byte_length: 4096,
            created_at: "2026-08-30T00:00:00Z".to_owned(),
            max_age_seconds: 86_400,
        }),
    });
    packaged_backup
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    assert_refused(
        Variant::FieldRemoved,
        previous.clone(),
        vec![packaged_backup],
        ReviewedMigrationError::Closure,
        "backup binding shipped inside the package",
    );

    let mut missing_fixture = valid.source();
    missing_fixture
        .files
        .retain(|file| !file.path.ends_with("fixtures/representative.jsonl"));
    assert_refused(
        Variant::RequiredField,
        previous.clone(),
        vec![missing_fixture],
        ReviewedMigrationError::Evidence,
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
        ReviewedMigrationError::Evidence,
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
        ReviewedMigrationError::Coverage,
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
        .publish_to_directory(&package)
        .expect("valid reviewed package publishes");
    fs::write(
        package.join("modules/core/migrations/required-field/steps/backfill.sql"),
        b"SELECT 'source-path-record-sql-canary'",
    )
    .expect("tamper reviewed SQL");
    refresh_shared_package_envelope(&package);
    assert_eq!(
        inspect_package_integrity(&package).err(),
        Some(PackageError::Integrity),
        "hash-covered reviewed SQL tampering must refuse before disclosure"
    );
}

#[test]
fn reviewed_encryption_flip_binds_envelope_blind_index_and_views() {
    let previous = compile_variant(Variant::EncryptedBase);
    let candidate = compile_variant(Variant::EncryptedFlipOn);

    // The flip is one backfill-classified change, never a physical rename.
    let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
    assert_eq!(change_set.changes.len(), 1);
    assert_eq!(
        (change_set.changes[0].code, change_set.changes[0].class),
        (
            CompiledRegistryChangeCode::FieldEncryptionChanged,
            CompiledRegistryChangeClass::DataBackfillRequired
        )
    );

    let artifacts = encryption_flip_artifacts("encryption-flip", &previous, &candidate);
    let prepared =
        prepare_reviewed_package(Variant::EncryptedFlipOn, previous, vec![artifacts.source()])
            .expect("reviewed encryption flip prepares");

    assert_eq!(
        prepared.manifest().migration_plan.reviewed_descriptors,
        vec!["modules/core/migrations/encryption-flip/descriptor.json"]
    );
    let statements = &prepared.manifest().migration_plan.statements;
    let entity = &candidate.entities()["asset"];
    let field = &entity.fields["secret"];
    let envelope = &field.physical_name;
    let blind = field
        .encryption
        .as_ref()
        .and_then(|encryption| encryption.blind_index.as_ref())
        .expect("the flip candidate declares a blind index");

    // The envelope column arrives under the field's own member, the blind
    // sibling under its lookup member, both nullable bytea ahead of the
    // reviewed backfill that fills them.
    let envelope_column = statement(statements, "entity.asset.field.secret.column");
    assert_eq!(envelope_column.kind, DdlStatementKind::Column);
    assert!(envelope_column
        .sql
        .contains(&format!("ADD COLUMN \"{envelope}\" bytea")));
    let blind_column = statement(statements, "entity.asset.field.secret.lookup-column");
    assert_eq!(blind_column.kind, DdlStatementKind::Column);
    assert_eq!(
        blind_column.sql,
        format!(
            "ALTER TABLE registry_data.\"{}\" ADD COLUMN \"{}\" bytea",
            entity.physical_table, blind.physical_name
        )
    );
    // The optional flip field defers nothing: no NOT NULL interlock exists.
    assert!(statements
        .iter()
        .all(|statement| statement.id != "entity.asset.field.secret.column.not-null"));
    let lookup_index = statement(statements, "entity.asset.field.secret.lookup-unique");
    assert_eq!(lookup_index.kind, DdlStatementKind::Index);
    assert!(lookup_index.sql.starts_with("CREATE UNIQUE INDEX "));

    // The registry_source view never exposes the envelope or its blind index.
    let source_view = statement(statements, "entity.asset.source-view");
    assert_eq!(source_view.kind, DdlStatementKind::View);
    assert!(!source_view.sql.contains(envelope));
    assert!(!source_view.sql.contains(&blind.physical_name));
}

#[test]
fn reviewed_encryption_flip_refuses_a_missing_history_choice() {
    let previous = compile_variant(Variant::EncryptedBase);
    let candidate = compile_variant(Variant::EncryptedFlipOn);
    let mut artifacts = encryption_flip_artifacts("encryption-flip", &previous, &candidate);
    // The choice is explicit or absent, never assumed: dropping it from an
    // otherwise complete flip plan refuses rather than defaulting.
    artifacts.descriptor.history = None;
    artifacts.rebind();
    assert_refused(
        Variant::EncryptedFlipOn,
        previous,
        vec![artifacts.source()],
        ReviewedMigrationError::Descriptor,
        "an encryption flip without an explicit history choice",
    );
}

#[test]
fn reviewed_encryption_flip_refuses_an_unknown_history_choice() {
    let previous = compile_variant(Variant::EncryptedBase);
    let candidate = compile_variant(Variant::EncryptedFlipOn);
    let artifacts = encryption_flip_artifacts("encryption-flip", &previous, &candidate);
    let mut source = artifacts.source();
    // The wire grammar is the two reviewed choices alone: a third word is
    // refused at parse, before any binding or digest is consulted.
    let mut descriptor =
        serde_json::to_value(&artifacts.descriptor).expect("the descriptor serializes");
    descriptor["history"] = serde_json::Value::String("scrub-everything".to_owned());
    source.descriptor.bytes = canonical(&descriptor);
    assert_refused(
        Variant::EncryptedFlipOn,
        previous,
        vec![source],
        ReviewedMigrationError::Descriptor,
        "an unknown history choice value",
    );
}

#[test]
fn reviewed_plan_refuses_a_history_choice_without_an_encryption_flip() {
    let previous = compile_variant(Variant::Base);
    let candidate = compile_variant(Variant::RequiredField);
    let mut artifacts = backfill_artifacts("required-field", &previous, &candidate);
    // The choice says what happens to pre-flip plaintext history; a plan that
    // flips nothing has nothing to choose, so the word alone refuses.
    artifacts.descriptor.history = Some(ReviewedFieldEncryptionHistory::RetainPlaintextHistory);
    artifacts.rebind();
    assert_refused(
        Variant::RequiredField,
        previous,
        vec![artifacts.source()],
        ReviewedMigrationError::Descriptor,
        "a history choice on a plan without a field-encryption flip",
    );
}

#[test]
fn reviewed_encryption_flip_refuses_a_chunk_size_beyond_the_commit_budget() {
    let previous = compile_variant(Variant::EncryptedBase);
    let candidate = compile_variant(Variant::EncryptedFlipOn);
    let mut artifacts = encryption_flip_artifacts("encryption-flip", &previous, &candidate);
    // One chunk journals one history commit, so its size is capped at the
    // history machinery's commit-member budget rather than the chunked-SQL cap.
    let ReviewedMigrationStepDescriptor::FieldEncryptionBackfill { chunk_size, .. } =
        &mut artifacts.descriptor.steps[0]
    else {
        panic!("the flip step is the engine-executed backfill");
    };
    *chunk_size = 1_001;
    artifacts.rebind();
    assert_refused(
        Variant::EncryptedFlipOn,
        previous,
        vec![artifacts.source()],
        ReviewedMigrationError::Descriptor,
        "a field-encryption chunk size beyond the commit-member budget",
    );
}

#[test]
fn reviewed_chunked_backfill_refuses_a_chunk_size_beyond_the_commit_budget() {
    let previous = compile_variant(Variant::Base);
    let candidate = compile_variant(Variant::RequiredField);
    let mut artifacts = backfill_artifacts("required-field", &previous, &candidate);
    // Every chunk journals the rows it changed as one history commit, so a
    // chunked backfill shares the commit-member budget too.
    let ReviewedMigrationStepDescriptor::ChunkedBackfill { chunk_size, .. } =
        &mut artifacts.descriptor.steps[0]
    else {
        panic!("the backfill step is chunked");
    };
    *chunk_size = 1_000;
    artifacts.rebind();
    prepare_reviewed_package(
        Variant::RequiredField,
        previous.clone(),
        vec![artifacts.source()],
    )
    .expect("a chunk size at the commit-member budget prepares");

    let ReviewedMigrationStepDescriptor::ChunkedBackfill { chunk_size, .. } =
        &mut artifacts.descriptor.steps[0]
    else {
        panic!("the backfill step is chunked");
    };
    *chunk_size = 1_001;
    artifacts.rebind();
    assert_refused(
        Variant::RequiredField,
        previous,
        vec![artifacts.source()],
        ReviewedMigrationError::Descriptor,
        "a chunked backfill chunk size beyond the commit-member budget",
    );
}

#[test]
fn reviewed_encryption_flip_refuses_multiple_backfill_steps_for_one_entity() {
    let previous = compile_variant(Variant::EncryptedBase);
    let candidate = compile_variant(Variant::EncryptedFlipOn);
    let mut artifacts = encryption_flip_artifacts("encryption-flip", &previous, &candidate);
    let mut second = artifacts.descriptor.steps[0].clone();
    let ReviewedMigrationStepDescriptor::FieldEncryptionBackfill { id, .. } = &mut second else {
        panic!("the flip step is the engine-executed backfill");
    };
    *id = "backfill-second".to_owned();
    artifacts.descriptor.steps.push(second);
    artifacts
        .receipt
        .row_assertions
        .push(RehearsalRowAssertion {
            step_id: "backfill-second".to_owned(),
            affected_rows: 10,
        });
    artifacts.rebind();

    assert_refused(
        Variant::EncryptedFlipOn,
        previous,
        vec![artifacts.source()],
        ReviewedMigrationError::Coverage,
        "multiple field-encryption steps for one entity",
    );
}

#[test]
fn reviewed_encryption_flip_refuses_plaintext_drop_before_backfill() {
    let previous = compile_variant(Variant::EncryptedBase);
    let candidate = compile_variant(Variant::EncryptedFlipOn);
    let mut artifacts = encryption_flip_artifacts("encryption-flip", &previous, &candidate);
    let entity = &previous.entities()["asset"];
    let plaintext = &entity.fields["secret"];
    let step_path = "modules/core/migrations/encryption-flip/steps/drop-plaintext.sql".to_owned();
    artifacts.descriptor.steps.insert(
        0,
        ReviewedMigrationStepDescriptor::TransactionalSql {
            id: "drop-plaintext".to_owned(),
            sql_path: step_path,
            objects: vec![ReviewedMigrationObject {
                schema: "registry_data".to_owned(),
                table: entity.physical_table.clone(),
                entity_id: "asset".to_owned(),
                kind: ReviewedMigrationObjectKind::Field,
                member_id: Some("secret".to_owned()),
                physical_name: plaintext.physical_name.clone(),
            }],
            affected_rows: None,
        },
    );
    artifacts.step_sql = format!(
        "ALTER TABLE registry_data.{} DROP COLUMN {}",
        entity.physical_table, plaintext.physical_name
    )
    .into_bytes();
    artifacts.rebind();
    assert_refused(
        Variant::EncryptedFlipOn,
        previous,
        vec![artifacts.source()],
        ReviewedMigrationError::Descriptor,
        "dropping the plaintext column before its sealing backfill",
    );
}

#[test]
fn reviewed_sql_updates_refuse_predecessor_or_successor_timer_fields_without_values() {
    for field in [
        "activates-at",
        "activation-window-end",
        "activation-revision",
        "eligible",
    ] {
        for timer_side in [TimerSide::Predecessor, TimerSide::Successor] {
            for step_kind in [
                TimerUpdateStepKind::Transactional,
                TimerUpdateStepKind::Chunked,
            ] {
                let previous_source =
                    timer_migration_source(timer_side.predecessor_fields(), None, false);
                let candidate_source =
                    timer_migration_source(timer_side.successor_fields(), Some(field), false);
                let previous = compile_source(&previous_source);
                let candidate = compile_source(&candidate_source);
                let artifacts = timer_field_update_artifacts(
                    &format!("timer-{field}-{}-{}", timer_side.id(), step_kind.id()),
                    &previous,
                    &candidate,
                    field,
                    step_kind,
                );
                let error = prepare_reviewed_package_from_source(
                    candidate_source,
                    previous,
                    vec![artifacts.source()],
                )
                .expect_err("reviewed SQL cannot update a timer control or predicate field");
                let expected = ReviewedMigrationError::TimerFieldUpdate {
                    entity_id: "asset".to_owned(),
                    field_id: field.to_owned(),
                };
                assert_eq!(error, PackageError::ReviewedMigration(expected.clone()));
                let diagnostic = expected.to_string();
                assert!(diagnostic.contains("asset"), "{diagnostic}");
                assert!(diagnostic.contains(field), "{diagnostic}");
                assert!(
                    !diagnostic.contains("migration-value-canary"),
                    "{diagnostic}"
                );
                assert!(!diagnostic.contains("UPDATE"), "{diagnostic}");
            }
        }
    }
}

#[test]
fn reviewed_sql_update_preserves_unrelated_fields_and_logical_encryption() {
    for step_kind in [
        TimerUpdateStepKind::Transactional,
        TimerUpdateStepKind::Chunked,
    ] {
        let previous_source = timer_migration_source(TimerFieldSet::Primary, None, false);
        let candidate_source = timer_migration_source(TimerFieldSet::Primary, Some("code"), false);
        let previous = compile_source(&previous_source);
        let candidate = compile_source(&candidate_source);
        let artifacts = timer_field_update_artifacts(
            &format!("unrelated-code-{}", step_kind.id()),
            &previous,
            &candidate,
            "code",
            step_kind,
        );
        let sources = reviewed_timer_sources(
            artifacts.source(),
            timer_metadata_review_source(
                &format!("zz-timer-code-{}", step_kind.id()),
                &previous,
                &candidate,
            ),
        );
        prepare_reviewed_package_from_source(candidate_source, previous, sources)
            .expect("reviewed SQL may update a field unrelated to timer control or predicates");
    }

    let previous_source = timer_migration_source(TimerFieldSet::Primary, None, false);
    let candidate_source = timer_migration_source(TimerFieldSet::Primary, None, true);
    let previous = compile_source(&previous_source);
    let candidate = compile_source(&candidate_source);
    let artifacts = encryption_flip_artifacts("timer-predicate-encryption", &previous, &candidate);
    let sources = reviewed_timer_sources(
        artifacts.source(),
        timer_metadata_review_source("zz-timer-predicate-encryption", &previous, &candidate),
    );
    prepare_reviewed_package_from_source(candidate_source, previous, sources)
        .expect("engine-owned logical encryption may seal a timer predicate field");
}

#[test]
fn reviewed_alter_type_refuses_timer_fields_but_preserves_unrelated_and_non_data_ddl() {
    let previous_source = timer_migration_source(TimerFieldSet::Primary, None, false);
    let candidate_source = timer_migration_source(TimerFieldSet::Primary, Some("eligible"), false);
    let previous = compile_source(&previous_source);
    let candidate = compile_source(&candidate_source);
    let artifacts = timer_alter_table_artifacts(
        "timer-alter-type",
        &previous,
        &candidate,
        "eligible",
        &[TimerAlterCommand::Type("eligible")],
    );
    let error =
        prepare_reviewed_package_from_source(candidate_source, previous, vec![artifacts.source()])
            .expect_err("ALTER COLUMN TYPE cannot rewrite a timer predicate field");
    let expected = ReviewedMigrationError::TimerFieldUpdate {
        entity_id: "asset".to_owned(),
        field_id: "eligible".to_owned(),
    };
    assert_eq!(error, PackageError::ReviewedMigration(expected.clone()));
    let diagnostic = expected.to_string();
    assert!(diagnostic.contains("asset"), "{diagnostic}");
    assert!(diagnostic.contains("eligible"), "{diagnostic}");
    assert!(
        !diagnostic.contains("migration-value-canary"),
        "{diagnostic}"
    );

    let previous_source = timer_migration_source(TimerFieldSet::Primary, None, false);
    let candidate_source = timer_migration_source(TimerFieldSet::Primary, Some("code"), false);
    let previous = compile_source(&previous_source);
    let candidate = compile_source(&candidate_source);
    let artifacts = timer_alter_table_artifacts(
        "unrelated-alter-type",
        &previous,
        &candidate,
        "code",
        &[TimerAlterCommand::Type("code")],
    );
    let sources = reviewed_timer_sources(
        artifacts.source(),
        timer_metadata_review_source("zz-unrelated-alter-type", &previous, &candidate),
    );
    prepare_reviewed_package_from_source(candidate_source, previous, sources)
        .expect("ALTER COLUMN TYPE may rewrite a field unrelated to timer policy");

    let previous_source = timer_migration_source(TimerFieldSet::Primary, None, false);
    let candidate_source = timer_migration_source_with_required_fields(
        TimerFieldSet::Primary,
        &["code", "eligible"],
        false,
    );
    let previous = compile_source(&previous_source);
    let candidate = compile_source(&candidate_source);
    let artifacts = timer_alter_table_artifacts(
        "mixed-alter-table",
        &previous,
        &candidate,
        "eligible",
        &[
            TimerAlterCommand::SetNotNull("eligible"),
            TimerAlterCommand::Type("code"),
        ],
    );
    let sources = reviewed_timer_sources(
        artifacts.source(),
        timer_metadata_review_source("zz-mixed-alter-table", &previous, &candidate),
    );
    prepare_reviewed_package_from_source(candidate_source, previous, sources)
        .expect("an unrelated type rewrite does not turn timer-field non-data DDL into a rewrite");
}

fn statement<'a>(
    statements: &'a [registry_breg::generated_ddl::DdlStatement],
    id: &str,
) -> &'a registry_breg::generated_ddl::DdlStatement {
    statements
        .iter()
        .find(|statement| statement.id == id)
        .unwrap_or_else(|| panic!("the plan carries the {id} statement"))
}

#[derive(Clone)]
struct ReviewedArtifacts {
    descriptor: ReviewedMigrationDescriptor,
    receipt: MigrationRehearsalReceipt,
    step_sql: Vec<u8>,
    pre_sql: Vec<u8>,
    post_sql: Vec<u8>,
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
        // The engine-executed backfill binds no SQL artifact, so the receipt
        // carries no digest for its step; the plan digest pins it whole.
        self.receipt.sql_sha256 = self
            .descriptor
            .steps
            .iter()
            .filter_map(|step| {
                step.sql_path().map(|path| ArtifactDigestBinding {
                    path: path.to_owned(),
                    sha256: digest(&self.step_sql),
                })
            })
            .collect();
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
        let mut files = Vec::new();
        if let Some(step_path) = self.descriptor.steps[0].sql_path() {
            files.push(ReviewedMigrationFile {
                path: step_path.to_owned(),
                bytes: self.step_sql.clone(),
            });
        }
        files.push(ReviewedMigrationFile {
            path: self.descriptor.pre_assertions[0].sql_path.clone(),
            bytes: self.pre_sql.clone(),
        });
        files.push(ReviewedMigrationFile {
            path: self.descriptor.post_assertions[0].sql_path.clone(),
            bytes: self.post_sql.clone(),
        });
        files.push(ReviewedMigrationFile {
            path: self.descriptor.rehearsal_receipt_path.clone(),
            bytes: canonical(&self.receipt),
        });
        files.push(ReviewedMigrationFile {
            path: self.receipt.fixture_inventory[0].path.clone(),
            bytes: self.fixture_bytes.clone(),
        });
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
    fn sql_path(&self) -> Option<&str>;
    fn objects(&self) -> &[ReviewedMigrationObject];
    fn objects_mut(&mut self) -> &mut [ReviewedMigrationObject];
}

impl StepPath for ReviewedMigrationStepDescriptor {
    fn sql_path(&self) -> Option<&str> {
        match self {
            Self::TransactionalSql { sql_path, .. } | Self::ChunkedBackfill { sql_path, .. } => {
                Some(sql_path)
            }
            Self::FieldEncryptionBackfill { .. } => None,
        }
    }

    fn objects(&self) -> &[ReviewedMigrationObject] {
        match self {
            Self::TransactionalSql { objects, .. }
            | Self::ChunkedBackfill { objects, .. }
            | Self::FieldEncryptionBackfill { objects, .. } => objects,
        }
    }

    fn objects_mut(&mut self) -> &mut [ReviewedMigrationObject] {
        match self {
            Self::TransactionalSql { objects, .. }
            | Self::ChunkedBackfill { objects, .. }
            | Self::FieldEncryptionBackfill { objects, .. } => objects,
        }
    }
}

fn timer_field_update_artifacts(
    id: &str,
    previous: &CompiledRegistry,
    candidate: &CompiledRegistry,
    field_id: &str,
    step_kind: TimerUpdateStepKind,
) -> ReviewedArtifacts {
    let change_set = compiled_registry_change_set(previous, candidate, PRIOR_REVISION);
    let change = change_set
        .changes
        .iter()
        .find(|change| {
            change.code == CompiledRegistryChangeCode::FieldRequirednessChanged
                && change.target.entity_id.as_deref() == Some("asset")
                && change.target.member_id.as_deref() == Some(field_id)
        })
        .unwrap_or_else(|| panic!("requiredness change for asset.{field_id} is classified"));
    let entity = &candidate.entities()["asset"];
    let field = &entity.fields[field_id];
    let base = format!("modules/core/migrations/{id}");
    let step_path = format!("{base}/steps/update.sql");
    let pre_path = format!("{base}/assertions/pre.sql");
    let post_path = format!("{base}/assertions/post.sql");
    let object = ReviewedMigrationObject {
        schema: "registry_data".to_owned(),
        table: entity.physical_table.clone(),
        entity_id: "asset".to_owned(),
        kind: ReviewedMigrationObjectKind::Field,
        member_id: Some(field_id.to_owned()),
        physical_name: field.physical_name.clone(),
    };
    let step = match step_kind {
        TimerUpdateStepKind::Transactional => ReviewedMigrationStepDescriptor::TransactionalSql {
            id: "update".to_owned(),
            sql_path: step_path,
            objects: vec![object],
            affected_rows: Some(AffectedRowBounds { min: 0, max: 1_000 }),
        },
        TimerUpdateStepKind::Chunked => ReviewedMigrationStepDescriptor::ChunkedBackfill {
            id: "update".to_owned(),
            entity_id: "asset".to_owned(),
            sql_path: step_path,
            objects: vec![object],
            cursor: ChunkCursorProtocol::RecordIdUuidArray,
            chunk_size: 100,
            max_total_rows: 1_000,
            lock_timeout_ms: 1_000,
            statement_timeout_ms: 10_000,
            exact_affected_rows: true,
        },
    };
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
        steps: vec![step],
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
        history: None,
    };
    let mut artifacts = ReviewedArtifacts {
        descriptor,
        receipt: receipt(vec![RehearsalRowAssertion {
            step_id: "update".to_owned(),
            affected_rows: 10,
        }]),
        step_sql: format!(
            "UPDATE registry_data.{} SET {} = 'migration-value-canary' WHERE record_id = ANY($1::pg_catalog.uuid[])",
            entity.physical_table, field.physical_name
        )
        .into_bytes(),
        pre_sql: assertion_sql.clone(),
        post_sql: assertion_sql,
        fixture_bytes: b"{\"fixture\":\"representative\"}\n".to_vec(),
    };
    artifacts.rebind();
    artifacts
}

#[derive(Clone, Copy)]
enum TimerAlterCommand<'a> {
    Type(&'a str),
    SetNotNull(&'a str),
}

fn timer_alter_table_artifacts(
    id: &str,
    previous: &CompiledRegistry,
    candidate: &CompiledRegistry,
    covered_field: &str,
    commands: &[TimerAlterCommand<'_>],
) -> ReviewedArtifacts {
    let mut artifacts = timer_field_update_artifacts(
        id,
        previous,
        candidate,
        covered_field,
        TimerUpdateStepKind::Transactional,
    );
    let changes = compiled_registry_change_set(previous, candidate, PRIOR_REVISION);
    for field_id in commands.iter().map(|command| match command {
        TimerAlterCommand::Type(field_id) | TimerAlterCommand::SetNotNull(field_id) => *field_id,
    }) {
        if let Some(change) = changes.changes.iter().find(|change| {
            change.code == CompiledRegistryChangeCode::FieldRequirednessChanged
                && change.target.entity_id.as_deref() == Some("asset")
                && change.target.member_id.as_deref() == Some(field_id)
        }) {
            let cover = ReviewedChangeCover::from(change);
            if !artifacts.descriptor.covers.contains(&cover) {
                artifacts.descriptor.covers.push(cover);
            }
        }
    }
    artifacts.descriptor.covers.sort();
    let entity = &candidate.entities()["asset"];
    let mut objects = commands
        .iter()
        .map(|command| {
            let field_id = match command {
                TimerAlterCommand::Type(field_id) | TimerAlterCommand::SetNotNull(field_id) => {
                    *field_id
                }
            };
            let field = &entity.fields[field_id];
            ReviewedMigrationObject {
                schema: "registry_data".to_owned(),
                table: entity.physical_table.clone(),
                entity_id: "asset".to_owned(),
                kind: ReviewedMigrationObjectKind::Field,
                member_id: Some(field_id.to_owned()),
                physical_name: field.physical_name.clone(),
            }
        })
        .collect::<Vec<_>>();
    objects.sort();
    objects.dedup();
    let ReviewedMigrationStepDescriptor::TransactionalSql {
        objects: step_objects,
        affected_rows,
        ..
    } = &mut artifacts.descriptor.steps[0]
    else {
        panic!("the ALTER TABLE fixture starts as a transactional step");
    };
    *step_objects = objects;
    *affected_rows = None;

    let clauses = commands
        .iter()
        .map(|command| match command {
            TimerAlterCommand::Type(field_id) => format!(
                "ALTER COLUMN {} TYPE text USING 'migration-value-canary'::text",
                entity.fields[*field_id].physical_name
            ),
            TimerAlterCommand::SetNotNull(field_id) => format!(
                "ALTER COLUMN {} SET NOT NULL",
                entity.fields[*field_id].physical_name
            ),
        })
        .collect::<Vec<_>>()
        .join(", ");
    artifacts.step_sql = format!(
        "ALTER TABLE registry_data.{} {clauses}",
        entity.physical_table
    )
    .into_bytes();
    artifacts.receipt.row_assertions.clear();
    artifacts.rebind();
    artifacts
}

fn timer_metadata_review_source(
    id: &str,
    previous: &CompiledRegistry,
    candidate: &CompiledRegistry,
) -> ReviewedMigrationSource {
    let change_set = compiled_registry_change_set(previous, candidate, PRIOR_REVISION);
    let change = change_set
        .changes
        .iter()
        .find(|change| change.code == CompiledRegistryChangeCode::TimerChanged)
        .expect("the module revision change is an explicit timer policy change");
    let base = format!("modules/core/migrations/{id}");
    let descriptor = ReviewedMigrationDescriptor {
        id: id.to_owned(),
        change_class: CompiledRegistryChangeClass::AccessOrDisclosureChange,
        covers: vec![ReviewedChangeCover::from(change)],
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        lock_timeout_ms: 10_000,
        statement_timeout_ms: 60_000,
        steps: Vec::new(),
        pre_assertions: Vec::new(),
        post_assertions: Vec::new(),
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: None,
        history: None,
    };
    let descriptor_bytes = canonical(&descriptor);
    let mut rehearsal = receipt(Vec::new());
    rehearsal.plan_sha256 = digest(&descriptor_bytes);
    rehearsal.fixture_inventory.clear();
    let receipt_path = descriptor.rehearsal_receipt_path.clone();
    ReviewedMigrationSource {
        module_id: "core".to_owned(),
        descriptor: ReviewedMigrationFile {
            path: format!("{base}/descriptor.json"),
            bytes: descriptor_bytes,
        },
        files: vec![ReviewedMigrationFile {
            path: receipt_path,
            bytes: canonical(&rehearsal),
        }],
    }
}

fn reviewed_timer_sources(
    migration: ReviewedMigrationSource,
    timer_review: ReviewedMigrationSource,
) -> Vec<ReviewedMigrationSource> {
    let mut sources = vec![migration, timer_review];
    sources.sort_by(|left, right| left.descriptor.path.cmp(&right.descriptor.path));
    sources
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
        history: None,
    };
    let mut artifacts = ReviewedArtifacts {
        descriptor,
        receipt: receipt(vec![RehearsalRowAssertion {
            step_id: "backfill".to_owned(),
            affected_rows: 10,
        }]),
        step_sql,
        pre_sql: assertion_sql.clone(),
        post_sql: assertion_sql,
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
        history: None,
    };
    let mut artifacts = ReviewedArtifacts {
        descriptor,
        receipt: receipt(Vec::new()),
        step_sql: format!(
            "ALTER TABLE registry_data.{} DROP COLUMN {}",
            entity.physical_table, field.physical_name
        )
        .into_bytes(),
        pre_sql: assertion_sql.clone(),
        post_sql: assertion_sql,
        fixture_bytes: b"{\"fixture\":\"representative\"}\n".to_vec(),
    };
    artifacts.rebind();
    artifacts
}

/// A reviewed encryption flip declared the way the engine executes it: one
/// engine-executed `FieldEncryptionBackfill` step with no authored SQL, an
/// explicit history choice, and objects that name the envelope column of the
/// covered field plus its blind-index sibling through the implicit `#lookup`
/// member.
fn encryption_flip_artifacts(
    id: &str,
    previous: &CompiledRegistry,
    candidate: &CompiledRegistry,
) -> ReviewedArtifacts {
    let change_set = compiled_registry_change_set(previous, candidate, PRIOR_REVISION);
    let change = change_set
        .changes
        .iter()
        .find(|change| change.code == CompiledRegistryChangeCode::FieldEncryptionChanged)
        .expect("the flip is classified as a field encryption change");
    let entity = &candidate.entities()["asset"];
    let field = &entity.fields["secret"];
    let blind = field
        .encryption
        .as_ref()
        .and_then(|encryption| encryption.blind_index.as_ref())
        .expect("the flip declares a blind index");
    let base = format!("modules/core/migrations/{id}");
    let pre_path = format!("{base}/assertions/pre.sql");
    let post_path = format!("{base}/assertions/post.sql");
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
        steps: vec![ReviewedMigrationStepDescriptor::FieldEncryptionBackfill {
            id: "backfill".to_owned(),
            entity_id: "asset".to_owned(),
            objects: vec![
                ReviewedMigrationObject {
                    schema: "registry_data".to_owned(),
                    table: entity.physical_table.clone(),
                    entity_id: "asset".to_owned(),
                    kind: ReviewedMigrationObjectKind::Field,
                    member_id: Some("secret".to_owned()),
                    physical_name: field.physical_name.clone(),
                },
                ReviewedMigrationObject {
                    schema: "registry_data".to_owned(),
                    table: entity.physical_table.clone(),
                    entity_id: "asset".to_owned(),
                    kind: ReviewedMigrationObjectKind::Field,
                    member_id: Some("secret#lookup".to_owned()),
                    physical_name: blind.physical_name.clone(),
                },
            ],
            cursor: ChunkCursorProtocol::RecordIdUuidArray,
            chunk_size: 100,
            max_total_rows: 1_000,
            lock_timeout_ms: 1_000,
            statement_timeout_ms: 10_000,
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
        history: Some(ReviewedFieldEncryptionHistory::EraseAndRebaseline),
    };
    let mut artifacts = ReviewedArtifacts {
        descriptor,
        receipt: receipt(vec![RehearsalRowAssertion {
            step_id: "backfill".to_owned(),
            affected_rows: 10,
        }]),
        step_sql: Vec::new(),
        pre_sql: assertion_sql.clone(),
        post_sql: assertion_sql,
        fixture_bytes: b"{\"fixture\":\"representative\"}\n".to_vec(),
    };
    artifacts.rebind();
    artifacts
}

fn receipt(row_assertions: Vec<RehearsalRowAssertion>) -> MigrationRehearsalReceipt {
    MigrationRehearsalReceipt {
        prior_package_digest: PRIOR_REVISION.to_owned(),
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
    }
}

fn assert_refused(
    candidate_variant: Variant,
    previous: CompiledRegistry,
    migrations: Vec<ReviewedMigrationSource>,
    expected: ReviewedMigrationError,
    label: &str,
) {
    let result = prepare_reviewed_package(candidate_variant, previous, migrations);
    assert_eq!(
        result.err(),
        Some(PackageError::ReviewedMigration(expected)),
        "{label} must be refused with a value-free error"
    );
}

fn prepare_reviewed_package(
    candidate_variant: Variant,
    previous: CompiledRegistry,
    migrations: Vec<ReviewedMigrationSource>,
) -> registry_breg::package::Result<registry_breg::package::PreparedPackage> {
    let source = source_for_variant(candidate_variant);
    prepare_reviewed_package_from_source(source, previous, migrations)
}

fn prepare_reviewed_package_from_source(
    source: SourceFixture,
    previous: CompiledRegistry,
    migrations: Vec<ReviewedMigrationSource>,
) -> registry_breg::package::Result<registry_breg::package::PreparedPackage> {
    prepare_package(PackageBuildRequest {
        from_package_digest: Some(PRIOR_REVISION.to_owned()),
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint: FINAL_FINGERPRINT.to_owned(),
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
    EncryptedBase,
    EncryptedFlipOn,
}

struct SourceFixture {
    project_bytes: Vec<u8>,
    module_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TimerSide {
    Predecessor,
    Successor,
}

impl TimerSide {
    fn id(self) -> &'static str {
        match self {
            Self::Predecessor => "predecessor",
            Self::Successor => "successor",
        }
    }

    fn predecessor_fields(self) -> TimerFieldSet {
        match self {
            Self::Predecessor => TimerFieldSet::Primary,
            Self::Successor => TimerFieldSet::Alternate,
        }
    }

    fn successor_fields(self) -> TimerFieldSet {
        match self {
            Self::Predecessor => TimerFieldSet::Alternate,
            Self::Successor => TimerFieldSet::Primary,
        }
    }
}

#[derive(Clone, Copy)]
enum TimerFieldSet {
    Primary,
    Alternate,
}

impl TimerFieldSet {
    fn fields(self) -> (&'static str, &'static str, &'static str, &'static str) {
        match self {
            Self::Primary => (
                "activates-at",
                "activation-window-end",
                "activation-revision",
                "eligible",
            ),
            Self::Alternate => (
                "alternate-activates-at",
                "alternate-window-end",
                "alternate-revision",
                "alternate-eligible",
            ),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum TimerUpdateStepKind {
    Transactional,
    Chunked,
}

impl TimerUpdateStepKind {
    fn id(self) -> &'static str {
        match self {
            Self::Transactional => "transactional",
            Self::Chunked => "chunked",
        }
    }
}

fn compile_variant(variant: Variant) -> CompiledRegistry {
    let source = source_for_variant(variant);
    compile_source(&source)
}

fn compile_source(source: &SourceFixture) -> CompiledRegistry {
    let module = parse_module_yaml(&source.module_bytes).expect("fixture module parses");
    let project = parse_project_yaml(&source.project_bytes).expect("fixture project parses");
    compile_project(&project, &[module], CompileProfile::Production)
        .expect("fixture compiles in production")
}

fn timer_migration_source(
    timer_fields: TimerFieldSet,
    required_field: Option<&str>,
    encrypt_predicate: bool,
) -> SourceFixture {
    timer_migration_source_with_required_fields(
        timer_fields,
        &required_field.into_iter().collect::<Vec<_>>(),
        encrypt_predicate,
    )
}

fn timer_migration_source_with_required_fields(
    timer_fields: TimerFieldSet,
    required_fields: &[&str],
    encrypt_predicate: bool,
) -> SourceFixture {
    let base = source_for_variant(Variant::Base);
    let mut module: serde_json::Value =
        serde_json::from_slice(&base.module_bytes).expect("base module is JSON");
    let asset = &mut module["recordTypes"][0];
    asset["mutationMode"] = serde_json::json!("mutable");
    let fields = asset["fields"]
        .as_array_mut()
        .expect("base Record fields are a list");
    fields.extend([
        serde_json::json!({"id":"activates-at","type":"timestamp","classification":"internal"}),
        serde_json::json!({"id":"activation-window-end","type":"timestamp","classification":"internal"}),
        serde_json::json!({"id":"activation-revision","type":"uuid","classification":"internal"}),
        serde_json::json!({"id":"eligible","type":"boolean","classification":"internal"}),
        serde_json::json!({"id":"alternate-activates-at","type":"timestamp","classification":"internal"}),
        serde_json::json!({"id":"alternate-window-end","type":"timestamp","classification":"internal"}),
        serde_json::json!({"id":"alternate-revision","type":"uuid","classification":"internal"}),
        serde_json::json!({"id":"alternate-eligible","type":"boolean","classification":"internal"}),
        serde_json::json!({"id":"processed","type":"boolean","classification":"internal"}),
        if encrypt_predicate {
            serde_json::json!({
                "id":"secret", "type":"string", "maximumLength":256,
                "classification":"restricted", "encrypted":true,
                "lookup":{"normalization":["uppercase"],"unique":true}
            })
        } else {
            serde_json::json!({
                "id":"secret", "type":"string", "maximumLength":256,
                "classification":"restricted"
            })
        },
    ]);
    for required_field in required_fields {
        fields
            .iter_mut()
            .find(|field| field["id"] == *required_field)
            .unwrap_or_else(|| panic!("timer migration field {required_field} exists"))
            ["required"] = serde_json::json!(true);
    }
    asset["accessProfiles"][0]["operations"] =
        serde_json::json!(["create", "get", "list", "patch"]);
    asset["accessProfiles"][0]["readableFields"] = serde_json::json!([
        "code",
        "rank",
        "activates-at",
        "activation-window-end",
        "activation-revision",
        "eligible",
        "alternate-activates-at",
        "alternate-window-end",
        "alternate-revision",
        "alternate-eligible",
        "processed",
        "secret"
    ]);
    asset["accessProfiles"][0]["writableFields"] =
        asset["accessProfiles"][0]["readableFields"].clone();
    let (at, not_after, rearm_on, predicate) = timer_fields.fields();
    let mut equals = serde_json::Map::new();
    equals.insert(predicate.to_owned(), serde_json::json!(false));
    equals.insert("secret".to_owned(), serde_json::json!("ready"));
    asset["timers"] = serde_json::json!([{
        "id":"activate",
        "at":at,
        "notAfter":not_after,
        "rearmOn":rearm_on,
        "when":{"type":"fields","equals":equals},
        "invoke":"activate-asset",
        "input":{"asset":{"fromRecordId":true}}
    }]);
    module["actions"] = serde_json::json!([{
        "id":"activate-asset",
        "execution":{"mode":"immediate"},
        "inputs":[{
            "id":"asset", "type":"reference", "target":"asset",
            "required":true, "classification":"internal"
        }],
        "plan":{"type":"fixed","effects":[{
            "id":"mark-processed",
            "target":{"fromInput":"asset"},
            "operation":"patch",
            "set":{"processed":{"value":true}}
        }]}
    }]);
    let module_bytes = serde_json::to_vec(&module).expect("timer module serializes");
    let parsed_module = parse_module_yaml(&module_bytes).expect("timer module parses");
    let digest = module_digest(&parsed_module);

    let mut project: serde_json::Value =
        serde_json::from_slice(&base.project_bytes).expect("base project is JSON");
    project["modules"][0]["digest"] = serde_json::json!(digest);
    project["timerGrants"] = serde_json::json!([{"recordType":"asset","timer":"activate"}]);
    SourceFixture {
        project_bytes: serde_json::to_vec(&project).expect("timer project serializes"),
        module_bytes,
    }
}

fn source_for_variant(variant: Variant) -> SourceFixture {
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
            r#"{{"datasets":[{{"id": "neutral-registry"}}],"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject","project":{{"id":"{registry_id}","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://package.example.test"}},"package":{{"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"id":"neutral-registry-authority","name":"Package Test Publisher"}}}},"publicService":{{"id":"neutral-registry-service","title":"Neutral Registry Catalog"}},"datasets":[{{"id":"neutral-registry","title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}],"dataServices":[{{"id":"neutral-registry-data-service","title":"Neutral Registry Catalog","endpointUrl":"https://package.example.test","servesDatasets":["neutral-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
        )
        .into_bytes(),
        module_bytes,
    }
}

fn module_bytes(variant: Variant) -> Vec<u8> {
    let fields = match variant {
        Variant::RequiredField => {
            r#"{"id":"code","type":"string","maximumLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"batch","type":"string","maximumLength":16,"required":true,"classification":"internal"}"#
        }
        Variant::FieldRemoved => {
            r#"{"id":"code","type":"string","maximumLength":8,"classification":"internal"}"#
        }
        Variant::EncryptedBase => {
            r#"{"id":"code","type":"string","maximumLength":8,"classification":"internal"},{"id":"secret","type":"string","maximumLength":256,"classification":"restricted"}"#
        }
        Variant::EncryptedFlipOn => {
            r#"{"id":"code","type":"string","maximumLength":8,"classification":"internal"},{"id":"secret","type":"string","maximumLength":256,"classification":"restricted","encrypted":true,"lookup":{"normalization":["uppercase"],"unique":true}}"#
        }
        Variant::Base | Variant::DifferentRegistry => {
            r#"{"id":"code","type":"string","maximumLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"}"#
        }
    };
    format!(
        r#"{{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"core","version":"1","recordTypes":[{{"id":"asset","primaryDataset":"neutral-registry","route":"assets","mutationMode":"create-only","fields":[{fields}],"accessProfiles":[{{"requiredScopes":"unrestricted","rowBoundaries":"unrestricted", "id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]}}]}},{{"id":"site","primaryDataset":"neutral-registry","route":"sites","mutationMode":"create-only","fields":[{{"id":"code","type":"string","maximumLength":8,"classification":"internal"}}],"accessProfiles":[{{"requiredScopes":"unrestricted","rowBoundaries":"unrestricted", "id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]}}]}}]}}"#
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

/// Republish the shared package envelope over a test-authored change, so the
/// refusal under test comes from the registry package check rather than from
/// the checksum file.
fn refresh_shared_package_envelope(root: &std::path::Path) {
    let revision_path = root.join(REVISION_FILE);
    let revision = revision_path.exists().then(|| {
        fs::read_to_string(&revision_path)
            .expect("shared package revision reads")
            .strip_suffix('\n')
            .expect("shared package revision has one trailing newline")
            .to_owned()
    });
    fs::remove_file(root.join(SUM_FILE)).expect("old shared package checksum file removes");
    if revision.is_some() {
        fs::remove_file(revision_path).expect("old shared package revision file removes");
    }
    write_sum_file(
        root,
        revision.as_deref(),
        &SharedPackageLimits::default(),
        "bregctl package",
    )
    .expect("test-authored shared package envelope republishes");
}
