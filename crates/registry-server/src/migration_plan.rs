// SPDX-License-Identifier: Apache-2.0
//! Closed, reviewed migration descriptors and PostgreSQL AST validation.
//!
//! Threat: a reviewed migration artifact could otherwise smuggle a second
//! statement, session or role mutation, cross-schema access, unbounded DML, or
//! evidence for a different package into a signed package. This module is the
//! single validator used while constructing and rederiving package closure.

#[cfg(feature = "tooling")]
use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "tooling")]
use pg_query::protobuf::{
    a_const, node::Node as PgNode, AExprKind, AlterTableType, ConstrType, ObjectType, SetOperation,
    SubLinkType,
};
#[cfg(feature = "tooling")]
use pg_query::NodeRef;
#[cfg(feature = "tooling")]
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use serde::{Deserialize, Serialize};
#[cfg(feature = "tooling")]
use sha2::{Digest, Sha256};
#[cfg(feature = "tooling")]
use thiserror::Error;
#[cfg(feature = "tooling")]
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[cfg(feature = "tooling")]
use crate::model::CompiledEntity;
#[cfg(feature = "tooling")]
use crate::package::CompiledRegistryChangeTargetKind;
use crate::package::{
    CompiledRegistryChange, CompiledRegistryChangeClass, CompiledRegistryChangeCode,
    CompiledRegistryChangeTarget,
};

#[cfg(feature = "tooling")]
const MAX_DESCRIPTOR_BYTES: usize = 1024 * 1024;
#[cfg(feature = "tooling")]
const MAX_SQL_BYTES: usize = 1024 * 1024;
#[cfg(feature = "tooling")]
const MAX_FIXTURE_BYTES: usize = 16 * 1024 * 1024;
#[cfg(feature = "tooling")]
const MAX_ARTIFACTS: usize = 1024;
#[cfg(feature = "tooling")]
const MAX_STEPS: usize = 256;
#[cfg(feature = "tooling")]
const MAX_ASSERTIONS: usize = 256;
#[cfg(feature = "tooling")]
const MAX_LOCK_TIMEOUT_MS: u64 = 300_000;
#[cfg(feature = "tooling")]
const MAX_STATEMENT_TIMEOUT_MS: u64 = 3_600_000;
#[cfg(feature = "tooling")]
const MAX_CHUNK_SIZE: u32 = 10_000;
#[cfg(feature = "tooling")]
const MAX_TOTAL_ROWS: u64 = 100_000_000;
#[cfg(feature = "tooling")]
const MAX_BACKUP_AGE_SECONDS: u64 = 31 * 24 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewedMigrationFile {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewedMigrationSource {
    pub module_id: String,
    pub descriptor: ReviewedMigrationFile,
    pub files: Vec<ReviewedMigrationFile>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewedMigrationDescriptor {
    pub id: String,
    pub change_class: CompiledRegistryChangeClass,
    pub covers: Vec<ReviewedChangeCover>,
    pub recovery: ReviewedMigrationRecovery,
    pub lock_timeout_ms: u64,
    pub statement_timeout_ms: u64,
    pub steps: Vec<ReviewedMigrationStepDescriptor>,
    pub pre_assertions: Vec<ReviewedMigrationAssertionDescriptor>,
    pub post_assertions: Vec<ReviewedMigrationAssertionDescriptor>,
    pub rehearsal_receipt_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_binding_path: Option<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewedChangeCover {
    pub code: CompiledRegistryChangeCode,
    pub target: CompiledRegistryChangeTarget,
}

impl From<&CompiledRegistryChange> for ReviewedChangeCover {
    fn from(change: &CompiledRegistryChange) -> Self {
        Self {
            code: change.code,
            target: change.target.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewedMigrationRecovery {
    ExactTargetResume,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields, rename_all = "snake_case")]
pub enum ReviewedMigrationStepDescriptor {
    TransactionalSql {
        id: String,
        sql_path: String,
        objects: Vec<ReviewedMigrationObject>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        affected_rows: Option<AffectedRowBounds>,
    },
    ChunkedBackfill {
        id: String,
        entity_id: String,
        sql_path: String,
        objects: Vec<ReviewedMigrationObject>,
        cursor: ChunkCursorProtocol,
        chunk_size: u32,
        max_total_rows: u64,
        lock_timeout_ms: u64,
        statement_timeout_ms: u64,
        exact_affected_rows: bool,
    },
}

impl ReviewedMigrationStepDescriptor {
    #[cfg(feature = "tooling")]
    fn id(&self) -> &str {
        match self {
            Self::TransactionalSql { id, .. } | Self::ChunkedBackfill { id, .. } => id,
        }
    }

    #[cfg(feature = "tooling")]
    fn sql_path(&self) -> &str {
        match self {
            Self::TransactionalSql { sql_path, .. } | Self::ChunkedBackfill { sql_path, .. } => {
                sql_path
            }
        }
    }

    #[cfg(feature = "tooling")]
    fn objects(&self) -> &[ReviewedMigrationObject] {
        match self {
            Self::TransactionalSql { objects, .. } | Self::ChunkedBackfill { objects, .. } => {
                objects
            }
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewedMigrationObject {
    pub schema: String,
    pub table: String,
    pub entity_id: String,
    pub kind: ReviewedMigrationObjectKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_id: Option<String>,
    pub physical_name: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewedMigrationObjectKind {
    Entity,
    Field,
    Constraint,
    Index,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChunkCursorProtocol {
    RecordIdUuidArray,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AffectedRowBounds {
    pub min: u64,
    pub max: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewedMigrationAssertionDescriptor {
    pub id: String,
    pub sql_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MigrationRehearsalReceipt {
    pub prior_revision: String,
    pub prior_schema_fingerprint: String,
    pub plan_sha256: String,
    pub sql_sha256: Vec<ArtifactDigestBinding>,
    pub assertion_sha256: Vec<ArtifactDigestBinding>,
    pub fixture_inventory: Vec<RehearsalFixture>,
    pub postgres_major: u16,
    pub row_assertions: Vec<RehearsalRowAssertion>,
    pub final_schema_fingerprint: String,
    pub proofs: RehearsalProofs,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ArtifactDigestBinding {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RehearsalFixture {
    pub id: String,
    pub path: String,
    pub sha256: String,
    pub row_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RehearsalRowAssertion {
    pub step_id: String,
    pub affected_rows: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RehearsalProofs {
    pub lock_timeout: bool,
    pub chunk_resume: bool,
    pub destructive_resume: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalBackupBinding {
    pub database_id: String,
    pub prior_revision: String,
    pub prior_schema_fingerprint: String,
    pub sha256: String,
    pub byte_length: u64,
    pub created_at: String,
    pub max_age_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedReviewedMigrationPlan {
    migrations: Vec<ValidatedReviewedMigration>,
}

impl ValidatedReviewedMigrationPlan {
    #[must_use]
    pub fn migrations(&self) -> &[ValidatedReviewedMigration] {
        &self.migrations
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedReviewedMigration {
    pub module_id: String,
    pub descriptor_path: String,
    pub descriptor: ReviewedMigrationDescriptor,
    pub steps: Vec<ValidatedReviewedMigrationStep>,
    pub pre_assertions: Vec<ValidatedReviewedMigrationAssertion>,
    pub post_assertions: Vec<ValidatedReviewedMigrationAssertion>,
    pub rehearsal_receipt: MigrationRehearsalReceipt,
    pub backup_binding: Option<ExternalBackupBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedReviewedMigrationStep {
    pub descriptor: ReviewedMigrationStepDescriptor,
    pub sql: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedReviewedMigrationAssertion {
    pub descriptor: ReviewedMigrationAssertionDescriptor,
    pub sql: String,
    pub sha256: String,
}

#[cfg(feature = "tooling")]
#[derive(Clone, Debug)]
pub(crate) struct ReviewedPlanBindings<'a> {
    pub prior_revision: &'a str,
    pub prior_schema_fingerprint: &'a str,
    pub final_schema_fingerprint: &'a str,
    pub database_id: &'a str,
    pub changes: &'a [CompiledRegistryChange],
    pub prior_entities: &'a BTreeMap<String, CompiledEntity>,
    pub candidate_entities: &'a BTreeMap<String, CompiledEntity>,
    pub prior_physical_names: &'a crate::physical_names::PhysicalNameInventory,
    pub candidate_physical_names: &'a crate::physical_names::PhysicalNameInventory,
}

#[cfg(feature = "tooling")]
#[derive(Clone, Debug)]
pub(crate) struct PreparedReviewedMigrationPlan {
    pub descriptor_paths: Vec<String>,
    pub files: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReviewedArtifactKind {
    Descriptor,
    StepSql,
    AssertionSql,
    RehearsalReceipt,
    BackupBinding,
    Fixture,
}

#[cfg(feature = "tooling")]
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum ReviewedMigrationError {
    #[error("the reviewed migration descriptor is invalid")]
    Descriptor,
    #[error("the reviewed migration coverage is invalid")]
    Coverage,
    #[error("the reviewed migration SQL is outside the accepted AST")]
    Sql,
    #[error("the reviewed migration evidence is not bound")]
    Evidence,
    #[error("the reviewed migration artifact closure is invalid")]
    Closure,
}

#[cfg(feature = "tooling")]
pub(crate) fn prepare_reviewed_migration_plan(
    sources: &[ReviewedMigrationSource],
    bindings: &ReviewedPlanBindings<'_>,
) -> Result<PreparedReviewedMigrationPlan, ReviewedMigrationError> {
    if sources.is_empty() || sources.len() > MAX_ARTIFACTS {
        return Err(ReviewedMigrationError::Coverage);
    }
    let mut descriptor_paths = Vec::with_capacity(sources.len());
    let mut files = BTreeMap::new();
    let mut prior_descriptor = None;
    for source in sources {
        if !valid_id(&source.module_id)
            || prior_descriptor
                .as_ref()
                .is_some_and(|prior: &String| prior >= &source.descriptor.path)
        {
            return Err(ReviewedMigrationError::Descriptor);
        }
        prior_descriptor = Some(source.descriptor.path.clone());
        descriptor_paths.push(source.descriptor.path.clone());
        if files
            .insert(
                source.descriptor.path.clone(),
                source.descriptor.bytes.clone(),
            )
            .is_some()
        {
            return Err(ReviewedMigrationError::Closure);
        }
        for file in &source.files {
            if files
                .insert(file.path.clone(), file.bytes.clone())
                .is_some()
            {
                return Err(ReviewedMigrationError::Closure);
            }
        }
    }
    let validated = validate_reviewed_migration_plan(&descriptor_paths, &files, bindings)?;
    for (source, migration) in sources.iter().zip(validated.migrations()) {
        if source.module_id != migration.module_id {
            return Err(ReviewedMigrationError::Descriptor);
        }
    }
    Ok(PreparedReviewedMigrationPlan {
        descriptor_paths,
        files,
    })
}

#[cfg(feature = "tooling")]
pub(crate) fn validate_reviewed_migration_plan(
    descriptor_paths: &[String],
    files: &BTreeMap<String, Vec<u8>>,
    bindings: &ReviewedPlanBindings<'_>,
) -> Result<ValidatedReviewedMigrationPlan, ReviewedMigrationError> {
    if descriptor_paths.len() > MAX_ARTIFACTS
        || !strictly_sorted(descriptor_paths.iter().map(String::as_str))
    {
        return Err(ReviewedMigrationError::Closure);
    }
    if bindings
        .changes
        .iter()
        .any(|change| change.class == CompiledRegistryChangeClass::Unsupported)
    {
        return Err(ReviewedMigrationError::Coverage);
    }

    let declared_tables = bindings
        .prior_entities
        .values()
        .chain(bindings.candidate_entities.values())
        .map(|entity| entity.physical_table.as_str())
        .collect::<BTreeSet<_>>();
    let non_additive = bindings
        .changes
        .iter()
        .filter(|change| change.class != CompiledRegistryChangeClass::CompatibleAdditive)
        .map(|change| (ReviewedChangeCover::from(change), change.class))
        .collect::<BTreeMap<_, _>>();
    if non_additive.is_empty() != descriptor_paths.is_empty() {
        return Err(ReviewedMigrationError::Coverage);
    }

    let mut claimed = BTreeSet::new();
    let mut referenced_paths = BTreeSet::new();
    let mut migrations = Vec::with_capacity(descriptor_paths.len());
    for descriptor_path in descriptor_paths {
        let descriptor_bytes = files
            .get(descriptor_path)
            .ok_or(ReviewedMigrationError::Closure)?;
        if descriptor_bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(ReviewedMigrationError::Descriptor);
        }
        let descriptor: ReviewedMigrationDescriptor = parse_canonical(descriptor_bytes)?;
        let (module_id, base) = descriptor_base(descriptor_path, &descriptor.id)?;
        referenced_paths.insert(descriptor_path.clone());
        validate_descriptor_shape(&descriptor, &base)?;
        for cover in &descriptor.covers {
            let Some(expected_class) = non_additive.get(cover) else {
                return Err(ReviewedMigrationError::Coverage);
            };
            if *expected_class != descriptor.change_class || !claimed.insert(cover.clone()) {
                return Err(ReviewedMigrationError::Coverage);
            }
        }

        let mut steps = Vec::with_capacity(descriptor.steps.len());
        let mut object_covers = BTreeSet::new();
        for step in &descriptor.steps {
            let path = step.sql_path();
            referenced_paths.insert(path.to_owned());
            let sql = read_sql(files, path)?;
            validate_step_sql(step, sql, &descriptor, bindings, &declared_tables)?;
            for object in step.objects() {
                object_covers.insert(object_cover(object, &descriptor.covers)?);
            }
            steps.push(ValidatedReviewedMigrationStep {
                descriptor: step.clone(),
                sql: sql.to_owned(),
                sha256: digest(sql.as_bytes()),
            });
        }
        let descriptor_covers = descriptor.covers.iter().cloned().collect::<BTreeSet<_>>();
        if descriptor.steps.is_empty() && covers_are_metadata_only(&descriptor.covers) {
            object_covers = descriptor_covers.clone();
        }
        if object_covers != descriptor_covers {
            return Err(ReviewedMigrationError::Coverage);
        }
        let pre_assertions = validate_assertions(
            &descriptor.pre_assertions,
            files,
            &declared_tables,
            &mut referenced_paths,
        )?;
        let post_assertions = validate_assertions(
            &descriptor.post_assertions,
            files,
            &declared_tables,
            &mut referenced_paths,
        )?;

        referenced_paths.insert(descriptor.rehearsal_receipt_path.clone());
        let receipt_bytes = files
            .get(&descriptor.rehearsal_receipt_path)
            .ok_or(ReviewedMigrationError::Evidence)?;
        let receipt: MigrationRehearsalReceipt =
            parse_canonical(receipt_bytes).map_err(|_| ReviewedMigrationError::Evidence)?;
        validate_receipt(
            &receipt,
            ReceiptValidationContext {
                descriptor_bytes,
                steps: &steps,
                pre_assertions: &pre_assertions,
                post_assertions: &post_assertions,
                descriptor: &descriptor,
                bindings,
                base: &base,
                files,
                referenced_paths: &mut referenced_paths,
            },
        )?;

        let backup_binding = match &descriptor.backup_binding_path {
            Some(path) => {
                referenced_paths.insert(path.clone());
                let bytes = files.get(path).ok_or(ReviewedMigrationError::Evidence)?;
                let binding: ExternalBackupBinding =
                    parse_canonical(bytes).map_err(|_| ReviewedMigrationError::Evidence)?;
                validate_backup(&binding, bindings)?;
                Some(binding)
            }
            None => None,
        };
        if descriptor.change_class == CompiledRegistryChangeClass::DestructiveOrIrreversible
            && backup_binding.is_none()
        {
            return Err(ReviewedMigrationError::Evidence);
        }
        migrations.push(ValidatedReviewedMigration {
            module_id,
            descriptor_path: descriptor_path.clone(),
            descriptor,
            steps,
            pre_assertions,
            post_assertions,
            rehearsal_receipt: receipt,
            backup_binding,
        });
    }
    if claimed != non_additive.keys().cloned().collect()
        || referenced_paths != files.keys().cloned().collect()
    {
        return Err(ReviewedMigrationError::Coverage);
    }
    Ok(ValidatedReviewedMigrationPlan { migrations })
}

pub(crate) fn reviewed_artifact_kind(path: &str) -> Option<ReviewedArtifactKind> {
    let components = path.split('/').collect::<Vec<_>>();
    match components.as_slice() {
        ["modules", module, "migrations", migration, "descriptor.json"]
            if valid_id(module) && valid_id(migration) =>
        {
            Some(ReviewedArtifactKind::Descriptor)
        }
        ["modules", module, "migrations", migration, "steps", file]
            if valid_id(module)
                && valid_id(migration)
                && file.strip_suffix(".sql").is_some_and(valid_id) =>
        {
            Some(ReviewedArtifactKind::StepSql)
        }
        ["modules", module, "migrations", migration, "assertions", file]
            if valid_id(module)
                && valid_id(migration)
                && file.strip_suffix(".sql").is_some_and(valid_id) =>
        {
            Some(ReviewedArtifactKind::AssertionSql)
        }
        ["modules", module, "migrations", migration, "rehearsal.json"]
            if valid_id(module) && valid_id(migration) =>
        {
            Some(ReviewedArtifactKind::RehearsalReceipt)
        }
        ["modules", module, "migrations", migration, "backup.json"]
            if valid_id(module) && valid_id(migration) =>
        {
            Some(ReviewedArtifactKind::BackupBinding)
        }
        ["modules", module, "migrations", migration, "fixtures", file]
            if valid_id(module)
                && valid_id(migration)
                && file.strip_suffix(".jsonl").is_some_and(valid_id) =>
        {
            Some(ReviewedArtifactKind::Fixture)
        }
        _ => None,
    }
}

#[cfg(feature = "tooling")]
fn validate_descriptor_shape(
    descriptor: &ReviewedMigrationDescriptor,
    base: &str,
) -> Result<(), ReviewedMigrationError> {
    let metadata_only = covers_are_metadata_only(&descriptor.covers);
    if !valid_id(&descriptor.id)
        || matches!(
            descriptor.change_class,
            CompiledRegistryChangeClass::CompatibleAdditive
                | CompiledRegistryChangeClass::Unsupported
        )
        || descriptor.covers.is_empty()
        || !strictly_sorted(descriptor.covers.iter())
        || (descriptor.steps.is_empty() && !metadata_only)
        || descriptor.steps.len() > MAX_STEPS
        || (descriptor.pre_assertions.is_empty() && !metadata_only)
        || descriptor.pre_assertions.len() > MAX_ASSERTIONS
        || (descriptor.post_assertions.is_empty() && !metadata_only)
        || descriptor.post_assertions.len() > MAX_ASSERTIONS
        || !valid_timeout(descriptor.lock_timeout_ms, MAX_LOCK_TIMEOUT_MS)
        || !valid_timeout(descriptor.statement_timeout_ms, MAX_STATEMENT_TIMEOUT_MS)
        || descriptor.recovery != ReviewedMigrationRecovery::ExactTargetResume
        || descriptor.rehearsal_receipt_path != format!("{base}/rehearsal.json")
        || descriptor
            .backup_binding_path
            .as_ref()
            .is_some_and(|path| path != &format!("{base}/backup.json"))
    {
        return Err(ReviewedMigrationError::Descriptor);
    }
    let mut ids = BTreeSet::new();
    for step in &descriptor.steps {
        if !valid_id(step.id())
            || !ids.insert(step.id())
            || step.sql_path() != format!("{base}/steps/{}.sql", step.id())
            || step.objects().is_empty()
            || !strictly_sorted(step.objects().iter())
        {
            return Err(ReviewedMigrationError::Descriptor);
        }
        match step {
            ReviewedMigrationStepDescriptor::TransactionalSql {
                affected_rows: Some(bounds),
                ..
            } if bounds.min > bounds.max || bounds.max > MAX_TOTAL_ROWS => {
                return Err(ReviewedMigrationError::Descriptor);
            }
            ReviewedMigrationStepDescriptor::ChunkedBackfill {
                entity_id,
                chunk_size,
                max_total_rows,
                lock_timeout_ms,
                statement_timeout_ms,
                exact_affected_rows,
                ..
            } if !valid_id(entity_id)
                || *chunk_size == 0
                || *chunk_size > MAX_CHUNK_SIZE
                || *max_total_rows == 0
                || *max_total_rows > MAX_TOTAL_ROWS
                || !valid_timeout(*lock_timeout_ms, descriptor.lock_timeout_ms)
                || !valid_timeout(*statement_timeout_ms, descriptor.statement_timeout_ms)
                || !*exact_affected_rows =>
            {
                return Err(ReviewedMigrationError::Descriptor);
            }
            _ => {}
        }
    }
    for assertion in descriptor
        .pre_assertions
        .iter()
        .chain(&descriptor.post_assertions)
    {
        if !valid_id(&assertion.id)
            || !ids.insert(&assertion.id)
            || assertion.sql_path != format!("{base}/assertions/{}.sql", assertion.id)
        {
            return Err(ReviewedMigrationError::Descriptor);
        }
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn validate_step_sql(
    step: &ReviewedMigrationStepDescriptor,
    sql: &str,
    descriptor: &ReviewedMigrationDescriptor,
    bindings: &ReviewedPlanBindings<'_>,
    declared_tables: &BTreeSet<&str>,
) -> Result<(), ReviewedMigrationError> {
    let parsed = parse_one(sql)?;
    validate_ast_objects(&parsed, declared_tables, false)?;
    let root = root_node(&parsed)?;
    let parsed_objects = match step {
        ReviewedMigrationStepDescriptor::TransactionalSql { affected_rows, .. } => {
            let (dml, objects) = match root {
                PgNode::UpdateStmt(update) => {
                    validate_update_relation(update, declared_tables)?;
                    (true, update_objects(update, bindings)?)
                }
                PgNode::AlterTableStmt(alter) => {
                    validate_alter_table(alter, declared_tables)?;
                    (false, alter_table_objects(alter, bindings)?)
                }
                PgNode::IndexStmt(index) => {
                    if index.concurrent {
                        return Err(ReviewedMigrationError::Sql);
                    }
                    validate_range_var(
                        index.relation.as_ref().ok_or(ReviewedMigrationError::Sql)?,
                        declared_tables,
                    )?;
                    (false, index_objects(index, bindings)?)
                }
                PgNode::DropStmt(drop) => {
                    validate_drop_table(drop, declared_tables)?;
                    (false, drop_table_objects(drop, bindings)?)
                }
                _ => return Err(ReviewedMigrationError::Sql),
            };
            if dml != affected_rows.is_some() {
                return Err(ReviewedMigrationError::Sql);
            }
            objects
        }
        ReviewedMigrationStepDescriptor::ChunkedBackfill { entity_id, .. } => {
            if descriptor.change_class != CompiledRegistryChangeClass::DataBackfillRequired {
                return Err(ReviewedMigrationError::Descriptor);
            }
            let entity = bindings
                .candidate_entities
                .get(entity_id)
                .or_else(|| bindings.prior_entities.get(entity_id))
                .ok_or(ReviewedMigrationError::Descriptor)?;
            if !descriptor
                .covers
                .iter()
                .any(|cover| cover.target.entity_id.as_deref() == Some(entity_id))
            {
                return Err(ReviewedMigrationError::Coverage);
            }
            let PgNode::UpdateStmt(update) = root else {
                return Err(ReviewedMigrationError::Sql);
            };
            validate_chunked_update(update, &entity.physical_table, declared_tables, &parsed)?;
            update_objects(update, bindings)?
        }
    };
    if parsed_objects != step.objects() {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn validate_assertions(
    descriptors: &[ReviewedMigrationAssertionDescriptor],
    files: &BTreeMap<String, Vec<u8>>,
    declared_tables: &BTreeSet<&str>,
    referenced_paths: &mut BTreeSet<String>,
) -> Result<Vec<ValidatedReviewedMigrationAssertion>, ReviewedMigrationError> {
    let mut result = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        referenced_paths.insert(descriptor.sql_path.clone());
        let sql = read_sql(files, &descriptor.sql_path)?;
        let parsed = parse_one(sql)?;
        validate_ast_objects(&parsed, declared_tables, true)?;
        let PgNode::SelectStmt(select) = root_node(&parsed)? else {
            return Err(ReviewedMigrationError::Sql);
        };
        if select.into_clause.is_some()
            || select.with_clause.is_some()
            || !select.locking_clause.is_empty()
            || SetOperation::try_from(select.op).ok() != Some(SetOperation::SetopNone)
            || select.target_list.len() != 1
        {
            return Err(ReviewedMigrationError::Sql);
        }
        let value = select
            .target_list
            .first()
            .and_then(|node| node.node.as_ref())
            .and_then(|node| match node {
                PgNode::ResTarget(target) => target.val.as_deref(),
                _ => None,
            })
            .and_then(|node| node.node.as_ref())
            .ok_or(ReviewedMigrationError::Sql)?;
        if !boolean_result_expression(value)? {
            return Err(ReviewedMigrationError::Sql);
        }
        result.push(ValidatedReviewedMigrationAssertion {
            descriptor: descriptor.clone(),
            sql: sql.to_owned(),
            sha256: digest(sql.as_bytes()),
        });
    }
    Ok(result)
}

#[cfg(feature = "tooling")]
struct ReceiptValidationContext<'a> {
    descriptor_bytes: &'a [u8],
    steps: &'a [ValidatedReviewedMigrationStep],
    pre_assertions: &'a [ValidatedReviewedMigrationAssertion],
    post_assertions: &'a [ValidatedReviewedMigrationAssertion],
    descriptor: &'a ReviewedMigrationDescriptor,
    bindings: &'a ReviewedPlanBindings<'a>,
    base: &'a str,
    files: &'a BTreeMap<String, Vec<u8>>,
    referenced_paths: &'a mut BTreeSet<String>,
}

#[cfg(feature = "tooling")]
fn validate_receipt(
    receipt: &MigrationRehearsalReceipt,
    context: ReceiptValidationContext<'_>,
) -> Result<(), ReviewedMigrationError> {
    let ReceiptValidationContext {
        descriptor_bytes,
        steps,
        pre_assertions,
        post_assertions,
        descriptor,
        bindings,
        base,
        files,
        referenced_paths,
    } = context;
    let expected_sql = steps
        .iter()
        .map(|step| ArtifactDigestBinding {
            path: step.descriptor.sql_path().to_owned(),
            sha256: step.sha256.clone(),
        })
        .collect::<Vec<_>>();
    let expected_assertions = pre_assertions
        .iter()
        .chain(post_assertions)
        .map(|assertion| ArtifactDigestBinding {
            path: assertion.descriptor.sql_path.clone(),
            sha256: assertion.sha256.clone(),
        })
        .collect::<Vec<_>>();
    let metadata_only = steps.is_empty() && covers_are_metadata_only(&descriptor.covers);
    if receipt.prior_revision != bindings.prior_revision
        || receipt.prior_schema_fingerprint != bindings.prior_schema_fingerprint
        || receipt.final_schema_fingerprint != bindings.final_schema_fingerprint
        || receipt.plan_sha256 != digest(descriptor_bytes)
        || receipt.sql_sha256 != expected_sql
        || receipt.assertion_sha256 != expected_assertions
        || !(15..=18).contains(&receipt.postgres_major)
        || (receipt.fixture_inventory.is_empty() && !metadata_only)
        || !strictly_sorted(
            receipt
                .fixture_inventory
                .iter()
                .map(|fixture| fixture.id.as_str()),
        )
        || !receipt.proofs.lock_timeout
    {
        return Err(ReviewedMigrationError::Evidence);
    }
    for fixture in &receipt.fixture_inventory {
        if !valid_id(&fixture.id)
            || fixture.path != format!("{base}/fixtures/{}.jsonl", fixture.id)
            || !valid_digest(&fixture.sha256)
            || !referenced_paths.insert(fixture.path.clone())
        {
            return Err(ReviewedMigrationError::Evidence);
        }
        let bytes = files
            .get(&fixture.path)
            .ok_or(ReviewedMigrationError::Evidence)?;
        if bytes.is_empty()
            || bytes.len() > MAX_FIXTURE_BYTES
            || !bytes.ends_with(b"\n")
            || digest(bytes) != fixture.sha256
            || validate_fixture_jsonl(bytes)? != fixture.row_count
        {
            return Err(ReviewedMigrationError::Evidence);
        }
    }
    let has_chunks = steps.iter().any(|step| {
        matches!(
            step.descriptor,
            ReviewedMigrationStepDescriptor::ChunkedBackfill { .. }
        )
    });
    let destructive =
        descriptor.change_class == CompiledRegistryChangeClass::DestructiveOrIrreversible;
    if receipt.proofs.chunk_resume != has_chunks || receipt.proofs.destructive_resume != destructive
    {
        return Err(ReviewedMigrationError::Evidence);
    }
    let expected_row_steps = steps
        .iter()
        .filter_map(|step| match &step.descriptor {
            ReviewedMigrationStepDescriptor::TransactionalSql {
                id,
                affected_rows: Some(bounds),
                ..
            } => Some((id.as_str(), bounds.min, bounds.max)),
            ReviewedMigrationStepDescriptor::ChunkedBackfill {
                id, max_total_rows, ..
            } => Some((id.as_str(), 0, *max_total_rows)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if receipt.row_assertions.len() != expected_row_steps.len() {
        return Err(ReviewedMigrationError::Evidence);
    }
    for (assertion, (step_id, min, max)) in receipt.row_assertions.iter().zip(expected_row_steps) {
        if assertion.step_id != step_id
            || assertion.affected_rows < min
            || assertion.affected_rows > max
        {
            return Err(ReviewedMigrationError::Evidence);
        }
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn validate_fixture_jsonl(bytes: &[u8]) -> Result<u64, ReviewedMigrationError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ReviewedMigrationError::Evidence)?;
    let mut count = 0_u64;
    for line in text.split_terminator('\n') {
        if line.is_empty() || line.ends_with('\r') {
            return Err(ReviewedMigrationError::Evidence);
        }
        let value =
            parse_json_strict(line.as_bytes()).map_err(|_| ReviewedMigrationError::Evidence)?;
        let canonical = canonicalize_json(&value).map_err(|_| ReviewedMigrationError::Evidence)?;
        if canonical != line.as_bytes() {
            return Err(ReviewedMigrationError::Evidence);
        }
        count = count
            .checked_add(1)
            .ok_or(ReviewedMigrationError::Evidence)?;
    }
    Ok(count)
}

#[cfg(feature = "tooling")]
fn validate_backup(
    backup: &ExternalBackupBinding,
    bindings: &ReviewedPlanBindings<'_>,
) -> Result<(), ReviewedMigrationError> {
    if backup.database_id != bindings.database_id
        || backup.prior_revision != bindings.prior_revision
        || backup.prior_schema_fingerprint != bindings.prior_schema_fingerprint
        || !valid_digest(&backup.sha256)
        || backup.byte_length == 0
        || backup.max_age_seconds == 0
        || backup.max_age_seconds > MAX_BACKUP_AGE_SECONDS
        || OffsetDateTime::parse(&backup.created_at, &Rfc3339).is_err()
    {
        return Err(ReviewedMigrationError::Evidence);
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn parse_one(sql: &str) -> Result<pg_query::ParseResult, ReviewedMigrationError> {
    if sql.is_empty() || sql.len() > MAX_SQL_BYTES || sql.as_bytes().contains(&0) {
        return Err(ReviewedMigrationError::Sql);
    }
    let parsed = pg_query::parse(sql).map_err(|_| ReviewedMigrationError::Sql)?;
    if parsed.protobuf.stmts.len() != 1 || !parsed.warnings.is_empty() {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(parsed)
}

#[cfg(feature = "tooling")]
fn root_node(parsed: &pg_query::ParseResult) -> Result<&PgNode, ReviewedMigrationError> {
    parsed
        .protobuf
        .stmts
        .first()
        .and_then(|statement| statement.stmt.as_deref())
        .and_then(|statement| statement.node.as_ref())
        .ok_or(ReviewedMigrationError::Sql)
}

#[cfg(feature = "tooling")]
fn validate_ast_objects(
    parsed: &pg_query::ParseResult,
    declared_tables: &BTreeSet<&str>,
    assertion: bool,
) -> Result<(), ReviewedMigrationError> {
    let mut statement_nodes = 0;
    for (node, _, _, _) in parsed.protobuf.nodes() {
        match node {
            NodeRef::RangeVar(range) => validate_range_var(range, declared_tables)?,
            NodeRef::FuncCall(function) => validate_function(function)?,
            NodeRef::AExpr(expression) => validate_operator(expression)?,
            NodeRef::TypeName(type_name) => validate_type_name(type_name)?,
            NodeRef::ParamRef(_) if assertion => return Err(ReviewedMigrationError::Sql),
            NodeRef::SqlvalueFunction(_)
            | NodeRef::RangeFunction(_)
            | NodeRef::TableFunc(_)
            | NodeRef::IntoClause(_) => return Err(ReviewedMigrationError::Sql),
            NodeRef::SelectStmt(_) if assertion => statement_nodes += 1,
            NodeRef::UpdateStmt(_)
            | NodeRef::AlterTableStmt(_)
            | NodeRef::IndexStmt(_)
            | NodeRef::DropStmt(_)
            | NodeRef::SelectStmt(_) => statement_nodes += 1,
            node if is_forbidden_statement_node(node) => return Err(ReviewedMigrationError::Sql),
            _ => {}
        }
    }
    if (!assertion && statement_nodes != 1) || (assertion && statement_nodes == 0) {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(())
}

#[allow(clippy::match_same_arms)]
#[cfg(feature = "tooling")]
fn is_forbidden_statement_node(node: NodeRef<'_>) -> bool {
    matches!(
        node,
        NodeRef::InsertStmt(_)
            | NodeRef::DeleteStmt(_)
            | NodeRef::MergeStmt(_)
            | NodeRef::TransactionStmt(_)
            | NodeRef::VariableSetStmt(_)
            | NodeRef::VariableShowStmt(_)
            | NodeRef::CreateStmt(_)
            | NodeRef::CreateTableAsStmt(_)
            | NodeRef::CopyStmt(_)
            | NodeRef::CreateFunctionStmt(_)
            | NodeRef::AlterFunctionStmt(_)
            | NodeRef::DoStmt(_)
            | NodeRef::CreateTrigStmt(_)
            | NodeRef::CreateEventTrigStmt(_)
            | NodeRef::AlterEventTrigStmt(_)
            | NodeRef::CreateSchemaStmt(_)
            | NodeRef::AlterObjectSchemaStmt(_)
            | NodeRef::CreateExtensionStmt(_)
            | NodeRef::AlterExtensionStmt(_)
            | NodeRef::AlterExtensionContentsStmt(_)
            | NodeRef::CreatedbStmt(_)
            | NodeRef::DropdbStmt(_)
            | NodeRef::CreateRoleStmt(_)
            | NodeRef::AlterRoleStmt(_)
            | NodeRef::DropRoleStmt(_)
            | NodeRef::AlterRoleSetStmt(_)
            | NodeRef::AlterDatabaseStmt(_)
            | NodeRef::AlterDatabaseSetStmt(_)
            | NodeRef::GrantStmt(_)
            | NodeRef::GrantRoleStmt(_)
            | NodeRef::AlterDefaultPrivilegesStmt(_)
            | NodeRef::TruncateStmt(_)
            | NodeRef::VacuumStmt(_)
            | NodeRef::CallStmt(_)
            | NodeRef::LockStmt(_)
            | NodeRef::PrepareStmt(_)
            | NodeRef::ExecuteStmt(_)
            | NodeRef::DeallocateStmt(_)
            | NodeRef::DeclareCursorStmt(_)
            | NodeRef::CreateSeqStmt(_)
            | NodeRef::AlterSeqStmt(_)
            | NodeRef::CreatePolicyStmt(_)
            | NodeRef::AlterPolicyStmt(_)
            | NodeRef::ViewStmt(_)
            | NodeRef::RuleStmt(_)
            | NodeRef::RefreshMatViewStmt(_)
            | NodeRef::ReindexStmt(_)
            | NodeRef::ClusterStmt(_)
            | NodeRef::LoadStmt(_)
    )
}

#[cfg(feature = "tooling")]
fn validate_range_var(
    range: &pg_query::protobuf::RangeVar,
    declared_tables: &BTreeSet<&str>,
) -> Result<(), ReviewedMigrationError> {
    if !range.catalogname.is_empty()
        || range.schemaname != "registry_data"
        || !declared_tables.contains(range.relname.as_str())
        || (!range.relpersistence.is_empty() && range.relpersistence != "p")
    {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn validate_function(
    function: &pg_query::protobuf::FuncCall,
) -> Result<(), ReviewedMigrationError> {
    let name = node_strings(&function.funcname)?;
    if !matches!(
        name.as_slice(),
        [schema, function]
            if schema == "pg_catalog"
                && matches!(function.as_str(), "count" | "bool_and" | "every")
    ) || function.over.is_some()
        || function.agg_within_group
        || function.func_variadic
    {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn validate_operator(expression: &pg_query::protobuf::AExpr) -> Result<(), ReviewedMigrationError> {
    let names = node_strings(&expression.name)?;
    if names.len() != 1
        || !matches!(
            names[0].as_str(),
            "=" | "<>" | "<" | ">" | "<=" | ">=" | "+" | "-" | "*" | "/"
        )
    {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn boolean_result_expression(node: &PgNode) -> Result<bool, ReviewedMigrationError> {
    Ok(match node {
        PgNode::AExpr(expression) => {
            let names = node_strings(&expression.name)?;
            names.len() == 1 && matches!(names[0].as_str(), "=" | "<>" | "<" | ">" | "<=" | ">=")
        }
        PgNode::BoolExpr(_) | PgNode::BooleanTest(_) | PgNode::NullTest(_) => true,
        PgNode::SubLink(link) => {
            SubLinkType::try_from(link.sub_link_type).ok() == Some(SubLinkType::ExistsSublink)
        }
        PgNode::AConst(constant) => matches!(constant.val, Some(a_const::Val::Boolval(_))),
        _ => false,
    })
}

#[cfg(feature = "tooling")]
fn validate_type_name(
    type_name: &pg_query::protobuf::TypeName,
) -> Result<(), ReviewedMigrationError> {
    let names = node_strings(&type_name.names)?;
    if type_name.setof
        || type_name.pct_type
        || !matches!(
            names.as_slice(),
            [schema, name]
                if schema == "pg_catalog"
                    && matches!(
                        name.as_str(),
                        "bool"
                            | "date"
                            | "float8"
                            | "int2"
                            | "int4"
                            | "int8"
                            | "jsonb"
                            | "numeric"
                            | "text"
                            | "timestamp"
                            | "timestamptz"
                            | "uuid"
                            | "varchar"
                    )
        )
    {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn validate_update_relation(
    update: &pg_query::protobuf::UpdateStmt,
    declared_tables: &BTreeSet<&str>,
) -> Result<(), ReviewedMigrationError> {
    validate_range_var(
        update
            .relation
            .as_ref()
            .ok_or(ReviewedMigrationError::Sql)?,
        declared_tables,
    )?;
    if update.target_list.is_empty()
        || update.where_clause.is_none()
        || update.with_clause.is_some()
        || !update.from_clause.is_empty()
        || !update.returning_list.is_empty()
    {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn validate_chunked_update(
    update: &pg_query::protobuf::UpdateStmt,
    physical_table: &str,
    declared_tables: &BTreeSet<&str>,
    parsed: &pg_query::ParseResult,
) -> Result<(), ReviewedMigrationError> {
    validate_update_relation(update, declared_tables)?;
    let relation = update
        .relation
        .as_ref()
        .ok_or(ReviewedMigrationError::Sql)?;
    if relation.relname != physical_table {
        return Err(ReviewedMigrationError::Sql);
    }
    for target in &update.target_list {
        let Some(PgNode::ResTarget(target)) = target.node.as_ref() else {
            return Err(ReviewedMigrationError::Sql);
        };
        if target.name.is_empty() || target.name == "record_id" || !target.indirection.is_empty() {
            return Err(ReviewedMigrationError::Sql);
        }
    }
    let where_node = update
        .where_clause
        .as_deref()
        .and_then(|node| node.node.as_ref())
        .ok_or(ReviewedMigrationError::Sql)?;
    let PgNode::AExpr(expression) = where_node else {
        return Err(ReviewedMigrationError::Sql);
    };
    if AExprKind::try_from(expression.kind).ok() != Some(AExprKind::AexprOpAny)
        || node_strings(&expression.name)?.as_slice() != ["="]
        || !is_column_ref(expression.lexpr.as_deref(), "record_id")
        || !is_uuid_array_parameter(expression.rexpr.as_deref())
    {
        return Err(ReviewedMigrationError::Sql);
    }
    let parameters = parsed
        .protobuf
        .nodes()
        .into_iter()
        .filter_map(|(node, _, _, _)| match node {
            NodeRef::ParamRef(parameter) => Some(parameter.number),
            _ => None,
        })
        .collect::<Vec<_>>();
    if parameters != [1] {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn validate_alter_table(
    alter: &pg_query::protobuf::AlterTableStmt,
    declared_tables: &BTreeSet<&str>,
) -> Result<(), ReviewedMigrationError> {
    validate_range_var(
        alter.relation.as_ref().ok_or(ReviewedMigrationError::Sql)?,
        declared_tables,
    )?;
    if alter.cmds.is_empty() {
        return Err(ReviewedMigrationError::Sql);
    }
    for command in &alter.cmds {
        let Some(PgNode::AlterTableCmd(command)) = command.node.as_ref() else {
            return Err(ReviewedMigrationError::Sql);
        };
        let subtype =
            AlterTableType::try_from(command.subtype).map_err(|_| ReviewedMigrationError::Sql)?;
        if !matches!(
            subtype,
            AlterTableType::AtColumnDefault
                | AlterTableType::AtDropNotNull
                | AlterTableType::AtSetNotNull
                | AlterTableType::AtDropColumn
                | AlterTableType::AtAddConstraint
                | AlterTableType::AtAlterConstraint
                | AlterTableType::AtValidateConstraint
                | AlterTableType::AtDropConstraint
                | AlterTableType::AtAlterColumnType
        ) {
            return Err(ReviewedMigrationError::Sql);
        }
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn validate_drop_table(
    drop: &pg_query::protobuf::DropStmt,
    declared_tables: &BTreeSet<&str>,
) -> Result<(), ReviewedMigrationError> {
    if ObjectType::try_from(drop.remove_type).ok() != Some(ObjectType::ObjectTable)
        || drop.concurrent
        || drop.objects.len() != 1
    {
        return Err(ReviewedMigrationError::Sql);
    }
    let Some(PgNode::List(object)) = drop.objects[0].node.as_ref() else {
        return Err(ReviewedMigrationError::Sql);
    };
    let names = node_strings(&object.items)?;
    if names.len() != 2
        || names[0] != "registry_data"
        || !declared_tables.contains(names[1].as_str())
    {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(())
}

#[cfg(feature = "tooling")]
fn update_objects(
    update: &pg_query::protobuf::UpdateStmt,
    bindings: &ReviewedPlanBindings<'_>,
) -> Result<Vec<ReviewedMigrationObject>, ReviewedMigrationError> {
    let relation = update
        .relation
        .as_ref()
        .ok_or(ReviewedMigrationError::Sql)?;
    let entity_id = entity_for_table(&relation.relname, bindings)?;
    let mut objects = Vec::with_capacity(update.target_list.len());
    for target in &update.target_list {
        let Some(PgNode::ResTarget(target)) = target.node.as_ref() else {
            return Err(ReviewedMigrationError::Sql);
        };
        let member_id = member_for_physical(
            &entity_id,
            &target.name,
            ReviewedMigrationObjectKind::Field,
            bindings,
        )?;
        objects.push(reviewed_object(
            &relation.relname,
            &entity_id,
            ReviewedMigrationObjectKind::Field,
            Some(member_id),
            &target.name,
        ));
    }
    finish_objects(objects)
}

#[cfg(feature = "tooling")]
fn alter_table_objects(
    alter: &pg_query::protobuf::AlterTableStmt,
    bindings: &ReviewedPlanBindings<'_>,
) -> Result<Vec<ReviewedMigrationObject>, ReviewedMigrationError> {
    let relation = alter.relation.as_ref().ok_or(ReviewedMigrationError::Sql)?;
    let entity_id = entity_for_table(&relation.relname, bindings)?;
    let mut objects = Vec::with_capacity(alter.cmds.len());
    for command in &alter.cmds {
        let Some(PgNode::AlterTableCmd(command)) = command.node.as_ref() else {
            return Err(ReviewedMigrationError::Sql);
        };
        let subtype =
            AlterTableType::try_from(command.subtype).map_err(|_| ReviewedMigrationError::Sql)?;
        let kind = match subtype {
            AlterTableType::AtAddConstraint
            | AlterTableType::AtAlterConstraint
            | AlterTableType::AtValidateConstraint
            | AlterTableType::AtDropConstraint => ReviewedMigrationObjectKind::Constraint,
            AlterTableType::AtColumnDefault
            | AlterTableType::AtDropNotNull
            | AlterTableType::AtSetNotNull
            | AlterTableType::AtDropColumn
            | AlterTableType::AtAlterColumnType => ReviewedMigrationObjectKind::Field,
            _ => return Err(ReviewedMigrationError::Sql),
        };
        let member_name = alter_table_command_member_name(command, subtype)?;
        let member_id = member_for_physical(&entity_id, member_name, kind, bindings)?;
        objects.push(reviewed_object(
            &relation.relname,
            &entity_id,
            kind,
            Some(member_id),
            member_name,
        ));
    }
    finish_objects(objects)
}

#[cfg(feature = "tooling")]
fn alter_table_command_member_name(
    command: &pg_query::protobuf::AlterTableCmd,
    subtype: AlterTableType,
) -> Result<&str, ReviewedMigrationError> {
    if !command.name.is_empty() {
        return Ok(&command.name);
    }
    if subtype == AlterTableType::AtAddConstraint {
        let Some(PgNode::Constraint(constraint)) =
            command.def.as_deref().and_then(|node| node.node.as_ref())
        else {
            return Err(ReviewedMigrationError::Sql);
        };
        if ConstrType::try_from(constraint.contype).is_err() || constraint.conname.is_empty() {
            return Err(ReviewedMigrationError::Sql);
        }
        return Ok(&constraint.conname);
    }
    Err(ReviewedMigrationError::Sql)
}

#[cfg(feature = "tooling")]
fn index_objects(
    index: &pg_query::protobuf::IndexStmt,
    bindings: &ReviewedPlanBindings<'_>,
) -> Result<Vec<ReviewedMigrationObject>, ReviewedMigrationError> {
    let relation = index.relation.as_ref().ok_or(ReviewedMigrationError::Sql)?;
    if index.idxname.is_empty()
        || !index.table_space.is_empty()
        || (!index.access_method.is_empty() && index.access_method != "btree")
    {
        return Err(ReviewedMigrationError::Sql);
    }
    let entity_id = entity_for_table(&relation.relname, bindings)?;
    let member_id = member_for_physical(
        &entity_id,
        &index.idxname,
        ReviewedMigrationObjectKind::Index,
        bindings,
    )?;
    Ok(vec![reviewed_object(
        &relation.relname,
        &entity_id,
        ReviewedMigrationObjectKind::Index,
        Some(member_id),
        &index.idxname,
    )])
}

#[cfg(feature = "tooling")]
fn drop_table_objects(
    drop: &pg_query::protobuf::DropStmt,
    bindings: &ReviewedPlanBindings<'_>,
) -> Result<Vec<ReviewedMigrationObject>, ReviewedMigrationError> {
    let Some(PgNode::List(object)) = drop.objects[0].node.as_ref() else {
        return Err(ReviewedMigrationError::Sql);
    };
    let names = node_strings(&object.items)?;
    let table = names.get(1).ok_or(ReviewedMigrationError::Sql)?;
    let entity_id = entity_for_table(table, bindings)?;
    Ok(vec![reviewed_object(
        table,
        &entity_id,
        ReviewedMigrationObjectKind::Entity,
        None,
        table,
    )])
}

#[cfg(feature = "tooling")]
fn entity_for_table(
    table: &str,
    bindings: &ReviewedPlanBindings<'_>,
) -> Result<String, ReviewedMigrationError> {
    let ids = bindings
        .prior_entities
        .values()
        .chain(bindings.candidate_entities.values())
        .filter(|entity| entity.physical_table == table)
        .map(|entity| entity.id.as_str())
        .collect::<BTreeSet<_>>();
    if ids.len() != 1 {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(ids.into_iter().next().expect("one id exists").to_owned())
}

#[cfg(feature = "tooling")]
fn member_for_physical(
    entity_id: &str,
    physical_name: &str,
    kind: ReviewedMigrationObjectKind,
    bindings: &ReviewedPlanBindings<'_>,
) -> Result<String, ReviewedMigrationError> {
    let inventories = [
        bindings.prior_physical_names,
        bindings.candidate_physical_names,
    ];
    let mut ids = BTreeSet::new();
    for inventory in inventories {
        let Some(entity) = inventory.entities.get(entity_id) else {
            continue;
        };
        let members = match kind {
            ReviewedMigrationObjectKind::Field => &entity.fields,
            ReviewedMigrationObjectKind::Constraint => &entity.constraints,
            ReviewedMigrationObjectKind::Index => &entity.indexes,
            ReviewedMigrationObjectKind::Entity => return Err(ReviewedMigrationError::Sql),
        };
        ids.extend(
            members
                .iter()
                .filter(|(_, physical)| physical.as_str() == physical_name)
                .map(|(id, _)| id.as_str()),
        );
    }
    if ids.len() != 1 {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(ids.into_iter().next().expect("one id exists").to_owned())
}

#[cfg(feature = "tooling")]
fn reviewed_object(
    table: &str,
    entity_id: &str,
    kind: ReviewedMigrationObjectKind,
    member_id: Option<String>,
    physical_name: &str,
) -> ReviewedMigrationObject {
    ReviewedMigrationObject {
        schema: "registry_data".to_owned(),
        table: table.to_owned(),
        entity_id: entity_id.to_owned(),
        kind,
        member_id,
        physical_name: physical_name.to_owned(),
    }
}

#[cfg(feature = "tooling")]
fn finish_objects(
    mut objects: Vec<ReviewedMigrationObject>,
) -> Result<Vec<ReviewedMigrationObject>, ReviewedMigrationError> {
    objects.sort();
    if objects.is_empty() || objects.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ReviewedMigrationError::Sql);
    }
    Ok(objects)
}

#[cfg(feature = "tooling")]
fn object_cover(
    object: &ReviewedMigrationObject,
    covers: &[ReviewedChangeCover],
) -> Result<ReviewedChangeCover, ReviewedMigrationError> {
    let kind = match object.kind {
        ReviewedMigrationObjectKind::Entity => CompiledRegistryChangeTargetKind::Entity,
        ReviewedMigrationObjectKind::Field => CompiledRegistryChangeTargetKind::Field,
        ReviewedMigrationObjectKind::Constraint => CompiledRegistryChangeTargetKind::Constraint,
        ReviewedMigrationObjectKind::Index => CompiledRegistryChangeTargetKind::Index,
    };
    let target = CompiledRegistryChangeTarget {
        kind,
        entity_id: Some(object.entity_id.clone()),
        member_id: object.member_id.clone(),
    };
    let matches = covers
        .iter()
        .filter(|cover| {
            cover.target == target
                || reference_target_cover_matches_implicit_constraint(cover, object)
        })
        .cloned()
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(ReviewedMigrationError::Coverage);
    }
    Ok(matches.into_iter().next().expect("one cover exists"))
}

#[cfg(feature = "tooling")]
fn reference_target_cover_matches_implicit_constraint(
    cover: &ReviewedChangeCover,
    object: &ReviewedMigrationObject,
) -> bool {
    cover.code == CompiledRegistryChangeCode::ReferenceTargetChanged
        && object.kind == ReviewedMigrationObjectKind::Constraint
        && cover.target.kind == CompiledRegistryChangeTargetKind::Field
        && cover.target.entity_id.as_deref() == Some(object.entity_id.as_str())
        && object
            .member_id
            .as_deref()
            .and_then(|member| member.strip_prefix("reference:"))
            == cover.target.member_id.as_deref()
}

#[cfg(feature = "tooling")]
fn covers_are_metadata_only(covers: &[ReviewedChangeCover]) -> bool {
    covers.iter().all(|cover| {
        matches!(
            cover.code,
            CompiledRegistryChangeCode::EntityRouteChanged
                | CompiledRegistryChangeCode::EntityMutationModeChanged
                | CompiledRegistryChangeCode::EntityClassificationChanged
                | CompiledRegistryChangeCode::FieldClassificationChanged
                | CompiledRegistryChangeCode::FieldTemporalRoleChanged
                | CompiledRegistryChangeCode::AccessProfileAdded
                | CompiledRegistryChangeCode::AccessProfileRemoved
                | CompiledRegistryChangeCode::AccessProfileChanged
                | CompiledRegistryChangeCode::RouteAdded
                | CompiledRegistryChangeCode::RouteRemoved
                | CompiledRegistryChangeCode::RouteChanged
                | CompiledRegistryChangeCode::QueryInventoryChanged
                | CompiledRegistryChangeCode::EventAdded
                | CompiledRegistryChangeCode::EventRemoved
                | CompiledRegistryChangeCode::EventChanged
        )
    })
}

#[cfg(feature = "tooling")]
fn is_column_ref(node: Option<&pg_query::protobuf::Node>, expected: &str) -> bool {
    let Some(PgNode::ColumnRef(column)) = node.and_then(|node| node.node.as_ref()) else {
        return false;
    };
    node_strings(&column.fields).is_ok_and(|names| names.as_slice() == [expected])
}

#[cfg(feature = "tooling")]
fn is_uuid_array_parameter(node: Option<&pg_query::protobuf::Node>) -> bool {
    let Some(PgNode::TypeCast(cast)) = node.and_then(|node| node.node.as_ref()) else {
        return false;
    };
    let parameter = cast.arg.as_deref().and_then(|node| node.node.as_ref());
    let type_name = cast.type_name.as_ref();
    matches!(parameter, Some(PgNode::ParamRef(parameter)) if parameter.number == 1)
        && type_name.is_some_and(|name| {
            name.array_bounds.len() == 1
                && node_strings(&name.names)
                    .is_ok_and(|names| names.as_slice() == ["pg_catalog", "uuid"])
        })
}

#[cfg(feature = "tooling")]
fn node_strings(nodes: &[pg_query::protobuf::Node]) -> Result<Vec<String>, ReviewedMigrationError> {
    nodes
        .iter()
        .map(|node| match node.node.as_ref() {
            Some(PgNode::String(value)) => Ok(value.sval.clone()),
            _ => Err(ReviewedMigrationError::Sql),
        })
        .collect()
}

#[cfg(feature = "tooling")]
fn read_sql<'a>(
    files: &'a BTreeMap<String, Vec<u8>>,
    path: &str,
) -> Result<&'a str, ReviewedMigrationError> {
    let bytes = files.get(path).ok_or(ReviewedMigrationError::Closure)?;
    if reviewed_artifact_kind(path) != Some(ReviewedArtifactKind::StepSql)
        && reviewed_artifact_kind(path) != Some(ReviewedArtifactKind::AssertionSql)
    {
        return Err(ReviewedMigrationError::Closure);
    }
    std::str::from_utf8(bytes).map_err(|_| ReviewedMigrationError::Sql)
}

#[cfg(feature = "tooling")]
fn descriptor_base(
    path: &str,
    descriptor_id: &str,
) -> Result<(String, String), ReviewedMigrationError> {
    if reviewed_artifact_kind(path) != Some(ReviewedArtifactKind::Descriptor) {
        return Err(ReviewedMigrationError::Descriptor);
    }
    let components = path.split('/').collect::<Vec<_>>();
    let module_id = components[1];
    if components[3] != descriptor_id {
        return Err(ReviewedMigrationError::Descriptor);
    }
    Ok((
        module_id.to_owned(),
        format!("modules/{module_id}/migrations/{descriptor_id}"),
    ))
}

#[cfg(feature = "tooling")]
fn parse_canonical<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
) -> Result<T, ReviewedMigrationError> {
    let value = parse_json_strict(bytes).map_err(|_| ReviewedMigrationError::Descriptor)?;
    let canonical = canonicalize_json(&value).map_err(|_| ReviewedMigrationError::Descriptor)?;
    if canonical != bytes {
        return Err(ReviewedMigrationError::Descriptor);
    }
    serde_json::from_value(value).map_err(|_| ReviewedMigrationError::Descriptor)
}

#[cfg(feature = "tooling")]
fn strictly_sorted<T: Ord>(values: impl Iterator<Item = T>) -> bool {
    let mut prior = None;
    for value in values {
        if prior.as_ref().is_some_and(|prior| prior >= &value) {
            return false;
        }
        prior = Some(value);
    }
    true
}

#[cfg(feature = "tooling")]
fn valid_timeout(value: u64, ceiling: u64) -> bool {
    value > 0 && value <= ceiling
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

#[cfg(feature = "tooling")]
fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(feature = "tooling")]
fn digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut result = String::with_capacity(71);
    result.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to a String cannot fail");
    }
    result
}
