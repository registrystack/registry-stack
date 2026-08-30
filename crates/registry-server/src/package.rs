// SPDX-License-Identifier: Apache-2.0
//! Closed Registry Server package verification boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use registry_platform_crypto::{verify, PublicJwk};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::artifacts::REGISTRY_METADATA_ARTIFACT_PATH;
use crate::compiler::{compile_project, CompileProfile};
use crate::contract::{
    parse_module_yaml, parse_project_yaml, FieldTypeSource, RegistryModule, RegistryProject,
};
use crate::generated_ddl::{add_column_statement, DdlStatement};
#[cfg(feature = "tooling")]
use crate::migration_plan::{
    prepare_reviewed_migration_plan, validate_reviewed_migration_plan,
    PreparedReviewedMigrationPlan, ReviewedMigrationRecovery, ReviewedMigrationSource,
    ReviewedMigrationStepDescriptor, ReviewedPlanBindings,
};
use crate::migration_plan::{
    reviewed_artifact_kind, ReviewedArtifactKind, ValidatedReviewedMigrationPlan,
};
use crate::model::{
    CompiledAccessInventory, CompiledEntity, CompiledQueryInventory, CompiledRouteInventory,
};
use crate::physical_names::PhysicalNameInventory;
use crate::CompiledRegistry;

pub const PACKAGE_API_VERSION: &str = "registry.registrystack.org/package/v1";
pub const TRUST_ANCHOR_API_VERSION: &str = "registry.registrystack.org/package-trust/v1";
pub const COMPILER_ID: &str = "registry-server";
pub const FIXTURE_JOURNEYS_PATH: &str = "tests/journeys.yaml";
pub const MAX_PACKAGE_SOURCE_FILE_BYTES: u64 = 16 * 1024 * 1024;

const MANIFEST_PATH: &str = "package.json";
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = MAX_PACKAGE_SOURCE_FILE_BYTES;
const MAX_PACKAGE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PACKAGE_FILES: usize = 1_024;
const MAX_PATH_BYTES: usize = 512;
const MAX_PATH_COMPONENTS: usize = 16;
const MAX_MIGRATION_STATEMENTS: usize = 1_024;
const MAX_MIGRATION_BASELINE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageEnvelope {
    pub api_version: String,
    pub signed: PackageManifest,
    pub signatures: Vec<PackageSignature>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageManifest {
    pub package_id: String,
    pub package_revision: String,
    pub environment: String,
    pub instance_id: String,
    pub database_id: String,
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_revision: Option<String>,
    pub compiler: CompilerIdentity,
    pub schema_fingerprint: String,
    pub signature_policy: SignaturePolicy,
    pub sources: CapturedSources,
    pub files: Vec<PackageFile>,
    pub migration_plan: MigrationPlan,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompilerIdentity {
    pub id: String,
    pub source_revision: String,
    pub profile: PackageCompileProfile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageCompileProfile {
    Production,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignaturePolicy {
    pub threshold: u16,
    pub key_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageSignature {
    pub key_id: String,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CapturedSources {
    pub project: String,
    pub modules: Vec<CapturedModule>,
    pub fixture_journeys: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CapturedModule {
    pub id: String,
    pub path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageFile {
    pub path: String,
    pub role: PackageFileRole,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageFileRole {
    SourceProject,
    SourceModule,
    FixtureJourneys,
    GovernedModel,
    PhysicalNameInventory,
    RouteInventory,
    AccessInventory,
    QueryInventory,
    EventInventory,
    CallerSafeMetadata,
    GeneratedDdl,
    MigrationPlan,
    GeneratedOpenapi,
    EntityJsonSchema,
    LossyManifestProjection,
    ReviewedMigrationDescriptor,
    ReviewedMigrationStepSql,
    ReviewedMigrationAssertionSql,
    MigrationRehearsalReceipt,
    ExternalBackupBinding,
    MigrationRehearsalFixture,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MigrationPlan {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_baseline: Option<CompiledRegistryMigrationBaseline>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<CompiledRegistryChange>,
    pub statements: Vec<DdlStatement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reviewed_descriptors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_schema_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledRegistryMigrationBaseline {
    pub package_revision: String,
    pub registry_id: String,
    pub registry_version: String,
    pub registry_revision: String,
    pub entities: BTreeMap<String, CompiledEntity>,
    pub physical_names: PhysicalNameInventory,
    pub routes: CompiledRouteInventory,
    pub access: CompiledAccessInventory,
    pub queries: CompiledQueryInventory,
}

impl CompiledRegistryMigrationBaseline {
    pub fn from_compiled(package_revision: &str, compiled: &CompiledRegistry) -> Self {
        Self {
            package_revision: package_revision.to_owned(),
            registry_id: compiled.registry_id().to_owned(),
            registry_version: compiled.version().to_owned(),
            registry_revision: compiled.revision().to_owned(),
            entities: compiled.entities().clone(),
            physical_names: compiled.physical_names().clone(),
            routes: compiled.routes().clone(),
            access: compiled.access().clone(),
            queries: compiled.queries().clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledRegistryChangeSet {
    pub from_revision: String,
    pub changes: Vec<CompiledRegistryChange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_plan: Option<MigrationPlan>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledRegistryChange {
    pub class: CompiledRegistryChangeClass,
    pub code: CompiledRegistryChangeCode,
    pub target: CompiledRegistryChangeTarget,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledRegistryChangeClass {
    CompatibleAdditive,
    DataBackfillRequired,
    AccessOrDisclosureChange,
    DestructiveOrIrreversible,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledRegistryChangeCode {
    RegistryIdentityChanged,
    EntityAdded,
    EntityRemoved,
    EntityPhysicalNameChanged,
    EntityRouteChanged,
    EntityMutationModeChanged,
    EntityClassificationChanged,
    EntityTemporalChanged,
    FieldAddedOptional,
    FieldAddedRequired,
    FieldRemoved,
    FieldTypeChanged,
    FieldPhysicalNameChanged,
    FieldRequirednessChanged,
    FieldClassificationChanged,
    FieldTemporalRoleChanged,
    ReferenceTargetChanged,
    ConstraintAdded,
    ConstraintRemoved,
    ConstraintChanged,
    IndexAdded,
    IndexRemoved,
    IndexChanged,
    AccessProfileAdded,
    AccessProfileRemoved,
    AccessProfileChanged,
    RouteAdded,
    RouteRemoved,
    RouteChanged,
    QueryInventoryChanged,
    EventAdded,
    EventRemoved,
    EventChanged,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledRegistryChangeTarget {
    pub kind: CompiledRegistryChangeTargetKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledRegistryChangeTargetKind {
    Registry,
    Entity,
    Field,
    Constraint,
    Index,
    AccessProfile,
    Route,
    QueryInventory,
    Event,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageTrustAnchor {
    pub api_version: String,
    pub environment: String,
    pub instance_id: String,
    pub database_id: String,
    pub threshold: u16,
    pub keys: Vec<TrustAnchorKey>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TrustAnchorKey {
    pub key_id: String,
    pub jwk: Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageIntent<'a> {
    InitialActivation,
    Activation {
        active_revision: &'a str,
        active_sequence: u64,
    },
    Startup {
        active_revision: &'a str,
        active_sequence: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum VerifiedPackageIntent {
    InitialActivation,
    Activation {
        active_revision: String,
        active_sequence: u64,
    },
    Startup {
        active_revision: String,
        active_sequence: u64,
    },
}

impl VerifiedPackageIntent {
    fn from_intent(intent: PackageIntent<'_>) -> Self {
        match intent {
            PackageIntent::InitialActivation => Self::InitialActivation,
            PackageIntent::Activation {
                active_revision,
                active_sequence,
            } => Self::Activation {
                active_revision: active_revision.to_owned(),
                active_sequence,
            },
            PackageIntent::Startup {
                active_revision,
                active_sequence,
            } => Self::Startup {
                active_revision: active_revision.to_owned(),
                active_sequence,
            },
        }
    }
}

pub struct PackageLoadContext<'a> {
    pub environment: &'a str,
    pub instance_id: &'a str,
    pub database_id: &'a str,
    /// Environment durably recorded when the database was initialized.
    pub database_initialization_environment: &'a str,
    pub compiler_source_revision: &'a str,
    pub trust_anchor: Option<&'a Path>,
    pub intent: PackageIntent<'a>,
}

/// Deployment bindings available to read-only package inspection.
///
/// The expected revision and sequence are configuration bindings only. This
/// context carries no activation intent or durable database-state claim, so a
/// successful inspection proves package closure, derivation, signature, and
/// configured identity only, never readiness or activation authority.
pub struct PackageInspectionContext<'a> {
    pub environment: &'a str,
    pub instance_id: &'a str,
    pub database_id: &'a str,
    pub database_initialization_environment: &'a str,
    pub compiler_source_revision: &'a str,
    pub trust_anchor: Option<&'a Path>,
    pub expected_package_revision: &'a str,
    pub expected_sequence: u64,
}

/// Closed operator-facing migration facts retained only by a fully rederived
/// tooling inspection. This summary deliberately carries no SQL, paths,
/// identifiers, physical names, signatures, trust material, or activation
/// authority.
#[cfg(feature = "tooling")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationInspectionSummary {
    plan_kind: MigrationInspectionPlanKind,
    has_prior_revision: bool,
    has_prior_baseline: bool,
    change_count: usize,
    change_counts: MigrationInspectionChangeCounts,
    generated_statement_count: usize,
    reviewed_migrations: Vec<ReviewedMigrationInspectionSummary>,
}

#[cfg(feature = "tooling")]
impl MigrationInspectionSummary {
    pub fn plan_kind(&self) -> MigrationInspectionPlanKind {
        self.plan_kind
    }

    pub fn has_prior_revision(&self) -> bool {
        self.has_prior_revision
    }

    pub fn has_prior_baseline(&self) -> bool {
        self.has_prior_baseline
    }

    pub fn change_count(&self) -> usize {
        self.change_count
    }

    pub fn change_counts(&self) -> &MigrationInspectionChangeCounts {
        &self.change_counts
    }

    pub fn generated_statement_count(&self) -> usize {
        self.generated_statement_count
    }

    pub fn reviewed_migrations(&self) -> &[ReviewedMigrationInspectionSummary] {
        &self.reviewed_migrations
    }
}

#[cfg(feature = "tooling")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationInspectionPlanKind {
    Initial,
    CompatibleAdditive,
    Reviewed,
}

#[cfg(feature = "tooling")]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationInspectionChangeCounts {
    compatible_additive: usize,
    data_backfill_required: usize,
    access_or_disclosure_change: usize,
    destructive_or_irreversible: usize,
    unsupported: usize,
}

#[cfg(feature = "tooling")]
impl MigrationInspectionChangeCounts {
    pub fn compatible_additive(&self) -> usize {
        self.compatible_additive
    }

    pub fn data_backfill_required(&self) -> usize {
        self.data_backfill_required
    }

    pub fn access_or_disclosure_change(&self) -> usize {
        self.access_or_disclosure_change
    }

    pub fn destructive_or_irreversible(&self) -> usize {
        self.destructive_or_irreversible
    }

    pub fn unsupported(&self) -> usize {
        self.unsupported
    }

    fn record(&mut self, class: CompiledRegistryChangeClass) {
        match class {
            CompiledRegistryChangeClass::CompatibleAdditive => self.compatible_additive += 1,
            CompiledRegistryChangeClass::DataBackfillRequired => {
                self.data_backfill_required += 1;
            }
            CompiledRegistryChangeClass::AccessOrDisclosureChange => {
                self.access_or_disclosure_change += 1;
            }
            CompiledRegistryChangeClass::DestructiveOrIrreversible => {
                self.destructive_or_irreversible += 1;
            }
            CompiledRegistryChangeClass::Unsupported => self.unsupported += 1,
        }
    }
}

#[cfg(feature = "tooling")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewedMigrationInspectionSummary {
    change_class: CompiledRegistryChangeClass,
    recovery: ReviewedMigrationRecovery,
    lock_timeout_ms: u64,
    statement_timeout_ms: u64,
    transactional_step_count: usize,
    chunked_step_count: usize,
    pre_assertion_count: usize,
    post_assertion_count: usize,
    backup_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    chunked_step_bounds: Option<ReviewedChunkedStepBounds>,
}

#[cfg(feature = "tooling")]
impl ReviewedMigrationInspectionSummary {
    pub fn change_class(&self) -> CompiledRegistryChangeClass {
        self.change_class
    }

    pub fn recovery(&self) -> ReviewedMigrationRecovery {
        self.recovery
    }

    pub fn lock_timeout_ms(&self) -> u64 {
        self.lock_timeout_ms
    }

    pub fn statement_timeout_ms(&self) -> u64 {
        self.statement_timeout_ms
    }

    pub fn transactional_step_count(&self) -> usize {
        self.transactional_step_count
    }

    pub fn chunked_step_count(&self) -> usize {
        self.chunked_step_count
    }

    pub fn pre_assertion_count(&self) -> usize {
        self.pre_assertion_count
    }

    pub fn post_assertion_count(&self) -> usize {
        self.post_assertion_count
    }

    pub fn backup_required(&self) -> bool {
        self.backup_required
    }

    pub fn chunked_step_bounds(&self) -> Option<&ReviewedChunkedStepBounds> {
        self.chunked_step_bounds.as_ref()
    }
}

#[cfg(feature = "tooling")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewedChunkedStepBounds {
    minimum_chunk_size: u32,
    maximum_chunk_size: u32,
    maximum_total_rows: u64,
}

#[cfg(feature = "tooling")]
impl ReviewedChunkedStepBounds {
    pub fn minimum_chunk_size(&self) -> u32 {
        self.minimum_chunk_size
    }

    pub fn maximum_chunk_size(&self) -> u32 {
        self.maximum_chunk_size
    }

    pub fn maximum_total_rows(&self) -> u64 {
        self.maximum_total_rows
    }
}

/// A closed package rederived for read-only comparison.
///
/// Unlike [`VerifiedPackage`], this type cannot authorize startup or apply.
pub struct IntegrityInspectedPackage {
    package_revision: String,
    registry: CompiledRegistry,
    #[cfg(feature = "tooling")]
    migration: MigrationInspectionSummary,
}

impl IntegrityInspectedPackage {
    pub fn package_revision(&self) -> &str {
        &self.package_revision
    }

    pub fn registry(&self) -> &CompiledRegistry {
        &self.registry
    }

    /// Return a value-minimized operator summary. Its presence proves only the
    /// package inspection described by [`PackageInspectionContext`], never
    /// startup readiness, database state, or activation authority.
    #[cfg(feature = "tooling")]
    pub fn migration_summary(&self) -> &MigrationInspectionSummary {
        &self.migration
    }
}

/// A package whose filesystem closure, signatures, bindings, sources, compiler
/// derivation, generated bytes, and migration plan have all been verified.
pub struct VerifiedPackage {
    manifest: PackageManifest,
    registry: CompiledRegistry,
    intent: VerifiedPackageIntent,
    reviewed_migration_plan: Option<ValidatedReviewedMigrationPlan>,
}

impl VerifiedPackage {
    pub fn manifest(&self) -> &PackageManifest {
        &self.manifest
    }

    pub fn registry(&self) -> &CompiledRegistry {
        &self.registry
    }

    /// Resolved reviewed SQL and evidence, present only after tooling-owned AST
    /// validation. Runtime-only package loading carries no authored-SQL parser.
    #[must_use]
    pub fn reviewed_migration_plan(&self) -> Option<&ValidatedReviewedMigrationPlan> {
        self.reviewed_migration_plan.as_ref()
    }

    pub(crate) fn verified_for_initial_activation(&self) -> bool {
        self.intent == VerifiedPackageIntent::InitialActivation
    }

    pub(crate) fn verified_for_activation(
        &self,
        active_revision: &str,
        active_sequence: u64,
    ) -> bool {
        matches!(
            &self.intent,
            VerifiedPackageIntent::Activation {
                active_revision: verified_revision,
                active_sequence: verified_sequence,
            } if verified_revision == active_revision && *verified_sequence == active_sequence
        )
    }
}

/// Value-free failures. Paths, source values, SQL, key material, signatures,
/// and deployment bindings are deliberately absent from both Display and Debug.
#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum PackageError {
    #[error("the package path is unsafe")]
    UnsafePath,
    #[error("the package exceeds its resource bounds")]
    Bounds,
    #[error("the package could not be read")]
    Read,
    #[error("the package is not canonical JSON")]
    CanonicalJson,
    #[error("the package filesystem closure is invalid")]
    Closure,
    #[error("the package integrity check failed")]
    Integrity,
    #[error("the package deployment binding is invalid")]
    Binding,
    #[error("the package signature policy failed")]
    Signature,
    #[error("the package compiler derivation failed")]
    Derivation,
    #[error("the package migration plan is invalid")]
    MigrationPlan,
    #[error("the package permissions are unsafe")]
    Permissions,
}

pub type Result<T> = std::result::Result<T, PackageError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageSourceFile {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageModuleSource {
    pub id: String,
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackageMigrationPlanInput {
    InitialCompiledDdl,
    Successor {
        prior_registry: Box<CompiledRegistry>,
    },
    #[cfg(feature = "tooling")]
    ReviewedSuccessor {
        prior_registry: Box<CompiledRegistry>,
        prior_schema_fingerprint: String,
        migrations: Vec<ReviewedMigrationSource>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageBuildRequest {
    pub environment: String,
    pub instance_id: String,
    pub database_id: String,
    pub sequence: u64,
    pub prior_revision: Option<String>,
    pub compiler_source_revision: String,
    pub schema_fingerprint: String,
    pub signature_policy: SignaturePolicy,
    pub project: PackageSourceFile,
    pub modules: Vec<PackageModuleSource>,
    pub fixture_journeys: PackageSourceFile,
    pub migration_plan: PackageMigrationPlanInput,
}

/// A deterministic package payload with its revision fixed before any caller
/// supplies signatures.
#[derive(Debug)]
pub struct PreparedPackage {
    manifest: PackageManifest,
    registry: CompiledRegistry,
    files: BTreeMap<String, Vec<u8>>,
    signed_bytes: Vec<u8>,
}

impl PreparedPackage {
    pub fn manifest(&self) -> &PackageManifest {
        &self.manifest
    }

    pub fn canonical_signed_bytes(&self) -> &[u8] {
        &self.signed_bytes
    }

    pub fn package_revision(&self) -> &str {
        &self.manifest.package_revision
    }

    /// The exact Production compilation captured by this candidate package.
    pub fn registry(&self) -> &CompiledRegistry {
        &self.registry
    }

    pub fn file_bytes(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }

    pub fn envelope(&self, signatures: Vec<PackageSignature>) -> Result<PackageEnvelope> {
        validate_publication_signatures(&self.manifest, &signatures)?;
        Ok(PackageEnvelope {
            api_version: PACKAGE_API_VERSION.to_owned(),
            signed: self.manifest.clone(),
            signatures,
        })
    }

    /// Publish into a new package directory. The manifest is written last, so
    /// a partial directory is never accepted as a package by `load_package`.
    pub fn publish_to_directory(
        &self,
        destination: &Path,
        signatures: Vec<PackageSignature>,
    ) -> Result<()> {
        reject_symlink_components(destination)?;
        if destination.exists() {
            return Err(PackageError::Closure);
        }
        let parent = destination.parent().ok_or(PackageError::UnsafePath)?;
        reject_symlink_components(parent)?;
        if !parent.is_dir() {
            return Err(PackageError::UnsafePath);
        }
        fs::create_dir(destination).map_err(|_| PackageError::Closure)?;
        if self.manifest.environment != "local" {
            set_safe_directory_permissions(destination)?;
        }
        let publish = (|| {
            for (path, bytes) in &self.files {
                let relative = Path::new(path);
                let full = destination.join(relative);
                if let Some(parent) = full.parent() {
                    fs::create_dir_all(parent).map_err(|_| PackageError::Closure)?;
                    if self.manifest.environment != "local" {
                        set_safe_directory_permissions(parent)?;
                    }
                }
                write_new_file(&full, bytes, self.manifest.environment != "local")?;
            }
            let envelope = self.envelope(signatures)?;
            let manifest_bytes = canonicalize_json(
                &serde_json::to_value(&envelope).map_err(|_| PackageError::CanonicalJson)?,
            )
            .map_err(|_| PackageError::CanonicalJson)?;
            write_new_file(
                &destination.join(MANIFEST_PATH),
                &manifest_bytes,
                self.manifest.environment != "local",
            )
        })();
        if publish.is_err() {
            let _ = remove_created_package_dir(destination);
        }
        publish
    }
}

/// Compare two compiled Registries by stable logical identifiers and return a
/// value-free change set. The embedded migration plan is present only when
/// every change is a compiler-derived compatible additive change.
pub fn compiled_registry_change_set(
    previous: &CompiledRegistry,
    candidate: &CompiledRegistry,
    prior_package_revision: &str,
) -> CompiledRegistryChangeSet {
    let previous_baseline =
        CompiledRegistryMigrationBaseline::from_compiled(prior_package_revision, previous);
    compiled_registry_change_set_from_baseline(
        &previous_baseline,
        candidate,
        prior_package_revision,
    )
}

fn compiled_registry_change_set_from_baseline(
    previous: &CompiledRegistryMigrationBaseline,
    candidate: &CompiledRegistry,
    prior_package_revision: &str,
) -> CompiledRegistryChangeSet {
    let candidate_baseline = CompiledRegistryMigrationBaseline::from_compiled("", candidate);
    let mut changes = Vec::new();
    compare_registry_identity(previous, &candidate_baseline, &mut changes);
    compare_entities(previous, &candidate_baseline, &mut changes);
    compare_routes(previous, &candidate_baseline, &mut changes);
    compare_query_inventory(previous, &candidate_baseline, &mut changes);
    sort_changes(&mut changes);
    changes.dedup();

    let mut change_set = CompiledRegistryChangeSet {
        from_revision: prior_package_revision.to_owned(),
        changes,
        migration_plan: None,
    };
    if change_set
        .changes
        .iter()
        .all(|change| change.class == CompiledRegistryChangeClass::CompatibleAdditive)
    {
        change_set.migration_plan = Some(additive_migration_plan(
            previous,
            candidate,
            prior_package_revision,
            change_set.changes.clone(),
        ));
    }
    change_set
}

/// Convert a value-free change set into an applicable migration plan only when
/// every classified change is compatible additive.
pub fn change_set_to_applicable_migration_plan(
    change_set: &CompiledRegistryChangeSet,
) -> Result<MigrationPlan> {
    if change_set
        .changes
        .iter()
        .all(|change| change.class == CompiledRegistryChangeClass::CompatibleAdditive)
    {
        change_set
            .migration_plan
            .clone()
            .ok_or(PackageError::MigrationPlan)
    } else {
        Err(PackageError::MigrationPlan)
    }
}

fn compare_registry_identity(
    previous: &CompiledRegistryMigrationBaseline,
    candidate: &CompiledRegistryMigrationBaseline,
    changes: &mut Vec<CompiledRegistryChange>,
) {
    if previous.registry_id != candidate.registry_id
        || previous.registry_version != candidate.registry_version
    {
        push_change(
            changes,
            CompiledRegistryChangeClass::Unsupported,
            CompiledRegistryChangeCode::RegistryIdentityChanged,
            target(CompiledRegistryChangeTargetKind::Registry, None, None),
        );
    }
}

fn compare_entities(
    previous: &CompiledRegistryMigrationBaseline,
    candidate: &CompiledRegistryMigrationBaseline,
    changes: &mut Vec<CompiledRegistryChange>,
) {
    for (entity_id, previous_entity) in &previous.entities {
        let Some(candidate_entity) = candidate.entities.get(entity_id) else {
            push_change(
                changes,
                CompiledRegistryChangeClass::DestructiveOrIrreversible,
                CompiledRegistryChangeCode::EntityRemoved,
                target(
                    CompiledRegistryChangeTargetKind::Entity,
                    Some(entity_id.as_str()),
                    None,
                ),
            );
            continue;
        };
        if previous_entity.physical_table != candidate_entity.physical_table {
            push_change(
                changes,
                CompiledRegistryChangeClass::DestructiveOrIrreversible,
                CompiledRegistryChangeCode::EntityPhysicalNameChanged,
                target(
                    CompiledRegistryChangeTargetKind::Entity,
                    Some(entity_id.as_str()),
                    None,
                ),
            );
        }
        if previous_entity.route != candidate_entity.route {
            push_change(
                changes,
                CompiledRegistryChangeClass::AccessOrDisclosureChange,
                CompiledRegistryChangeCode::EntityRouteChanged,
                target(
                    CompiledRegistryChangeTargetKind::Entity,
                    Some(entity_id.as_str()),
                    None,
                ),
            );
        }
        if previous_entity.mutation_mode != candidate_entity.mutation_mode
            || previous_entity.tombstone != candidate_entity.tombstone
        {
            push_change(
                changes,
                CompiledRegistryChangeClass::AccessOrDisclosureChange,
                CompiledRegistryChangeCode::EntityMutationModeChanged,
                target(
                    CompiledRegistryChangeTargetKind::Entity,
                    Some(entity_id.as_str()),
                    None,
                ),
            );
        }
        if previous_entity.classification != candidate_entity.classification {
            push_change(
                changes,
                CompiledRegistryChangeClass::AccessOrDisclosureChange,
                CompiledRegistryChangeCode::EntityClassificationChanged,
                target(
                    CompiledRegistryChangeTargetKind::Entity,
                    Some(entity_id.as_str()),
                    None,
                ),
            );
        }
        if previous_entity.temporal != candidate_entity.temporal {
            push_change(
                changes,
                CompiledRegistryChangeClass::DestructiveOrIrreversible,
                CompiledRegistryChangeCode::EntityTemporalChanged,
                target(
                    CompiledRegistryChangeTargetKind::Entity,
                    Some(entity_id.as_str()),
                    None,
                ),
            );
        }
        compare_fields(entity_id, previous_entity, candidate_entity, changes);
        compare_map(
            entity_id,
            &previous_entity.constraints,
            &candidate_entity.constraints,
            CompiledRegistryChangeTargetKind::Constraint,
            CompiledRegistryChangeCode::ConstraintAdded,
            CompiledRegistryChangeCode::ConstraintRemoved,
            CompiledRegistryChangeCode::ConstraintChanged,
            CompiledRegistryChangeClass::CompatibleAdditive,
            CompiledRegistryChangeClass::DestructiveOrIrreversible,
            CompiledRegistryChangeClass::DestructiveOrIrreversible,
            changes,
        );
        compare_map(
            entity_id,
            &previous_entity.indexes,
            &candidate_entity.indexes,
            CompiledRegistryChangeTargetKind::Index,
            CompiledRegistryChangeCode::IndexAdded,
            CompiledRegistryChangeCode::IndexRemoved,
            CompiledRegistryChangeCode::IndexChanged,
            CompiledRegistryChangeClass::CompatibleAdditive,
            CompiledRegistryChangeClass::DestructiveOrIrreversible,
            CompiledRegistryChangeClass::DestructiveOrIrreversible,
            changes,
        );
        compare_map(
            entity_id,
            &previous_entity.access_profiles,
            &candidate_entity.access_profiles,
            CompiledRegistryChangeTargetKind::AccessProfile,
            CompiledRegistryChangeCode::AccessProfileAdded,
            CompiledRegistryChangeCode::AccessProfileRemoved,
            CompiledRegistryChangeCode::AccessProfileChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            changes,
        );
        compare_map(
            entity_id,
            &previous_entity.events,
            &candidate_entity.events,
            CompiledRegistryChangeTargetKind::Event,
            CompiledRegistryChangeCode::EventAdded,
            CompiledRegistryChangeCode::EventRemoved,
            CompiledRegistryChangeCode::EventChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            changes,
        );
    }

    for entity_id in candidate.entities.keys() {
        if !previous.entities.contains_key(entity_id) {
            push_change(
                changes,
                CompiledRegistryChangeClass::CompatibleAdditive,
                CompiledRegistryChangeCode::EntityAdded,
                target(
                    CompiledRegistryChangeTargetKind::Entity,
                    Some(entity_id.as_str()),
                    None,
                ),
            );
        }
    }
}

fn compare_fields(
    entity_id: &str,
    previous: &CompiledEntity,
    candidate: &CompiledEntity,
    changes: &mut Vec<CompiledRegistryChange>,
) {
    for (field_id, previous_field) in &previous.fields {
        let Some(candidate_field) = candidate.fields.get(field_id) else {
            push_change(
                changes,
                CompiledRegistryChangeClass::DestructiveOrIrreversible,
                CompiledRegistryChangeCode::FieldRemoved,
                target(
                    CompiledRegistryChangeTargetKind::Field,
                    Some(entity_id),
                    Some(field_id.as_str()),
                ),
            );
            continue;
        };
        if previous_field.physical_name != candidate_field.physical_name {
            push_change(
                changes,
                CompiledRegistryChangeClass::DestructiveOrIrreversible,
                CompiledRegistryChangeCode::FieldPhysicalNameChanged,
                target(
                    CompiledRegistryChangeTargetKind::Field,
                    Some(entity_id),
                    Some(field_id.as_str()),
                ),
            );
        }
        if previous_field.field_type != candidate_field.field_type {
            let code = match (&previous_field.field_type, &candidate_field.field_type) {
                (
                    FieldTypeSource::Reference {
                        target: previous_target,
                        ..
                    },
                    FieldTypeSource::Reference {
                        target: candidate_target,
                        ..
                    },
                ) if previous_target != candidate_target => {
                    CompiledRegistryChangeCode::ReferenceTargetChanged
                }
                _ => CompiledRegistryChangeCode::FieldTypeChanged,
            };
            push_change(
                changes,
                CompiledRegistryChangeClass::DestructiveOrIrreversible,
                code,
                target(
                    CompiledRegistryChangeTargetKind::Field,
                    Some(entity_id),
                    Some(field_id.as_str()),
                ),
            );
        }
        if previous_field.required != candidate_field.required {
            let class = if candidate_field.required {
                CompiledRegistryChangeClass::DataBackfillRequired
            } else {
                CompiledRegistryChangeClass::DestructiveOrIrreversible
            };
            push_change(
                changes,
                class,
                CompiledRegistryChangeCode::FieldRequirednessChanged,
                target(
                    CompiledRegistryChangeTargetKind::Field,
                    Some(entity_id),
                    Some(field_id.as_str()),
                ),
            );
        }
        if previous_field.classification != candidate_field.classification {
            push_change(
                changes,
                CompiledRegistryChangeClass::AccessOrDisclosureChange,
                CompiledRegistryChangeCode::FieldClassificationChanged,
                target(
                    CompiledRegistryChangeTargetKind::Field,
                    Some(entity_id),
                    Some(field_id.as_str()),
                ),
            );
        }
        if previous_field.valid_time_role != candidate_field.valid_time_role {
            push_change(
                changes,
                CompiledRegistryChangeClass::AccessOrDisclosureChange,
                CompiledRegistryChangeCode::FieldTemporalRoleChanged,
                target(
                    CompiledRegistryChangeTargetKind::Field,
                    Some(entity_id),
                    Some(field_id.as_str()),
                ),
            );
        }
    }

    for (field_id, field) in &candidate.fields {
        if previous.fields.contains_key(field_id) {
            continue;
        }
        let class = if field.required {
            CompiledRegistryChangeClass::DataBackfillRequired
        } else {
            CompiledRegistryChangeClass::CompatibleAdditive
        };
        let code = if field.required {
            CompiledRegistryChangeCode::FieldAddedRequired
        } else {
            CompiledRegistryChangeCode::FieldAddedOptional
        };
        push_change(
            changes,
            class,
            code,
            target(
                CompiledRegistryChangeTargetKind::Field,
                Some(entity_id),
                Some(field_id.as_str()),
            ),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn compare_map<T: Eq>(
    entity_id: &str,
    previous: &BTreeMap<String, T>,
    candidate: &BTreeMap<String, T>,
    target_kind: CompiledRegistryChangeTargetKind,
    added_code: CompiledRegistryChangeCode,
    removed_code: CompiledRegistryChangeCode,
    changed_code: CompiledRegistryChangeCode,
    added_class: CompiledRegistryChangeClass,
    removed_class: CompiledRegistryChangeClass,
    changed_class: CompiledRegistryChangeClass,
    changes: &mut Vec<CompiledRegistryChange>,
) {
    for (id, previous_value) in previous {
        match candidate.get(id) {
            Some(candidate_value) if previous_value == candidate_value => {}
            Some(_) => push_change(
                changes,
                changed_class,
                changed_code,
                target(target_kind, Some(entity_id), Some(id.as_str())),
            ),
            None => push_change(
                changes,
                removed_class,
                removed_code,
                target(target_kind, Some(entity_id), Some(id.as_str())),
            ),
        }
    }
    for id in candidate.keys() {
        if !previous.contains_key(id) {
            push_change(
                changes,
                added_class,
                added_code,
                target(target_kind, Some(entity_id), Some(id.as_str())),
            );
        }
    }
}

fn compare_routes(
    previous: &CompiledRegistryMigrationBaseline,
    candidate: &CompiledRegistryMigrationBaseline,
    changes: &mut Vec<CompiledRegistryChange>,
) {
    let previous_routes = previous
        .routes
        .routes
        .iter()
        .map(|route| (route.id.as_str(), route))
        .collect::<BTreeMap<_, _>>();
    let candidate_routes = candidate
        .routes
        .routes
        .iter()
        .map(|route| (route.id.as_str(), route))
        .collect::<BTreeMap<_, _>>();
    for (route_id, previous_route) in &previous_routes {
        match candidate_routes.get(route_id) {
            Some(candidate_route) if previous_route == candidate_route => {}
            Some(candidate_route) => {
                if previous.entities.contains_key(&previous_route.entity_id)
                    && candidate.entities.contains_key(&candidate_route.entity_id)
                {
                    push_change(
                        changes,
                        CompiledRegistryChangeClass::AccessOrDisclosureChange,
                        CompiledRegistryChangeCode::RouteChanged,
                        target(
                            CompiledRegistryChangeTargetKind::Route,
                            Some(candidate_route.entity_id.as_str()),
                            Some(route_id),
                        ),
                    );
                }
            }
            None => {
                if previous.entities.contains_key(&previous_route.entity_id)
                    && candidate.entities.contains_key(&previous_route.entity_id)
                {
                    push_change(
                        changes,
                        CompiledRegistryChangeClass::AccessOrDisclosureChange,
                        CompiledRegistryChangeCode::RouteRemoved,
                        target(
                            CompiledRegistryChangeTargetKind::Route,
                            Some(previous_route.entity_id.as_str()),
                            Some(route_id),
                        ),
                    );
                }
            }
        }
    }
    for (route_id, candidate_route) in &candidate_routes {
        if !previous_routes.contains_key(route_id)
            && previous.entities.contains_key(&candidate_route.entity_id)
        {
            push_change(
                changes,
                CompiledRegistryChangeClass::AccessOrDisclosureChange,
                CompiledRegistryChangeCode::RouteAdded,
                target(
                    CompiledRegistryChangeTargetKind::Route,
                    Some(candidate_route.entity_id.as_str()),
                    Some(route_id),
                ),
            );
        }
    }
}

fn compare_query_inventory(
    previous: &CompiledRegistryMigrationBaseline,
    candidate: &CompiledRegistryMigrationBaseline,
    changes: &mut Vec<CompiledRegistryChange>,
) {
    let previous_queries = previous
        .queries
        .operations
        .iter()
        .map(|query| (query.id.as_str(), query))
        .collect::<BTreeMap<_, _>>();
    let candidate_queries = candidate
        .queries
        .operations
        .iter()
        .map(|query| (query.id.as_str(), query))
        .collect::<BTreeMap<_, _>>();
    for (query_id, previous_query) in &previous_queries {
        match candidate_queries.get(query_id) {
            Some(candidate_query) if previous_query == candidate_query => {}
            Some(candidate_query)
                if previous.entities.contains_key(&previous_query.entity_id)
                    && candidate.entities.contains_key(&candidate_query.entity_id) =>
            {
                push_change(
                    changes,
                    CompiledRegistryChangeClass::AccessOrDisclosureChange,
                    CompiledRegistryChangeCode::QueryInventoryChanged,
                    target(
                        CompiledRegistryChangeTargetKind::QueryInventory,
                        Some(candidate_query.entity_id.as_str()),
                        Some(query_id),
                    ),
                );
            }
            None if previous.entities.contains_key(&previous_query.entity_id)
                && candidate.entities.contains_key(&previous_query.entity_id) =>
            {
                push_change(
                    changes,
                    CompiledRegistryChangeClass::AccessOrDisclosureChange,
                    CompiledRegistryChangeCode::QueryInventoryChanged,
                    target(
                        CompiledRegistryChangeTargetKind::QueryInventory,
                        Some(previous_query.entity_id.as_str()),
                        Some(query_id),
                    ),
                );
            }
            _ => {}
        }
    }
    for (query_id, candidate_query) in &candidate_queries {
        if !previous_queries.contains_key(query_id)
            && previous.entities.contains_key(&candidate_query.entity_id)
        {
            push_change(
                changes,
                CompiledRegistryChangeClass::AccessOrDisclosureChange,
                CompiledRegistryChangeCode::QueryInventoryChanged,
                target(
                    CompiledRegistryChangeTargetKind::QueryInventory,
                    Some(candidate_query.entity_id.as_str()),
                    Some(query_id),
                ),
            );
        }
    }
}

fn additive_migration_plan(
    previous: &CompiledRegistryMigrationBaseline,
    candidate: &CompiledRegistry,
    prior_package_revision: &str,
    changes: Vec<CompiledRegistryChange>,
) -> MigrationPlan {
    let mut new_statement_ids = BTreeSet::<String>::new();
    let mut added_columns = BTreeMap::<String, Vec<DdlStatement>>::new();

    for (entity_id, candidate_entity) in candidate.entities() {
        if !previous.entities.contains_key(entity_id) {
            let prefix = format!("entity.{entity_id}.");
            new_statement_ids.extend(
                candidate
                    .ddl()
                    .statements
                    .iter()
                    .filter(|statement| statement.id.starts_with(&prefix))
                    .map(|statement| statement.id.clone()),
            );
            continue;
        }
        let previous_entity = &previous.entities[entity_id];
        for (field_id, field) in &candidate_entity.fields {
            if !previous_entity.fields.contains_key(field_id) && !field.required {
                added_columns
                    .entry(entity_id.clone())
                    .or_default()
                    .push(add_column_statement(candidate_entity, field));
                if matches!(field.field_type, FieldTypeSource::Reference { .. }) {
                    new_statement_ids
                        .insert(format!("entity.{entity_id}.field.{field_id}.reference"));
                }
            }
        }
        for constraint_id in candidate_entity.constraints.keys() {
            if !previous_entity.constraints.contains_key(constraint_id) {
                new_statement_ids.insert(format!("entity.{entity_id}.constraint.{constraint_id}"));
            }
        }
        for index_id in candidate_entity.indexes.keys() {
            if !previous_entity.indexes.contains_key(index_id) {
                new_statement_ids.insert(format!("entity.{entity_id}.index.{index_id}"));
            }
        }
    }

    let mut statements = Vec::new();
    for statement in &candidate.ddl().statements {
        if let Some(entity_id) = table_statement_entity_id(&statement.id) {
            if let Some(columns) = added_columns.get(entity_id) {
                statements.extend(columns.iter().cloned());
            }
        }
        if new_statement_ids.contains(statement.id.as_str()) {
            statements.push(statement.clone());
        }
    }
    MigrationPlan {
        from_revision: Some(prior_package_revision.to_owned()),
        prior_baseline: Some(previous.clone()),
        changes,
        statements,
        reviewed_descriptors: Vec::new(),
        prior_schema_fingerprint: None,
    }
}

fn initial_migration_plan(compiled: &CompiledRegistry) -> MigrationPlan {
    MigrationPlan {
        from_revision: None,
        prior_baseline: None,
        changes: Vec::new(),
        statements: compiled.ddl().statements.clone(),
        reviewed_descriptors: Vec::new(),
        prior_schema_fingerprint: None,
    }
}

fn reviewed_successor_migration_plan(
    baseline: &CompiledRegistryMigrationBaseline,
    candidate: &CompiledRegistry,
    change_set: &CompiledRegistryChangeSet,
    descriptor_paths: Vec<String>,
    prior_schema_fingerprint: String,
) -> Result<MigrationPlan> {
    if descriptor_paths.is_empty()
        || change_set
            .changes
            .iter()
            .any(|change| change.class == CompiledRegistryChangeClass::Unsupported)
    {
        return Err(PackageError::MigrationPlan);
    }
    let additive_changes = change_set
        .changes
        .iter()
        .filter(|change| change.class == CompiledRegistryChangeClass::CompatibleAdditive)
        .cloned()
        .collect::<Vec<_>>();
    let additive = additive_migration_plan(
        baseline,
        candidate,
        &change_set.from_revision,
        additive_changes,
    );
    Ok(MigrationPlan {
        from_revision: Some(change_set.from_revision.clone()),
        prior_baseline: Some(baseline.clone()),
        changes: change_set.changes.clone(),
        statements: additive.statements,
        reviewed_descriptors: descriptor_paths,
        prior_schema_fingerprint: Some(prior_schema_fingerprint),
    })
}

fn table_statement_entity_id(statement_id: &str) -> Option<&str> {
    statement_id
        .strip_prefix("entity.")
        .and_then(|suffix| suffix.strip_suffix(".table"))
}

fn push_change(
    changes: &mut Vec<CompiledRegistryChange>,
    class: CompiledRegistryChangeClass,
    code: CompiledRegistryChangeCode,
    target: CompiledRegistryChangeTarget,
) {
    changes.push(CompiledRegistryChange {
        class,
        code,
        target,
    });
}

fn sort_changes(changes: &mut [CompiledRegistryChange]) {
    changes.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then_with(|| left.code.cmp(&right.code))
            .then_with(|| left.class.cmp(&right.class))
    });
}

fn target(
    kind: CompiledRegistryChangeTargetKind,
    entity_id: Option<&str>,
    member_id: Option<&str>,
) -> CompiledRegistryChangeTarget {
    CompiledRegistryChangeTarget {
        kind,
        entity_id: entity_id.map(str::to_owned),
        member_id: member_id.map(str::to_owned),
    }
}

pub fn prepare_package(request: PackageBuildRequest) -> Result<PreparedPackage> {
    validate_build_identity(&request)?;
    validate_relative(&request.project.path)?;
    if request.fixture_journeys.path != FIXTURE_JOURNEYS_PATH
        || request.fixture_journeys.bytes.is_empty()
        || request.fixture_journeys.bytes.len() as u64 > MAX_PACKAGE_SOURCE_FILE_BYTES
    {
        return Err(PackageError::Closure);
    }
    let project =
        parse_project_yaml(&request.project.bytes).map_err(|_| PackageError::Derivation)?;
    let modules = request
        .modules
        .iter()
        .map(|source| {
            validate_relative(&source.path)?;
            if source.id.is_empty() {
                return Err(PackageError::Derivation);
            }
            let module = parse_module_yaml(&source.bytes).map_err(|_| PackageError::Derivation)?;
            if module.id != source.id {
                return Err(PackageError::Derivation);
            }
            Ok(module)
        })
        .collect::<Result<Vec<_>>>()?;
    let compiled = compile_project(&project, &modules, CompileProfile::Production)
        .map_err(|_| PackageError::Derivation)?;
    validate_build_bindings(&request, &project, &compiled)?;

    let (migration_plan, reviewed_files): (MigrationPlan, BTreeMap<String, Vec<u8>>) = match request
        .migration_plan
    {
        PackageMigrationPlanInput::InitialCompiledDdl => {
            if request.sequence != 1 || request.prior_revision.is_some() {
                return Err(PackageError::MigrationPlan);
            }
            (initial_migration_plan(&compiled), BTreeMap::new())
        }
        PackageMigrationPlanInput::Successor { prior_registry } => {
            if request.sequence == 1 || request.prior_revision.is_none() {
                return Err(PackageError::MigrationPlan);
            }
            let prior_revision = request
                .prior_revision
                .as_deref()
                .ok_or(PackageError::MigrationPlan)?;
            let change_set =
                compiled_registry_change_set(&prior_registry, &compiled, prior_revision);
            (
                change_set_to_applicable_migration_plan(&change_set)?,
                BTreeMap::new(),
            )
        }
        #[cfg(feature = "tooling")]
        PackageMigrationPlanInput::ReviewedSuccessor {
            prior_registry,
            prior_schema_fingerprint,
            migrations,
        } => {
            if request.sequence == 1
                || request.prior_revision.is_none()
                || !valid_digest(&prior_schema_fingerprint)
            {
                return Err(PackageError::MigrationPlan);
            }
            let prior_revision = request
                .prior_revision
                .as_deref()
                .ok_or(PackageError::MigrationPlan)?;
            let baseline =
                CompiledRegistryMigrationBaseline::from_compiled(prior_revision, &prior_registry);
            let change_set =
                compiled_registry_change_set(&prior_registry, &compiled, prior_revision);
            let reviewed = prepare_reviewed_migration_plan(
                &migrations,
                &ReviewedPlanBindings {
                    prior_revision,
                    prior_schema_fingerprint: &prior_schema_fingerprint,
                    final_schema_fingerprint: &request.schema_fingerprint,
                    database_id: &request.database_id,
                    changes: &change_set.changes,
                    prior_entities: prior_registry.entities(),
                    candidate_entities: compiled.entities(),
                    prior_physical_names: prior_registry.physical_names(),
                    candidate_physical_names: compiled.physical_names(),
                },
            )
            .map_err(|_| PackageError::MigrationPlan)?;
            let PreparedReviewedMigrationPlan {
                descriptor_paths,
                files,
            } = reviewed;
            (
                reviewed_successor_migration_plan(
                    &baseline,
                    &compiled,
                    &change_set,
                    descriptor_paths,
                    prior_schema_fingerprint,
                )?,
                files,
            )
        }
    };

    let mut files = BTreeMap::new();
    files.insert(request.project.path.clone(), request.project.bytes.clone());
    for module in &request.modules {
        if files
            .insert(module.path.clone(), module.bytes.clone())
            .is_some()
        {
            return Err(PackageError::Closure);
        }
    }
    if files
        .insert(
            request.fixture_journeys.path.clone(),
            request.fixture_journeys.bytes.clone(),
        )
        .is_some()
    {
        return Err(PackageError::Closure);
    }
    for (path, bytes) in reviewed_files {
        validate_relative(&path)?;
        if files.insert(path, bytes).is_some() {
            return Err(PackageError::Closure);
        }
    }
    add_compiled_artifacts(&compiled, &migration_plan, &mut files)?;

    let mut entries = Vec::new();
    entries.push(file_entry(
        &request.project.path,
        PackageFileRole::SourceProject,
        &request.project.bytes,
    )?);
    for module in &request.modules {
        entries.push(file_entry(
            &module.path,
            PackageFileRole::SourceModule,
            &module.bytes,
        )?);
    }
    entries.push(file_entry(
        &request.fixture_journeys.path,
        PackageFileRole::FixtureJourneys,
        &request.fixture_journeys.bytes,
    )?);
    for (path, bytes) in &files {
        if path == &request.project.path
            || path == &request.fixture_journeys.path
            || request.modules.iter().any(|module| module.path == *path)
        {
            continue;
        }
        entries.push(file_entry(path, package_role_for_path(path)?, bytes)?);
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    ensure_unique_file_entries(&entries)?;

    let mut manifest = PackageManifest {
        package_id: compiled.registry_id().to_owned(),
        package_revision: String::new(),
        environment: request.environment,
        instance_id: request.instance_id,
        database_id: request.database_id,
        sequence: request.sequence,
        prior_revision: request.prior_revision,
        compiler: CompilerIdentity {
            id: COMPILER_ID.to_owned(),
            source_revision: request.compiler_source_revision,
            profile: PackageCompileProfile::Production,
        },
        schema_fingerprint: request.schema_fingerprint,
        signature_policy: request.signature_policy,
        sources: CapturedSources {
            project: request.project.path,
            modules: request
                .modules
                .into_iter()
                .map(|module| CapturedModule {
                    id: module.id,
                    path: module.path,
                })
                .collect(),
            fixture_journeys: request.fixture_journeys.path,
        },
        files: entries,
        migration_plan,
    };
    validate_migration_plan(&manifest, &compiled)?;
    validate_source_inventory(&manifest)?;
    manifest.package_revision = derive_package_revision(&manifest)?;
    let signed_bytes = canonical_signed_bytes(&manifest)?;
    Ok(PreparedPackage {
        manifest,
        registry: compiled,
        files,
        signed_bytes,
    })
}

/// Return the exact canonical bytes signed by every package signer.
pub fn canonical_signed_bytes(manifest: &PackageManifest) -> Result<Vec<u8>> {
    canonicalize_json(&serde_json::to_value(manifest).map_err(|_| PackageError::CanonicalJson)?)
        .map_err(|_| PackageError::CanonicalJson)
}

fn add_compiled_artifacts(
    compiled: &CompiledRegistry,
    migration_plan: &MigrationPlan,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    insert_generated(
        files,
        "effective-model.json",
        compiled
            .artifacts()
            .get("compiled/effective-model.json")
            .ok_or(PackageError::Derivation)?
            .bytes
            .clone(),
    )?;
    insert_json_file(
        files,
        "inventories/physical-names.json",
        compiled.physical_names(),
    )?;
    insert_json_file(files, "inventories/routes.json", compiled.routes())?;
    insert_json_file(files, "inventories/access.json", compiled.access())?;
    insert_json_file(files, "inventories/queries.json", compiled.queries())?;
    insert_json_file(
        files,
        "inventories/events.json",
        compiled.event_deliveries(),
    )?;
    insert_generated(
        files,
        "metadata/registry.json",
        compiled
            .artifacts()
            .get(REGISTRY_METADATA_ARTIFACT_PATH)
            .ok_or(PackageError::Derivation)?
            .bytes
            .clone(),
    )?;
    insert_generated(
        files,
        "database/ddl.sql",
        compiled.ddl().script().into_bytes(),
    )?;
    insert_json_file(files, "database/migration-plan.json", migration_plan)?;
    insert_generated(
        files,
        "openapi/openapi.json",
        compiled
            .artifacts()
            .get("generated/openapi.json")
            .ok_or(PackageError::Derivation)?
            .bytes
            .clone(),
    )?;
    insert_generated(
        files,
        "manifest/registry-manifest.json",
        compiled
            .artifacts()
            .get("generated/manifest/registry-manifest.json")
            .ok_or(PackageError::Derivation)?
            .bytes
            .clone(),
    )?;
    for (path, artifact) in compiled.artifacts().entries() {
        let Some(schema_name) = path.strip_prefix("generated/schemas/") else {
            continue;
        };
        insert_generated(
            files,
            &format!("schemas/{schema_name}"),
            artifact.bytes.clone(),
        )?;
    }
    Ok(())
}

fn expected_artifact_bytes(
    manifest: &PackageManifest,
    compiled: &CompiledRegistry,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut files = BTreeMap::new();
    add_compiled_artifacts(compiled, &manifest.migration_plan, &mut files)?;
    Ok(files)
}

fn insert_json_file(
    files: &mut BTreeMap<String, Vec<u8>>,
    path: &str,
    value: &impl Serialize,
) -> Result<()> {
    let bytes =
        canonicalize_json(&serde_json::to_value(value).map_err(|_| PackageError::CanonicalJson)?)
            .map_err(|_| PackageError::CanonicalJson)?;
    insert_generated(files, path, bytes)
}

fn insert_generated(
    files: &mut BTreeMap<String, Vec<u8>>,
    path: &str,
    bytes: Vec<u8>,
) -> Result<()> {
    validate_relative(path)?;
    if files.insert(path.to_owned(), bytes).is_some() {
        return Err(PackageError::Closure);
    }
    Ok(())
}

fn package_role_for_path(path: &str) -> Result<PackageFileRole> {
    if let Some(kind) = reviewed_artifact_kind(path) {
        return Ok(match kind {
            ReviewedArtifactKind::Descriptor => PackageFileRole::ReviewedMigrationDescriptor,
            ReviewedArtifactKind::StepSql => PackageFileRole::ReviewedMigrationStepSql,
            ReviewedArtifactKind::AssertionSql => PackageFileRole::ReviewedMigrationAssertionSql,
            ReviewedArtifactKind::RehearsalReceipt => PackageFileRole::MigrationRehearsalReceipt,
            ReviewedArtifactKind::BackupBinding => PackageFileRole::ExternalBackupBinding,
            ReviewedArtifactKind::Fixture => PackageFileRole::MigrationRehearsalFixture,
        });
    }
    Ok(match path {
        FIXTURE_JOURNEYS_PATH => PackageFileRole::FixtureJourneys,
        "effective-model.json" => PackageFileRole::GovernedModel,
        "inventories/physical-names.json" => PackageFileRole::PhysicalNameInventory,
        "inventories/routes.json" => PackageFileRole::RouteInventory,
        "inventories/access.json" => PackageFileRole::AccessInventory,
        "inventories/queries.json" => PackageFileRole::QueryInventory,
        "inventories/events.json" => PackageFileRole::EventInventory,
        "metadata/registry.json" => PackageFileRole::CallerSafeMetadata,
        "database/ddl.sql" => PackageFileRole::GeneratedDdl,
        "database/migration-plan.json" => PackageFileRole::MigrationPlan,
        "openapi/openapi.json" => PackageFileRole::GeneratedOpenapi,
        path if path.starts_with("schemas/") && path.ends_with(".schema.json") => {
            PackageFileRole::EntityJsonSchema
        }
        "manifest/registry-manifest.json" => PackageFileRole::LossyManifestProjection,
        _ => return Err(PackageError::Closure),
    })
}

fn reviewed_package_role(role: PackageFileRole) -> bool {
    matches!(
        role,
        PackageFileRole::ReviewedMigrationDescriptor
            | PackageFileRole::ReviewedMigrationStepSql
            | PackageFileRole::ReviewedMigrationAssertionSql
            | PackageFileRole::MigrationRehearsalReceipt
            | PackageFileRole::ExternalBackupBinding
            | PackageFileRole::MigrationRehearsalFixture
    )
}

fn file_entry(path: &str, role: PackageFileRole, bytes: &[u8]) -> Result<PackageFile> {
    validate_relative(path)?;
    Ok(PackageFile {
        path: path.to_owned(),
        role,
        size: bytes.len() as u64,
        sha256: digest(bytes),
    })
}

fn ensure_unique_file_entries(entries: &[PackageFile]) -> Result<()> {
    let mut previous = None;
    let mut paths = BTreeSet::new();
    for entry in entries {
        if previous.is_some_and(|path: &str| path >= entry.path.as_str())
            || !paths.insert(entry.path.as_str())
        {
            return Err(PackageError::Closure);
        }
        previous = Some(entry.path.as_str());
    }
    Ok(())
}

fn validate_build_identity(request: &PackageBuildRequest) -> Result<()> {
    if !valid_build_id(&request.environment)
        || !valid_build_id(&request.instance_id)
        || !valid_build_id(&request.database_id)
        || request.sequence == 0
        || request.compiler_source_revision.is_empty()
        || !valid_digest(&request.schema_fingerprint)
    {
        return Err(PackageError::Binding);
    }
    validate_signature_policy(&request.environment, &request.signature_policy)
}

fn valid_build_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn validate_signature_policy(environment: &str, policy: &SignaturePolicy) -> Result<()> {
    let ids = exact_sorted_unique(policy.key_ids.iter().map(String::as_str))?;
    if environment == "local" {
        if policy.threshold != 0 || !ids.is_empty() {
            return Err(PackageError::Signature);
        }
    } else if policy.threshold == 0 || usize::from(policy.threshold) > ids.len() {
        return Err(PackageError::Signature);
    }
    Ok(())
}

fn validate_build_bindings(
    request: &PackageBuildRequest,
    project: &RegistryProject,
    compiled: &CompiledRegistry,
) -> Result<()> {
    let identity = project.package.as_ref().ok_or(PackageError::Derivation)?;
    if project.registry.id != compiled.registry_id()
        || identity.environment != request.environment
        || identity.instance_id != request.instance_id
        || identity.sequence != request.sequence
        || identity.source_revision != request.compiler_source_revision
    {
        return Err(PackageError::Derivation);
    }
    let mut prior_id = None;
    for module in &request.modules {
        if prior_id.is_some_and(|id: &str| id >= module.id.as_str()) {
            return Err(PackageError::Derivation);
        }
        prior_id = Some(module.id.as_str());
    }
    Ok(())
}

fn validate_publication_signatures(
    manifest: &PackageManifest,
    signatures: &[PackageSignature],
) -> Result<()> {
    validate_signature_policy(&manifest.environment, &manifest.signature_policy)?;
    if manifest.environment == "local" {
        if !signatures.is_empty() {
            return Err(PackageError::Signature);
        }
        return Ok(());
    }
    let policy_ids = manifest
        .signature_policy
        .key_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut previous = None;
    for signature in signatures {
        if previous.is_some_and(|id: &str| id >= signature.key_id.as_str())
            || !seen.insert(signature.key_id.as_str())
            || !policy_ids.contains(signature.key_id.as_str())
        {
            return Err(PackageError::Signature);
        }
        previous = Some(signature.key_id.as_str());
        decode_hex(&signature.signature_hex)?;
    }
    if seen.len() < usize::from(manifest.signature_policy.threshold) {
        return Err(PackageError::Signature);
    }
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8], production: bool) -> Result<()> {
    reject_symlink_components(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| PackageError::Closure)?;
    file.write_all(bytes).map_err(|_| PackageError::Read)?;
    file.sync_all().map_err(|_| PackageError::Read)?;
    if production {
        set_safe_file_permissions(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_safe_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .map_err(|_| PackageError::Permissions)
}

#[cfg(not(unix))]
fn set_safe_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_safe_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o644))
        .map_err(|_| PackageError::Permissions)
}

#[cfg(not(unix))]
fn set_safe_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn remove_created_package_dir(path: &Path) -> Result<()> {
    reject_symlink_components(path)?;
    if path.is_dir() {
        fs::remove_dir_all(path).map_err(|_| PackageError::Read)?;
    }
    Ok(())
}

/// Compute the package revision over the complete signed manifest with only
/// its self-referential revision member cleared.
pub fn derive_package_revision(manifest: &PackageManifest) -> Result<String> {
    let mut unsigned = manifest.clone();
    unsigned.package_revision.clear();
    Ok(digest(&canonical_signed_bytes(&unsigned)?))
}

/// Load one package from the caller-selected local root. This function performs
/// no network resolution and must complete before a database mutation or
/// listener construction is attempted.
pub fn load_package(root: &Path, context: &PackageLoadContext<'_>) -> Result<VerifiedPackage> {
    validate_root(root)?;
    let production = context.database_initialization_environment != "local";
    if production {
        ensure_safe_permissions(root)?;
    }

    let manifest_path = root.join(MANIFEST_PATH);
    let manifest_bytes = read_bounded_regular(&manifest_path, MAX_MANIFEST_BYTES, production)?;
    let envelope: PackageEnvelope = parse_canonical(&manifest_bytes)?;
    if envelope.api_version != PACKAGE_API_VERSION
        || envelope.signed.files.is_empty()
        || envelope.signed.files.len() > MAX_PACKAGE_FILES
    {
        return Err(PackageError::Integrity);
    }

    let signed_bytes = canonical_signed_bytes(&envelope.signed)?;
    if derive_package_revision(&envelope.signed)? != envelope.signed.package_revision {
        return Err(PackageError::Integrity);
    }
    validate_bindings(&envelope.signed, context)?;
    let inspection_context = PackageInspectionContext {
        environment: context.environment,
        instance_id: context.instance_id,
        database_id: context.database_id,
        database_initialization_environment: context.database_initialization_environment,
        compiler_source_revision: context.compiler_source_revision,
        trust_anchor: context.trust_anchor,
        expected_package_revision: &envelope.signed.package_revision,
        expected_sequence: envelope.signed.sequence,
    };
    verify_signatures(&envelope, &inspection_context, production, &signed_bytes)?;
    let loaded = load_closure(
        root,
        &envelope.signed.files,
        manifest_bytes.len(),
        production,
    )?;
    let (registry, reviewed_migration_plan) = rederive(&envelope.signed, &loaded)?;

    Ok(VerifiedPackage {
        manifest: envelope.signed,
        registry,
        intent: VerifiedPackageIntent::from_intent(context.intent),
        reviewed_migration_plan,
    })
}

/// Rederive a closed package for integrity-only comparison.
///
/// Signatures are checked for structural consistency but are not treated as a
/// trust decision because this mode has no configured trust anchor. Safe
/// permissions are still mandatory. The returned type carries no startup or
/// activation authority.
pub fn inspect_package_integrity(root: &Path) -> Result<IntegrityInspectedPackage> {
    inspect_package(root, None)
}

/// Rederive a closed package and verify its configured deployment bindings and
/// signature policy without making a startup or activation claim.
pub fn inspect_package_with_context(
    root: &Path,
    context: &PackageInspectionContext<'_>,
) -> Result<IntegrityInspectedPackage> {
    inspect_package(root, Some(context))
}

fn inspect_package(
    root: &Path,
    context: Option<&PackageInspectionContext<'_>>,
) -> Result<IntegrityInspectedPackage> {
    validate_root(root)?;
    ensure_safe_permissions(root)?;

    let manifest_path = root.join(MANIFEST_PATH);
    let manifest_bytes = read_bounded_regular(&manifest_path, MAX_MANIFEST_BYTES, true)?;
    let envelope: PackageEnvelope = parse_canonical(&manifest_bytes)?;
    if envelope.api_version != PACKAGE_API_VERSION
        || envelope.signed.files.is_empty()
        || envelope.signed.files.len() > MAX_PACKAGE_FILES
    {
        return Err(PackageError::Integrity);
    }

    let signed_bytes = canonical_signed_bytes(&envelope.signed)?;
    if derive_package_revision(&envelope.signed)? != envelope.signed.package_revision {
        return Err(PackageError::Integrity);
    }
    validate_intrinsic_bindings(&envelope.signed)?;
    match context {
        Some(context) => {
            validate_inspection_bindings(&envelope.signed, context)?;
            let production = context.database_initialization_environment != "local";
            verify_signatures(&envelope, context, production, &signed_bytes)?;
        }
        None => validate_publication_signatures(&envelope.signed, &envelope.signatures)?,
    }
    let loaded = load_closure(root, &envelope.signed.files, manifest_bytes.len(), true)?;
    let (registry, _reviewed_migration_plan) = rederive(&envelope.signed, &loaded)?;
    #[cfg(feature = "tooling")]
    let migration =
        migration_inspection_summary(&envelope.signed, _reviewed_migration_plan.as_ref())?;

    Ok(IntegrityInspectedPackage {
        package_revision: envelope.signed.package_revision,
        registry,
        #[cfg(feature = "tooling")]
        migration,
    })
}

#[cfg(feature = "tooling")]
fn migration_inspection_summary(
    manifest: &PackageManifest,
    reviewed_plan: Option<&ValidatedReviewedMigrationPlan>,
) -> Result<MigrationInspectionSummary> {
    let plan = &manifest.migration_plan;
    let plan_kind = if !plan.reviewed_descriptors.is_empty() {
        MigrationInspectionPlanKind::Reviewed
    } else if plan.from_revision.is_some() {
        MigrationInspectionPlanKind::CompatibleAdditive
    } else {
        MigrationInspectionPlanKind::Initial
    };
    let mut change_counts = MigrationInspectionChangeCounts::default();
    for change in &plan.changes {
        change_counts.record(change.class);
    }
    let reviewed_migrations = match plan_kind {
        MigrationInspectionPlanKind::Reviewed => {
            let reviewed_plan = reviewed_plan.ok_or(PackageError::MigrationPlan)?;
            if reviewed_plan.migrations().len() != plan.reviewed_descriptors.len() {
                return Err(PackageError::MigrationPlan);
            }
            reviewed_plan
                .migrations()
                .iter()
                .map(reviewed_migration_inspection_summary)
                .collect()
        }
        MigrationInspectionPlanKind::Initial | MigrationInspectionPlanKind::CompatibleAdditive => {
            if reviewed_plan.is_some() {
                return Err(PackageError::MigrationPlan);
            }
            Vec::new()
        }
    };
    Ok(MigrationInspectionSummary {
        plan_kind,
        has_prior_revision: manifest.prior_revision.is_some(),
        has_prior_baseline: plan.prior_baseline.is_some(),
        change_count: plan.changes.len(),
        change_counts,
        generated_statement_count: plan.statements.len(),
        reviewed_migrations,
    })
}

#[cfg(feature = "tooling")]
fn reviewed_migration_inspection_summary(
    migration: &crate::migration_plan::ValidatedReviewedMigration,
) -> ReviewedMigrationInspectionSummary {
    let mut transactional_step_count = 0;
    let mut chunked_step_count = 0;
    let mut minimum_chunk_size = None;
    let mut maximum_chunk_size = 0;
    let mut maximum_total_rows = 0;
    for step in &migration.steps {
        match &step.descriptor {
            ReviewedMigrationStepDescriptor::TransactionalSql { .. } => {
                transactional_step_count += 1;
            }
            ReviewedMigrationStepDescriptor::ChunkedBackfill {
                chunk_size,
                max_total_rows,
                ..
            } => {
                chunked_step_count += 1;
                minimum_chunk_size = Some(
                    minimum_chunk_size.map_or(*chunk_size, |minimum: u32| minimum.min(*chunk_size)),
                );
                maximum_chunk_size = maximum_chunk_size.max(*chunk_size);
                maximum_total_rows = maximum_total_rows.max(*max_total_rows);
            }
        }
    }
    ReviewedMigrationInspectionSummary {
        change_class: migration.descriptor.change_class,
        recovery: migration.descriptor.recovery,
        lock_timeout_ms: migration.descriptor.lock_timeout_ms,
        statement_timeout_ms: migration.descriptor.statement_timeout_ms,
        transactional_step_count,
        chunked_step_count,
        pre_assertion_count: migration.pre_assertions.len(),
        post_assertion_count: migration.post_assertions.len(),
        backup_required: migration.descriptor.change_class
            == CompiledRegistryChangeClass::DestructiveOrIrreversible,
        chunked_step_bounds: minimum_chunk_size.map(|minimum_chunk_size| {
            ReviewedChunkedStepBounds {
                minimum_chunk_size,
                maximum_chunk_size,
                maximum_total_rows,
            }
        }),
    }
}

fn validate_root(root: &Path) -> Result<()> {
    if root.as_os_str().is_empty() {
        return Err(PackageError::UnsafePath);
    }
    reject_symlink_components(root)?;
    let metadata = fs::symlink_metadata(root).map_err(|_| PackageError::Read)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PackageError::UnsafePath);
    }
    Ok(())
}

fn validate_bindings(manifest: &PackageManifest, context: &PackageLoadContext<'_>) -> Result<()> {
    validate_intrinsic_bindings(manifest)?;
    if manifest.environment != context.environment
        || manifest.environment != context.database_initialization_environment
        || manifest.instance_id != context.instance_id
        || manifest.database_id != context.database_id
        || manifest.compiler.source_revision != context.compiler_source_revision
    {
        return Err(PackageError::Binding);
    }
    match context.intent {
        PackageIntent::InitialActivation => {
            if manifest.sequence != 1
                || manifest.prior_revision.is_some()
                || manifest.migration_plan.from_revision.is_some()
            {
                return Err(PackageError::Binding);
            }
        }
        PackageIntent::Activation {
            active_revision,
            active_sequence,
        } => {
            if manifest.sequence <= active_sequence
                || manifest.prior_revision.as_deref() != Some(active_revision)
                || manifest.migration_plan.from_revision.as_deref() != Some(active_revision)
            {
                return Err(PackageError::Binding);
            }
        }
        PackageIntent::Startup {
            active_revision,
            active_sequence,
        } => {
            if manifest.package_revision != active_revision || manifest.sequence != active_sequence
            {
                return Err(PackageError::Binding);
            }
            if manifest.sequence == 1 && manifest.prior_revision.is_some() {
                return Err(PackageError::Binding);
            }
            if manifest.sequence > 1 && manifest.prior_revision.is_none() {
                return Err(PackageError::Binding);
            }
        }
    }
    Ok(())
}

fn validate_intrinsic_bindings(manifest: &PackageManifest) -> Result<()> {
    if manifest.package_id.is_empty()
        || manifest.package_revision.is_empty()
        || manifest.environment.is_empty()
        || manifest.instance_id.is_empty()
        || manifest.database_id.is_empty()
        || manifest.sequence == 0
        || manifest.compiler.id != COMPILER_ID
        || manifest.compiler.source_revision.is_empty()
        || manifest.compiler.profile != PackageCompileProfile::Production
        || !valid_digest(&manifest.schema_fingerprint)
        || manifest.migration_plan.from_revision != manifest.prior_revision
        || (manifest.sequence == 1 && manifest.prior_revision.is_some())
        || (manifest.sequence > 1 && manifest.prior_revision.is_none())
    {
        return Err(PackageError::Binding);
    }
    Ok(())
}

fn validate_inspection_bindings(
    manifest: &PackageManifest,
    context: &PackageInspectionContext<'_>,
) -> Result<()> {
    if manifest.environment != context.environment
        || manifest.environment != context.database_initialization_environment
        || manifest.instance_id != context.instance_id
        || manifest.database_id != context.database_id
        || manifest.compiler.source_revision != context.compiler_source_revision
        || manifest.package_revision != context.expected_package_revision
        || manifest.sequence != context.expected_sequence
    {
        return Err(PackageError::Binding);
    }
    Ok(())
}

fn verify_signatures(
    envelope: &PackageEnvelope,
    context: &PackageInspectionContext<'_>,
    production: bool,
    signed_bytes: &[u8],
) -> Result<()> {
    if !production {
        if context.trust_anchor.is_some()
            || envelope.signed.signature_policy.threshold != 0
            || !envelope.signed.signature_policy.key_ids.is_empty()
            || !envelope.signatures.is_empty()
        {
            return Err(PackageError::Signature);
        }
        return Ok(());
    }

    let anchor_path = context.trust_anchor.ok_or(PackageError::Signature)?;
    reject_symlink_components(anchor_path)?;
    let anchor_bytes = read_bounded_regular(anchor_path, MAX_MANIFEST_BYTES, true)?;
    let anchor: PackageTrustAnchor = parse_canonical(&anchor_bytes)?;
    if anchor.api_version != TRUST_ANCHOR_API_VERSION
        || anchor.environment != context.database_initialization_environment
        || anchor.instance_id != context.instance_id
        || anchor.database_id != context.database_id
        || anchor.threshold == 0
        || usize::from(anchor.threshold) > anchor.keys.len()
    {
        return Err(PackageError::Signature);
    }

    let policy = &envelope.signed.signature_policy;
    let anchor_ids = exact_sorted_unique(anchor.keys.iter().map(|key| key.key_id.as_str()))?;
    let policy_ids = exact_sorted_unique(policy.key_ids.iter().map(String::as_str))?;
    if policy.threshold != anchor.threshold || policy_ids != anchor_ids {
        return Err(PackageError::Signature);
    }

    let mut trusted = BTreeMap::new();
    for key in &anchor.keys {
        let jwk = parse_public_jwk(&key.jwk)?;
        if jwk.kid.as_deref() != Some(key.key_id.as_str()) {
            return Err(PackageError::Signature);
        }
        trusted.insert(key.key_id.as_str(), jwk);
    }
    let mut verified = BTreeSet::new();
    let mut prior_signature_id = None;
    for signature in &envelope.signatures {
        if prior_signature_id.is_some_and(|prior: &str| prior >= signature.key_id.as_str())
            || !verified.insert(signature.key_id.as_str())
        {
            return Err(PackageError::Signature);
        }
        prior_signature_id = Some(signature.key_id.as_str());
        let jwk = trusted
            .get(signature.key_id.as_str())
            .ok_or(PackageError::Signature)?;
        let bytes = decode_hex(&signature.signature_hex)?;
        verify(signed_bytes, &bytes, jwk).map_err(|_| PackageError::Signature)?;
    }
    if verified.len() < usize::from(anchor.threshold) {
        return Err(PackageError::Signature);
    }
    Ok(())
}

fn parse_public_jwk(value: &Value) -> Result<PublicJwk> {
    let members = value.as_object().ok_or(PackageError::Signature)?;
    let allowed = BTreeSet::from(["alg", "crv", "e", "kid", "kty", "n", "x", "y"]);
    if members.keys().any(|key| !allowed.contains(key.as_str())) {
        return Err(PackageError::Signature);
    }
    let bytes = canonicalize_json(value).map_err(|_| PackageError::Signature)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| PackageError::Signature)?;
    PublicJwk::parse(text).map_err(|_| PackageError::Signature)
}

fn load_closure(
    root: &Path,
    entries: &[PackageFile],
    manifest_size: usize,
    production: bool,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut listed = BTreeSet::new();
    let mut loaded = BTreeMap::new();
    let mut total = u64::try_from(manifest_size).map_err(|_| PackageError::Bounds)?;
    let mut previous = None;
    for entry in entries {
        validate_relative(&entry.path)?;
        if previous.is_some_and(|path: &str| path >= entry.path.as_str())
            || !listed.insert(entry.path.as_str())
            || entry.size > MAX_FILE_BYTES
            || !valid_digest(&entry.sha256)
        {
            return Err(PackageError::Closure);
        }
        previous = Some(entry.path.as_str());
        let relative = Path::new(&entry.path);
        reject_relative_symlinks(root, relative)?;
        let path = root.join(relative);
        let bytes = read_bounded_regular(&path, MAX_FILE_BYTES, production)?;
        if bytes.len() as u64 != entry.size || digest(&bytes) != entry.sha256 {
            return Err(PackageError::Integrity);
        }
        total = total.checked_add(entry.size).ok_or(PackageError::Bounds)?;
        if total > MAX_PACKAGE_BYTES {
            return Err(PackageError::Bounds);
        }
        loaded.insert(entry.path.clone(), bytes);
    }
    let actual = enumerate_files(root, production)?;
    let mut expected = listed
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    expected.insert(MANIFEST_PATH.to_owned());
    if actual != expected {
        return Err(PackageError::Closure);
    }
    Ok(loaded)
}

fn rederive(
    manifest: &PackageManifest,
    loaded: &BTreeMap<String, Vec<u8>>,
) -> Result<(CompiledRegistry, Option<ValidatedReviewedMigrationPlan>)> {
    validate_source_inventory(manifest)?;
    let fixture_journeys = loaded
        .get(&manifest.sources.fixture_journeys)
        .ok_or(PackageError::Derivation)?;
    if fixture_journeys.is_empty() || fixture_journeys.len() as u64 > MAX_PACKAGE_SOURCE_FILE_BYTES
    {
        return Err(PackageError::Derivation);
    }
    let project_bytes = loaded
        .get(&manifest.sources.project)
        .ok_or(PackageError::Derivation)?;
    let project = parse_project_yaml(project_bytes).map_err(|_| PackageError::Derivation)?;
    let modules = manifest
        .sources
        .modules
        .iter()
        .map(|source| {
            loaded
                .get(&source.path)
                .ok_or(PackageError::Derivation)
                .and_then(|bytes| parse_module_yaml(bytes).map_err(|_| PackageError::Derivation))
        })
        .collect::<Result<Vec<RegistryModule>>>()?;
    validate_captured_bindings(manifest, &project, &modules)?;
    let compiled = compile_project(&project, &modules, CompileProfile::Production)
        .map_err(|_| PackageError::Derivation)?;
    if compiled.registry_id() != manifest.package_id {
        return Err(PackageError::Derivation);
    }

    let expected_artifacts = expected_artifact_bytes(manifest, &compiled)?;
    let packaged_artifacts = manifest
        .files
        .iter()
        .filter(|entry| {
            !matches!(
                entry.role,
                PackageFileRole::SourceProject
                    | PackageFileRole::SourceModule
                    | PackageFileRole::FixtureJourneys
            ) && !reviewed_package_role(entry.role)
        })
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    if expected_artifacts
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != packaged_artifacts
    {
        return Err(PackageError::Derivation);
    }
    for (path, bytes) in expected_artifacts {
        if loaded.get(&path).map(Vec::as_slice) != Some(bytes.as_slice()) {
            return Err(PackageError::Derivation);
        }
    }
    validate_migration_plan(manifest, &compiled)?;
    let reviewed_migration_plan = rederive_reviewed_migration_plan(manifest, loaded, &compiled)?;
    Ok((compiled, reviewed_migration_plan))
}

fn reviewed_artifact_files(
    manifest: &PackageManifest,
    loaded: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    manifest
        .files
        .iter()
        .filter(|entry| reviewed_package_role(entry.role))
        .map(|entry| {
            loaded
                .get(&entry.path)
                .cloned()
                .map(|bytes| (entry.path.clone(), bytes))
                .ok_or(PackageError::Closure)
        })
        .collect()
}

#[cfg(feature = "tooling")]
fn rederive_reviewed_migration_plan(
    manifest: &PackageManifest,
    loaded: &BTreeMap<String, Vec<u8>>,
    compiled: &CompiledRegistry,
) -> Result<Option<ValidatedReviewedMigrationPlan>> {
    let files = reviewed_artifact_files(manifest, loaded)?;
    if manifest.migration_plan.reviewed_descriptors.is_empty() {
        return if files.is_empty() {
            Ok(None)
        } else {
            Err(PackageError::MigrationPlan)
        };
    }
    let baseline = manifest
        .migration_plan
        .prior_baseline
        .as_ref()
        .ok_or(PackageError::MigrationPlan)?;
    let prior_revision = manifest
        .prior_revision
        .as_deref()
        .ok_or(PackageError::MigrationPlan)?;
    let prior_schema_fingerprint = manifest
        .migration_plan
        .prior_schema_fingerprint
        .as_deref()
        .ok_or(PackageError::MigrationPlan)?;
    validate_reviewed_migration_plan(
        &manifest.migration_plan.reviewed_descriptors,
        &files,
        &ReviewedPlanBindings {
            prior_revision,
            prior_schema_fingerprint,
            final_schema_fingerprint: &manifest.schema_fingerprint,
            database_id: &manifest.database_id,
            changes: &manifest.migration_plan.changes,
            prior_entities: &baseline.entities,
            candidate_entities: compiled.entities(),
            prior_physical_names: &baseline.physical_names,
            candidate_physical_names: compiled.physical_names(),
        },
    )
    .map(Some)
    .map_err(|_| PackageError::MigrationPlan)
}

#[cfg(not(feature = "tooling"))]
fn rederive_reviewed_migration_plan(
    manifest: &PackageManifest,
    loaded: &BTreeMap<String, Vec<u8>>,
    _compiled: &CompiledRegistry,
) -> Result<Option<ValidatedReviewedMigrationPlan>> {
    let files = reviewed_artifact_files(manifest, loaded)?;
    if manifest.migration_plan.reviewed_descriptors.is_empty() && files.is_empty() {
        Ok(None)
    } else if manifest.migration_plan.reviewed_descriptors.is_empty() != files.is_empty() {
        Err(PackageError::MigrationPlan)
    } else {
        // The runtime graph intentionally carries no PostgreSQL parser. The
        // tooling path that constructs and applies reviewed packages performs
        // the AST and evidence validation and exposes the resolved packet.
        Ok(None)
    }
}

fn validate_source_inventory(manifest: &PackageManifest) -> Result<()> {
    validate_relative(&manifest.sources.project)?;
    let project_entries = manifest
        .files
        .iter()
        .filter(|entry| entry.role == PackageFileRole::SourceProject)
        .collect::<Vec<_>>();
    if project_entries.len() != 1 || project_entries[0].path != manifest.sources.project {
        return Err(PackageError::Derivation);
    }
    if manifest.sources.fixture_journeys != FIXTURE_JOURNEYS_PATH {
        return Err(PackageError::Derivation);
    }
    let fixture_journey_entries = manifest
        .files
        .iter()
        .filter(|entry| entry.role == PackageFileRole::FixtureJourneys)
        .collect::<Vec<_>>();
    if fixture_journey_entries.len() != 1
        || fixture_journey_entries[0].path != manifest.sources.fixture_journeys
    {
        return Err(PackageError::Derivation);
    }
    let mut prior_id = None;
    let mut module_paths = BTreeSet::new();
    for module in &manifest.sources.modules {
        validate_relative(&module.path)?;
        if module.id.is_empty()
            || prior_id.is_some_and(|id: &str| id >= module.id.as_str())
            || !module_paths.insert(module.path.as_str())
        {
            return Err(PackageError::Derivation);
        }
        prior_id = Some(module.id.as_str());
    }
    let declared_paths = manifest
        .sources
        .modules
        .iter()
        .map(|module| module.path.as_str())
        .collect::<BTreeSet<_>>();
    let file_paths = manifest
        .files
        .iter()
        .filter(|entry| entry.role == PackageFileRole::SourceModule)
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    if declared_paths != file_paths {
        return Err(PackageError::Derivation);
    }
    for entry in &manifest.files {
        if matches!(
            entry.role,
            PackageFileRole::SourceProject
                | PackageFileRole::SourceModule
                | PackageFileRole::FixtureJourneys
        ) {
            continue;
        }
        if package_role_for_path(&entry.path)? != entry.role {
            return Err(PackageError::Derivation);
        }
    }
    Ok(())
}

fn validate_captured_bindings(
    manifest: &PackageManifest,
    project: &RegistryProject,
    modules: &[RegistryModule],
) -> Result<()> {
    let identity = project.package.as_ref().ok_or(PackageError::Derivation)?;
    if project.registry.id != manifest.package_id
        || identity.environment != manifest.environment
        || identity.instance_id != manifest.instance_id
        || identity.sequence != manifest.sequence
        || identity.source_revision != manifest.compiler.source_revision
    {
        return Err(PackageError::Derivation);
    }
    let source_ids = manifest
        .sources
        .modules
        .iter()
        .map(|module| module.id.as_str())
        .collect::<Vec<_>>();
    let module_ids = modules
        .iter()
        .map(|module| module.id.as_str())
        .collect::<Vec<_>>();
    let lock_ids = project
        .modules
        .iter()
        .map(|module| module.id.as_str())
        .collect::<BTreeSet<_>>();
    if source_ids != module_ids || source_ids.into_iter().collect::<BTreeSet<_>>() != lock_ids {
        return Err(PackageError::Derivation);
    }
    Ok(())
}

fn validate_migration_plan(manifest: &PackageManifest, compiled: &CompiledRegistry) -> Result<()> {
    if manifest.migration_plan.statements.len() > MAX_MIGRATION_STATEMENTS {
        return Err(PackageError::Bounds);
    }
    if manifest.migration_plan.changes.len() > MAX_MIGRATION_STATEMENTS {
        return Err(PackageError::Bounds);
    }
    if manifest.migration_plan.reviewed_descriptors.len() > MAX_MIGRATION_STATEMENTS {
        return Err(PackageError::Bounds);
    }
    let mut prior_descriptor = None;
    for descriptor in &manifest.migration_plan.reviewed_descriptors {
        validate_relative(descriptor)?;
        if prior_descriptor.is_some_and(|prior: &str| prior >= descriptor.as_str()) {
            return Err(PackageError::MigrationPlan);
        }
        prior_descriptor = Some(descriptor.as_str());
    }
    if let Some(baseline) = &manifest.migration_plan.prior_baseline {
        validate_migration_baseline(baseline)?;
    }
    let expected = expected_migration_plan(manifest, compiled)?;
    if manifest.migration_plan != expected {
        return Err(PackageError::MigrationPlan);
    }
    Ok(())
}

fn expected_migration_plan(
    manifest: &PackageManifest,
    compiled: &CompiledRegistry,
) -> Result<MigrationPlan> {
    match (
        manifest.prior_revision.as_deref(),
        manifest.migration_plan.from_revision.as_deref(),
    ) {
        (None, None) => {
            if manifest.migration_plan.prior_baseline.is_some()
                || !manifest.migration_plan.changes.is_empty()
                || !manifest.migration_plan.reviewed_descriptors.is_empty()
                || manifest.migration_plan.prior_schema_fingerprint.is_some()
            {
                return Err(PackageError::MigrationPlan);
            }
            Ok(initial_migration_plan(compiled))
        }
        (Some(prior_revision), Some(from_revision)) if prior_revision == from_revision => {
            let baseline = manifest
                .migration_plan
                .prior_baseline
                .as_ref()
                .ok_or(PackageError::MigrationPlan)?;
            if baseline.package_revision != prior_revision {
                return Err(PackageError::MigrationPlan);
            }
            let change_set =
                compiled_registry_change_set_from_baseline(baseline, compiled, prior_revision);
            if manifest.migration_plan.reviewed_descriptors.is_empty() {
                if manifest.migration_plan.prior_schema_fingerprint.is_some() {
                    return Err(PackageError::MigrationPlan);
                }
                change_set_to_applicable_migration_plan(&change_set)
            } else {
                let prior_schema_fingerprint = manifest
                    .migration_plan
                    .prior_schema_fingerprint
                    .clone()
                    .filter(|fingerprint| valid_digest(fingerprint))
                    .ok_or(PackageError::MigrationPlan)?;
                reviewed_successor_migration_plan(
                    baseline,
                    compiled,
                    &change_set,
                    manifest.migration_plan.reviewed_descriptors.clone(),
                    prior_schema_fingerprint,
                )
            }
        }
        _ => Err(PackageError::MigrationPlan),
    }
}

fn validate_migration_baseline(baseline: &CompiledRegistryMigrationBaseline) -> Result<()> {
    let bytes = canonicalize_json(
        &serde_json::to_value(baseline).map_err(|_| PackageError::MigrationPlan)?,
    )
    .map_err(|_| PackageError::MigrationPlan)?;
    if bytes.len() > MAX_MIGRATION_BASELINE_BYTES {
        return Err(PackageError::Bounds);
    }
    Ok(())
}

fn exact_sorted_unique<'a>(values: impl Iterator<Item = &'a str>) -> Result<Vec<&'a str>> {
    let mut result = Vec::new();
    for value in values {
        if value.is_empty() || result.last().is_some_and(|prior| *prior >= value) {
            return Err(PackageError::Signature);
        }
        result.push(value);
    }
    Ok(result)
}

fn parse_canonical<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    let value = parse_json_strict(bytes).map_err(|_| PackageError::CanonicalJson)?;
    let canonical = canonicalize_json(&value).map_err(|_| PackageError::CanonicalJson)?;
    if canonical != bytes {
        return Err(PackageError::CanonicalJson);
    }
    serde_json::from_value(value).map_err(|_| PackageError::CanonicalJson)
}

fn validate_relative(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.contains('\\')
        || value.ends_with('/')
    {
        return Err(PackageError::UnsafePath);
    }
    let path = Path::new(value);
    let components = path.components().collect::<Vec<_>>();
    let canonical = components
        .iter()
        .filter_map(|component| match component {
            Component::Normal(component) => component.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/");
    if path.is_absolute()
        || components.len() > MAX_PATH_COMPONENTS
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path.to_str() != Some(value)
        || canonical != value
    {
        return Err(PackageError::UnsafePath);
    }
    Ok(())
}

fn reject_relative_symlinks(root: &Path, relative: &Path) -> Result<()> {
    let mut checked = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(PackageError::UnsafePath);
        };
        checked.push(component);
        let metadata = fs::symlink_metadata(&checked).map_err(|_| PackageError::Read)?;
        if metadata.file_type().is_symlink() {
            return Err(PackageError::UnsafePath);
        }
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut checked = PathBuf::new();
    for component in path.components() {
        checked.push(component.as_os_str());
        if matches!(component, Component::RootDir | Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&checked) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(PackageError::UnsafePath);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(PackageError::Read),
        }
    }
    Ok(())
}

fn enumerate_files(root: &Path, production: bool) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    let mut pending = vec![(root.to_path_buf(), String::new())];
    let mut entry_count = 0_usize;
    while let Some((directory, prefix)) = pending.pop() {
        for entry in fs::read_dir(directory).map_err(|_| PackageError::Read)? {
            let entry = entry.map_err(|_| PackageError::Read)?;
            entry_count = entry_count.checked_add(1).ok_or(PackageError::Bounds)?;
            if entry_count > MAX_PACKAGE_FILES * 2 {
                return Err(PackageError::Bounds);
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| PackageError::UnsafePath)?;
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            validate_relative(&relative)?;
            let file_type = entry.file_type().map_err(|_| PackageError::Read)?;
            if production {
                ensure_safe_permissions(&entry.path())?;
            }
            if file_type.is_symlink() {
                return Err(PackageError::UnsafePath);
            }
            if file_type.is_dir() {
                pending.push((entry.path(), relative));
            } else if file_type.is_file() {
                result.insert(relative);
            } else {
                return Err(PackageError::Closure);
            }
            if result.len() > MAX_PACKAGE_FILES + 1 {
                return Err(PackageError::Bounds);
            }
        }
    }
    Ok(result)
}

fn read_bounded_regular(path: &Path, bound: u64, production: bool) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path).map_err(|_| PackageError::Read)?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(PackageError::Closure);
    }
    if before.len() > bound {
        return Err(PackageError::Bounds);
    }
    if production {
        ensure_safe_permissions(path)?;
    }
    let file = fs::File::open(path).map_err(|_| PackageError::Read)?;
    let opened = file.metadata().map_err(|_| PackageError::Read)?;
    let after = fs::symlink_metadata(path).map_err(|_| PackageError::Read)?;
    if after.file_type().is_symlink() || !same_file(&before, &opened) || !same_file(&opened, &after)
    {
        return Err(PackageError::UnsafePath);
    }
    let capacity = usize::try_from(opened.len()).map_err(|_| PackageError::Bounds)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(bound.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| PackageError::Read)?;
    if bytes.len() as u64 > bound {
        return Err(PackageError::Bounds);
    }
    if bytes.len() as u64 != opened.len() {
        return Err(PackageError::Integrity);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.created().ok() == right.created().ok()
}

#[cfg(unix)]
fn ensure_safe_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::symlink_metadata(path).map_err(|_| PackageError::Read)?;
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(PackageError::Permissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_safe_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

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

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if value.is_empty()
        || value.len() > 32 * 1024
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PackageError::Signature);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| PackageError::Signature)?;
            u8::from_str_radix(text, 16).map_err(|_| PackageError::Signature)
        })
        .collect()
}
