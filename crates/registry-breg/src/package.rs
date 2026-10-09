// SPDX-License-Identifier: Apache-2.0
//! Closed Base Registry Engine package verification boundary.

#[cfg(test)]
#[path = "package/tests/immediate_actions.rs"]
mod immediate_action_tests;
#[cfg(test)]
#[path = "package/tests/retired_anonymous.rs"]
mod retired_anonymous_tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use registry_platform_config::package::{
    plan_package, write_sum_file, PackageLimits as SharedPackageLimits,
    VerifiedPackage as SharedVerifiedPackage, REVISION_FILE, SUM_FILE,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use thiserror::Error;

use crate::artifacts::{restore_effective_model_planner_origins, REGISTRY_METADATA_ARTIFACT_PATH};
use crate::compiler::{compile_project_with_assets, CompileProfile};
use crate::contract::{
    parse_module_yaml, parse_project_yaml, FieldTypeSource, ModuleAssetSource, RegistryModule,
    RegistryProject,
};
use crate::derived_sql::MAX_DERIVED_SQL_BYTES;
use crate::generated_ddl::{
    add_blind_index_column_statement, add_column_statement, drop_spatial_bbox_function_statement,
    drop_spatial_candidate_view_statement, generate_ddl_with_actions, quote_identifier,
    replace_length_check_statement, replace_vocabulary_check_statement,
    set_column_not_null_statement, spatial_bbox_function_statement, spatial_projection_fields,
    spatial_projection_statements, DdlInventory, DdlPolicy, DdlPolicyRole, DdlStatement,
    DdlStatementKind, DdlTable,
};
use crate::history_schema::{
    serialize_descriptor, HistoryEntityDescriptor, HistoryLifecycleDescriptor,
    HistoryLifecycleSource, HistorySchemaDescriptor, HISTORY_SCHEMA_ENCODING_VERSION,
};
#[cfg(feature = "tooling")]
use crate::migration_plan::{
    prepare_reviewed_migration_plan, validate_reviewed_migration_plan,
    PreparedReviewedMigrationPlan, ReviewedMigrationError, ReviewedMigrationRecovery,
    ReviewedMigrationSource, ReviewedMigrationStepDescriptor, ReviewedPlanBindings,
};
use crate::migration_plan::{
    reviewed_artifact_kind, ReviewedArtifactKind, ValidatedReviewedMigrationPlan,
};
use crate::model::CompiledStatisticalDataset;
use crate::model::{
    CompiledAccessInventory, CompiledActionInventory, CompiledEntity, CompiledQueryInventory,
    CompiledQueryOperation, CompiledQueryTemporalValueKind, CompiledRecipients,
    CompiledRouteInventory, REFERENCE_INDEX_PREFIX,
};
use crate::physical_names::PhysicalNameInventory;
use crate::CompiledRegistry;

pub const PACKAGE_API_VERSION: &str = "id.registrystack.org/formats/breg/package/v2";
pub const PACKAGE_KIND: &str = "BRegPackage";
/// The apiVersion packages carried before the format took its
/// `id.registrystack.org` name. A deployed package that carries it is still
/// read as a predecessor, so the package that replaces it can be built,
/// planned, and applied; every other read refuses it and names the current
/// apiVersion.
pub const RETIRED_PACKAGE_API_VERSION: &str = "registry.registrystack.org/package/v2";
pub const COMPILER_ID: &str = "breg";
pub const FIXTURE_JOURNEYS_PATH: &str = "tests/journeys.yaml";
pub const MAX_PACKAGE_SOURCE_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_RHAI_PLANNER_SOURCE_BYTES: u64 =
    crate::change_request::MAX_CHANGE_REQUEST_PLANNER_SOURCE_BYTES as u64;
pub const MAX_RHAI_PLANNER_PATH_BYTES: usize = 256;

const MANIFEST_PATH: &str = "package.json";
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = MAX_PACKAGE_SOURCE_FILE_BYTES;
pub const MAX_PACKAGE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_PACKAGE_FILES: usize = 1_024;
const MAX_PATH_BYTES: usize = 512;
const MAX_PATH_COMPONENTS: usize = 16;
const MAX_MIGRATION_STATEMENTS: usize = 1_024;
const MAX_MIGRATION_BASELINE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageEnvelope {
    pub api_version: String,
    pub kind: String,
    pub manifest: PackageManifest,
}

/// The envelope a package carrying [`RETIRED_PACKAGE_API_VERSION`] was
/// written with: it predates `kind`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RetiredPackageEnvelope {
    #[serde(rename = "apiVersion")]
    _api_version: String,
    manifest: PackageManifest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageManifest {
    pub package_id: String,
    pub compiler: CompilerIdentity,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub engine_features: BTreeSet<PackageEngineFeature>,
    pub schema_fingerprint: String,
    pub sources: CapturedSources,
    pub files: Vec<PackageFile>,
    pub migration_plan: MigrationPlan,
}

/// Engine-owned catalog capabilities installed by the package's compiler.
/// The set is hash-covered package identity and defaults empty only for
/// predecessor packages produced before capability declarations existed.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageEngineFeature {
    StatisticalReleaseStore,
    /// Spent idempotency keys are found by the verified caller, the key scope,
    /// and the key, and held responses carry a receipt horizon.
    CallerScopedIdempotency,
}

fn current_engine_features() -> BTreeSet<PackageEngineFeature> {
    BTreeSet::from([
        PackageEngineFeature::StatisticalReleaseStore,
        PackageEngineFeature::CallerScopedIdempotency,
    ])
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
pub struct CapturedSources {
    pub project: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub project_assets: Vec<String>,
    pub modules: Vec<CapturedModule>,
    pub fixture_journeys: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CapturedModule {
    pub id: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assets: Vec<String>,
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
    SourceProjectPlannerScript,
    SourceProjectEvidenceContract,
    SourceModule,
    SourceModuleAsset,
    SourceModulePlannerScript,
    FixtureJourneys,
    GovernedModel,
    PhysicalNameInventory,
    RouteInventory,
    AccessInventory,
    QueryInventory,
    EventInventory,
    ActionInventory,
    CallerSafeMetadata,
    GeneratedDdl,
    MigrationPlan,
    GeneratedOpenapi,
    EntityJsonSchema,
    ActionJsonSchema,
    LossyManifestProjection,
    DcatCatalogProjection,
    ReviewedMigrationDescriptor,
    ReviewedMigrationStepSql,
    ReviewedMigrationAssertionSql,
    MigrationRehearsalReceipt,
    MigrationRehearsalFixture,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MigrationPlan {
    /// The digest of the package this plan migrates from, absent for the root
    /// package of a chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_package_digest: Option<String>,
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
    pub package_digest: String,
    pub registry_id: String,
    pub registry_version: String,
    pub registry_revision: String,
    pub entities: BTreeMap<String, CompiledEntity>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub statistical_datasets: BTreeMap<String, CompiledStatisticalDataset>,
    pub physical_names: PhysicalNameInventory,
    pub routes: CompiledRouteInventory,
    pub access: CompiledAccessInventory,
    pub queries: CompiledQueryInventory,
    #[serde(default, skip_serializing_if = "CompiledActionInventory::is_empty")]
    pub actions: CompiledActionInventory,
    #[serde(default, skip_serializing_if = "CompiledRecipients::is_empty")]
    pub recipients: CompiledRecipients,
}

impl CompiledRegistryMigrationBaseline {
    pub fn from_compiled(package_digest: &str, compiled: &CompiledRegistry) -> Self {
        Self {
            package_digest: package_digest.to_owned(),
            registry_id: compiled.registry_id().to_owned(),
            registry_version: compiled.version().to_owned(),
            registry_revision: compiled.revision().to_owned(),
            entities: compiled.entities().clone(),
            statistical_datasets: compiled.statistical_datasets().clone(),
            physical_names: compiled.physical_names().clone(),
            routes: compiled.routes().clone(),
            access: compiled.access().clone(),
            queries: compiled.queries().clone(),
            actions: compiled.actions().clone(),
            recipients: compiled.recipients().clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledRegistryChangeSet {
    pub from_package_digest: String,
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
    RegistryVersionChanged,
    EntityAdded,
    EntityRemoved,
    EntityPhysicalNameChanged,
    EntityRouteChanged,
    EntityMutationModeChanged,
    EntityClassificationChanged,
    EntityAccessRequirementsChanged,
    EntityAccessLogChanged,
    EntityGeoJsonChanged,
    EntityTemporalChanged,
    ChangeRequestContractChanged,
    FieldAddedOptional,
    FieldAddedRequired,
    FieldRemoved,
    FieldTypeChanged,
    FieldVocabularyCodesAdded,
    FieldLengthWidened,
    FieldPhysicalNameChanged,
    FieldRequirednessChanged,
    FieldPatternAdded,
    FieldPatternChanged,
    FieldPatternRemoved,
    FieldEncryptionChanged,
    FieldLookupChanged,
    FieldClassificationChanged,
    FieldTemporalRoleChanged,
    DerivedRelationAdded,
    DerivedRelationRemoved,
    DerivedRelationChanged,
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
    ActionAdded,
    ActionRemoved,
    ActionChanged,
    ActionVocabularyCodesAdded,
    ActionTargetFieldsWidened,
    ConsentRecordChanged,
    RecipientOrganizationAdded,
    RecipientOrganizationRemoved,
    RecipientOrganizationChanged,
    RecipientGroupAdded,
    RecipientGroupRemoved,
    RecipientGroupChanged,
    StatisticalDatasetAdded,
    StatisticalDatasetRemoved,
    StatisticalDatasetChanged,
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
    ChangeRequest,
    Field,
    DerivedRelation,
    Constraint,
    Index,
    AccessProfile,
    Route,
    QueryInventory,
    Event,
    Action,
    Recipient,
    StatisticalDataset,
}

/// What package loading needs from the deployment. A package carries no
/// environment, so the only deployment input is how strictly the package
/// directory's permissions are checked.
pub struct PackageLoadContext<'a> {
    /// Environment durably recorded when the database was initialized.
    pub database_initialization_environment: &'a str,
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
    has_predecessor: bool,
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

    pub fn has_predecessor(&self) -> bool {
        self.has_predecessor
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
    package_digest: String,
    schema_fingerprint: String,
    registry: CompiledRegistry,
    #[cfg(feature = "tooling")]
    migration: MigrationInspectionSummary,
}

impl IntegrityInspectedPackage {
    pub fn package_digest(&self) -> &str {
        &self.package_digest
    }

    /// The fingerprint bound by the inspected package, not a measurement of a live database.
    pub fn schema_fingerprint(&self) -> &str {
        &self.schema_fingerprint
    }

    pub fn registry(&self) -> &CompiledRegistry {
        &self.registry
    }

    /// Return a value-minimized operator summary. Its presence proves only
    /// package closure and derivation, never startup readiness, database
    /// state, or activation authority.
    #[cfg(feature = "tooling")]
    pub fn migration_summary(&self) -> &MigrationInspectionSummary {
        &self.migration
    }
}

/// A predecessor package verified for read-only successor planning. It proves
/// the package bytes against their sum file, but it does not rederive
/// historical generated artifacts with the current compiler and cannot
/// authorize startup or package execution.
pub struct VerifiedPredecessorPackage {
    manifest: PackageManifest,
    package_digest: String,
    migration_baseline: CompiledRegistryMigrationBaseline,
    history_schema_descriptor: HistorySchemaDescriptor,
    statistical_release_store_present: bool,
    retired_api_version: bool,
}

impl VerifiedPredecessorPackage {
    pub fn package_id(&self) -> &str {
        &self.manifest.package_id
    }

    pub fn package_digest(&self) -> &str {
        &self.package_digest
    }

    pub fn schema_fingerprint(&self) -> &str {
        &self.manifest.schema_fingerprint
    }

    pub fn migration_baseline(&self) -> &CompiledRegistryMigrationBaseline {
        &self.migration_baseline
    }

    /// Return the retained schema descriptor derived from the predecessor's
    /// verified governed model. This descriptor preserves only the
    /// historical snapshot decode contract; it never authorizes startup,
    /// runtime access, SQL execution, or successor activation.
    pub fn history_schema_descriptor(&self) -> HistorySchemaDescriptor {
        self.history_schema_descriptor.clone()
    }

    /// Whether this predecessor's hash-covered manifest declares the complete
    /// engine-owned statistical release store. Reconciliation uses this closed
    /// fact to compare an older active catalog without granting partial-store
    /// compatibility.
    pub fn statistical_release_store_present(&self) -> bool {
        self.statistical_release_store_present
    }

    /// The engine-owned capabilities this predecessor's hash-covered manifest
    /// declares. A successor declaring one this set lacks has apply work even
    /// when its authored model is unchanged.
    pub fn engine_features(&self) -> &BTreeSet<PackageEngineFeature> {
        &self.manifest.engine_features
    }

    /// Whether this predecessor carries [`RETIRED_PACKAGE_API_VERSION`]. The
    /// runtime no longer starts such a package, so a successor that replaces
    /// it has apply work even when its authored model is unchanged.
    pub fn carries_retired_api_version(&self) -> bool {
        self.retired_api_version
    }
}

/// A package whose filesystem closure, sum file, sources, compiler
/// derivation, generated bytes, and migration plan have all been verified.
pub struct VerifiedPackage {
    manifest: PackageManifest,
    registry: CompiledRegistry,
    package_digest: String,
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

    /// The package identity: the SHA-256 of its `SHA256SUMS` file.
    pub fn package_digest(&self) -> &str {
        &self.package_digest
    }

    /// The value-minimized summary of the steps this package's plan runs,
    /// as `bregctl migration explain` reports it.
    #[cfg(feature = "tooling")]
    pub fn migration_summary(&self) -> Result<MigrationInspectionSummary> {
        migration_inspection_summary(&self.manifest, self.reviewed_migration_plan.as_ref())
    }
}

/// Value-free failures. Paths, source values, SQL, key material, signatures,
/// and deployment bindings are deliberately absent from both Display and Debug.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
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
    #[error("the shared package envelope is invalid")]
    Envelope,
    /// The package at `package.root` is not the one the runtime file's
    /// `package.expectedDigest` pins. Both digests are package identities,
    /// not secrets, so the refusal names them.
    #[error("{0}")]
    ExpectedDigestMismatch(registry_platform_config::blocks::PackageDigestMismatch),
    #[error("the package identity binding is invalid")]
    Binding,
    #[error("the package compiler derivation failed")]
    Derivation,
    #[error("the package migration plan is invalid")]
    MigrationPlan,
    #[error("the package permissions are unsafe")]
    Permissions,
    /// The package carries [`RETIRED_PACKAGE_API_VERSION`]. A package is
    /// generated and never edited, so the fix is a rebuild with this release.
    #[error(
        "the package apiVersion `{retired}` is retired; the current apiVersion is `{current}`",
        retired = RETIRED_PACKAGE_API_VERSION,
        current = PACKAGE_API_VERSION
    )]
    RetiredApiVersion,
    // The wrapped reason is one of `ReviewedMigrationError`'s own fixed,
    // value-free messages, so it carries no source value either.
    #[cfg(feature = "tooling")]
    #[error("the reviewed migration plan was refused: {0}")]
    ReviewedMigration(ReviewedMigrationError),
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
    pub assets: Vec<PackageSourceFile>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackageMigrationPlanInput {
    InitialCompiledDdl,
    Successor {
        prior_registry: Box<CompiledRegistry>,
    },
    SuccessorFromBaseline {
        prior_baseline: Box<CompiledRegistryMigrationBaseline>,
    },
    #[cfg(feature = "tooling")]
    ReviewedSuccessor {
        prior_registry: Box<CompiledRegistry>,
        prior_schema_fingerprint: String,
        migrations: Vec<ReviewedMigrationSource>,
    },
    #[cfg(feature = "tooling")]
    ReviewedSuccessorFromBaseline {
        prior_baseline: Box<CompiledRegistryMigrationBaseline>,
        prior_schema_fingerprint: String,
        migrations: Vec<ReviewedMigrationSource>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageBuildRequest {
    /// The digest of the predecessor package, absent for the root package of
    /// a chain.
    pub from_package_digest: Option<String>,
    pub compiler_source_revision: String,
    pub schema_fingerprint: String,
    pub project: PackageSourceFile,
    pub modules: Vec<PackageModuleSource>,
    pub fixture_journeys: PackageSourceFile,
    pub migration_plan: PackageMigrationPlanInput,
}

/// A deterministic package payload. Its identity, the digest of its sum file,
/// exists once it is published.
#[derive(Debug)]
pub struct PreparedPackage {
    manifest: PackageManifest,
    registry: CompiledRegistry,
    files: BTreeMap<String, Vec<u8>>,
}

impl PreparedPackage {
    pub fn manifest(&self) -> &PackageManifest {
        &self.manifest
    }

    /// The exact Production compilation captured by this candidate package.
    pub fn registry(&self) -> &CompiledRegistry {
        &self.registry
    }

    pub fn file_bytes(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }

    /// The reviewed migration plan this candidate carries, validated again
    /// from its captured files exactly as package loading validates it.
    #[cfg(feature = "tooling")]
    pub fn reviewed_migration_plan(&self) -> Result<Option<ValidatedReviewedMigrationPlan>> {
        rederive_reviewed_migration_plan(&self.manifest, &self.files, &self.registry)
    }

    pub fn envelope(&self) -> PackageEnvelope {
        PackageEnvelope {
            api_version: PACKAGE_API_VERSION.to_owned(),
            kind: PACKAGE_KIND.to_owned(),
            manifest: self.manifest.clone(),
        }
    }

    /// The package identity this candidate has once published without a
    /// `REVISION` file: the digest of the sum file over its files and
    /// manifest. Nothing is written.
    pub fn package_digest(&self) -> Result<String> {
        let mut files = self.files.clone();
        let manifest_bytes = canonicalize_json(
            &serde_json::to_value(self.envelope()).map_err(|_| PackageError::CanonicalJson)?,
        )
        .map_err(|_| PackageError::CanonicalJson)?;
        files.insert(MANIFEST_PATH.to_owned(), manifest_bytes);
        plan_package(
            Path::new("."),
            &files,
            None,
            &shared_package_limits(),
            "bregctl package",
        )
        .map_err(|_| PackageError::Bounds)
    }

    /// Publish into a new package directory. The manifest and then the sum
    /// file are written last, so a partial directory is never accepted as a
    /// package by `load_package`.
    pub fn publish_to_directory(&self, destination: &Path) -> Result<SharedVerifiedPackage> {
        self.publish_to_directory_with_revision(destination, None)
    }

    /// Publish inside the shared Registry Stack package envelope, optionally
    /// with a `REVISION` file. A package carries no environment, so every
    /// directory and file is written owner-only.
    pub fn publish_to_directory_with_revision(
        &self,
        destination: &Path,
        revision: Option<&str>,
    ) -> Result<SharedVerifiedPackage> {
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
        set_safe_directory_permissions(destination)?;
        let publish = (|| {
            for (path, bytes) in &self.files {
                let relative = Path::new(path);
                let full = destination.join(relative);
                if let Some(parent) = full.parent() {
                    fs::create_dir_all(parent).map_err(|_| PackageError::Closure)?;
                    set_safe_directory_permissions(parent)?;
                }
                write_new_file(&full, bytes)?;
            }
            let manifest_bytes = canonicalize_json(
                &serde_json::to_value(self.envelope()).map_err(|_| PackageError::CanonicalJson)?,
            )
            .map_err(|_| PackageError::CanonicalJson)?;
            write_new_file(&destination.join(MANIFEST_PATH), &manifest_bytes)?;
            let package = write_sum_file(
                destination,
                revision,
                &shared_package_limits(),
                "bregctl package",
            )
            .map_err(|_| PackageError::Closure)?;
            set_safe_file_permissions(&destination.join(SUM_FILE))?;
            if revision.is_some() {
                set_safe_file_permissions(&destination.join(REVISION_FILE))?;
            }
            Ok(package)
        })();
        if publish.is_err() {
            let _ = remove_created_package_dir(destination);
        }
        publish
    }
}

pub(crate) fn shared_package_limits() -> SharedPackageLimits {
    SharedPackageLimits {
        max_files: MAX_PACKAGE_FILES + 2,
        max_file_bytes: MAX_FILE_BYTES,
        max_total_bytes: MAX_PACKAGE_BYTES,
        max_depth: MAX_PATH_COMPONENTS,
        max_path_bytes: MAX_PATH_BYTES,
    }
}

/// Compare two compiled Registries by stable logical identifiers and return a
/// value-free change set. The embedded migration plan is present only when
/// every change is compiler-owned and can be applied without reviewed SQL.
pub fn compiled_registry_change_set(
    previous: &CompiledRegistry,
    candidate: &CompiledRegistry,
    from_package_digest: &str,
) -> CompiledRegistryChangeSet {
    let previous_baseline =
        CompiledRegistryMigrationBaseline::from_compiled(from_package_digest, previous);
    compiled_registry_change_set_from_baseline(&previous_baseline, candidate, from_package_digest)
}

/// Compare a retained predecessor baseline with the current candidate without
/// reconstructing or executing the predecessor compiler model.
pub fn compiled_registry_change_set_from_baseline(
    previous: &CompiledRegistryMigrationBaseline,
    candidate: &CompiledRegistry,
    from_package_digest: &str,
) -> CompiledRegistryChangeSet {
    let candidate_baseline = CompiledRegistryMigrationBaseline::from_compiled("", candidate);
    let mut changes = Vec::new();
    compare_registry_identity(previous, &candidate_baseline, &mut changes);
    compare_entities(previous, &candidate_baseline, &mut changes);
    compare_statistical_datasets(previous, &candidate_baseline, &mut changes);
    compare_routes(previous, &candidate_baseline, &mut changes);
    compare_query_inventory(previous, &candidate_baseline, &mut changes);
    compare_actions(previous, &candidate_baseline, &mut changes);
    compare_recipients(previous, &candidate_baseline, &mut changes);
    sort_changes(&mut changes);
    changes.dedup();

    let mut change_set = CompiledRegistryChangeSet {
        from_package_digest: from_package_digest.to_owned(),
        changes,
        migration_plan: None,
    };
    if compiler_applicable_without_review(previous, &candidate_baseline, &change_set.changes) {
        change_set.migration_plan = Some(additive_migration_plan(
            previous,
            candidate,
            from_package_digest,
            change_set.changes.clone(),
        ));
    }
    change_set
}

/// Convert a value-free change set into an applicable migration plan only when
/// the compiler can apply it without reviewed SQL.
pub fn change_set_to_applicable_migration_plan(
    change_set: &CompiledRegistryChangeSet,
) -> Result<MigrationPlan> {
    change_set
        .migration_plan
        .clone()
        .ok_or(PackageError::MigrationPlan)
}

fn compiler_applicable_without_review(
    previous: &CompiledRegistryMigrationBaseline,
    candidate: &CompiledRegistryMigrationBaseline,
    changes: &[CompiledRegistryChange],
) -> bool {
    changes.iter().all(|change| match change.class {
        CompiledRegistryChangeClass::CompatibleAdditive => true,
        CompiledRegistryChangeClass::AccessOrDisclosureChange
            if change.code == CompiledRegistryChangeCode::QueryInventoryChanged =>
        {
            automatic_query_inventory_change(previous, candidate, change)
        }
        CompiledRegistryChangeClass::AccessOrDisclosureChange
            if change.target.kind == CompiledRegistryChangeTargetKind::Action =>
        {
            false
        }
        CompiledRegistryChangeClass::AccessOrDisclosureChange => true,
        _ => false,
    })
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
    if previous.registry_version != candidate.registry_version {
        push_change(
            changes,
            CompiledRegistryChangeClass::Unsupported,
            CompiledRegistryChangeCode::RegistryVersionChanged,
            target(CompiledRegistryChangeTargetKind::Registry, None, None),
        );
    }
}

fn compare_statistical_datasets(
    previous: &CompiledRegistryMigrationBaseline,
    candidate: &CompiledRegistryMigrationBaseline,
    changes: &mut Vec<CompiledRegistryChange>,
) {
    for (id, before) in &previous.statistical_datasets {
        match candidate.statistical_datasets.get(id) {
            None => push_change(
                changes,
                CompiledRegistryChangeClass::AccessOrDisclosureChange,
                CompiledRegistryChangeCode::StatisticalDatasetRemoved,
                target(
                    CompiledRegistryChangeTargetKind::StatisticalDataset,
                    None,
                    Some(id),
                ),
            ),
            Some(after) if before != after => push_change(
                changes,
                CompiledRegistryChangeClass::AccessOrDisclosureChange,
                CompiledRegistryChangeCode::StatisticalDatasetChanged,
                target(
                    CompiledRegistryChangeTargetKind::StatisticalDataset,
                    None,
                    Some(id),
                ),
            ),
            Some(_) => {}
        }
    }
    for id in candidate.statistical_datasets.keys() {
        if !previous.statistical_datasets.contains_key(id) {
            push_change(
                changes,
                CompiledRegistryChangeClass::AccessOrDisclosureChange,
                CompiledRegistryChangeCode::StatisticalDatasetAdded,
                target(
                    CompiledRegistryChangeTargetKind::StatisticalDataset,
                    None,
                    Some(id),
                ),
            );
        }
    }
}

impl CompiledRegistryChangeCode {
    /// The sentence an adopter needs beyond the code name, for `diff` output and
    /// for a review refusal that lists the change. `None` when the code name is
    /// the whole story.
    pub fn explanation(self) -> Option<&'static str> {
        match self {
            Self::RegistryVersionChanged => Some(
                "registry.version is bound to the database for its lifetime: an installed database keeps the registry identity it was initialized with, so a package that changes the version can only initialize a new database, never migrate this one",
            ),
            Self::FieldEncryptionChanged => Some(
                "turning field encryption on rekeys storage behind a reviewed backfill before the plaintext column retires; Phase 1 does not support turning encryption off",
            ),
            Self::FieldLookupChanged => Some(
                "Phase 1 does not support changing the blind-index lookup of an already-encrypted field; keep its lookup unchanged",
            ),
            Self::FieldAddedRequired => Some(
                "a required field on an existing entity needs a reviewed backfill; when the field is encrypted, add it as optional, populate it through authorized Registry writes, then make it required in a later package",
            ),
            _ => None,
        }
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
        if previous_entity.access_requirements != candidate_entity.access_requirements {
            push_change(
                changes,
                CompiledRegistryChangeClass::AccessOrDisclosureChange,
                CompiledRegistryChangeCode::EntityAccessRequirementsChanged,
                target(
                    CompiledRegistryChangeTargetKind::Entity,
                    Some(entity_id.as_str()),
                    None,
                ),
            );
        }
        if previous_entity.access_log != candidate_entity.access_log {
            push_change(
                changes,
                CompiledRegistryChangeClass::AccessOrDisclosureChange,
                CompiledRegistryChangeCode::EntityAccessLogChanged,
                target(
                    CompiledRegistryChangeTargetKind::Entity,
                    Some(entity_id.as_str()),
                    None,
                ),
            );
        }
        if previous_entity.consent_record != candidate_entity.consent_record {
            push_change(
                changes,
                CompiledRegistryChangeClass::AccessOrDisclosureChange,
                CompiledRegistryChangeCode::ConsentRecordChanged,
                target(
                    CompiledRegistryChangeTargetKind::Entity,
                    Some(entity_id.as_str()),
                    None,
                ),
            );
        }
        if previous_entity.geojson != candidate_entity.geojson {
            push_change(
                changes,
                CompiledRegistryChangeClass::AccessOrDisclosureChange,
                CompiledRegistryChangeCode::EntityGeoJsonChanged,
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
        if previous_entity
            .change_request
            .as_ref()
            .map(|request| request.contract_fingerprint.as_str())
            != candidate_entity
                .change_request
                .as_ref()
                .map(|request| request.contract_fingerprint.as_str())
        {
            push_change(
                changes,
                CompiledRegistryChangeClass::AccessOrDisclosureChange,
                CompiledRegistryChangeCode::ChangeRequestContractChanged,
                target(
                    CompiledRegistryChangeTargetKind::ChangeRequest,
                    Some(entity_id.as_str()),
                    None,
                ),
            );
        }
        compare_fields(entity_id, previous_entity, candidate_entity, changes);
        compare_derived_relations(entity_id, previous_entity, candidate_entity, changes);
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
        // A compiler-owned reference index leaves when an authored index or
        // unique constraint takes over its column, or with its column. Its
        // removal drops no data, so it needs no reviewed SQL.
        for compiler_owned in [false, true] {
            let select = |indexes: &BTreeMap<String, Vec<String>>| {
                indexes
                    .iter()
                    .filter(|(id, _)| id.starts_with(REFERENCE_INDEX_PREFIX) == compiler_owned)
                    .map(|(id, fields)| (id.clone(), fields.clone()))
                    .collect::<BTreeMap<_, _>>()
            };
            compare_map(
                entity_id,
                &select(&previous_entity.indexes),
                &select(&candidate_entity.indexes),
                CompiledRegistryChangeTargetKind::Index,
                CompiledRegistryChangeCode::IndexAdded,
                CompiledRegistryChangeCode::IndexRemoved,
                CompiledRegistryChangeCode::IndexChanged,
                CompiledRegistryChangeClass::CompatibleAdditive,
                if compiler_owned {
                    CompiledRegistryChangeClass::CompatibleAdditive
                } else {
                    CompiledRegistryChangeClass::DestructiveOrIrreversible
                },
                CompiledRegistryChangeClass::DestructiveOrIrreversible,
                changes,
            );
        }
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
            &previous_entity.hooks,
            &candidate_entity.hooks,
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

fn compare_derived_relations(
    entity_id: &str,
    previous: &CompiledEntity,
    candidate: &CompiledEntity,
    changes: &mut Vec<CompiledRegistryChange>,
) {
    for (relation_id, previous_relation) in &previous.derived_relations {
        match candidate.derived_relations.get(relation_id) {
            Some(candidate_relation) if previous_relation == candidate_relation => {}
            Some(candidate_relation) => {
                let class = if previous_relation.sql_path == candidate_relation.sql_path
                    && previous_relation.key_field == candidate_relation.key_field
                    && previous_relation.execution == candidate_relation.execution
                    && previous_relation.fields == candidate_relation.fields
                {
                    CompiledRegistryChangeClass::CompatibleAdditive
                } else {
                    CompiledRegistryChangeClass::DestructiveOrIrreversible
                };
                push_change(
                    changes,
                    class,
                    CompiledRegistryChangeCode::DerivedRelationChanged,
                    target(
                        CompiledRegistryChangeTargetKind::DerivedRelation,
                        Some(entity_id),
                        Some(relation_id.as_str()),
                    ),
                );
            }
            None => push_change(
                changes,
                CompiledRegistryChangeClass::DestructiveOrIrreversible,
                CompiledRegistryChangeCode::DerivedRelationRemoved,
                target(
                    CompiledRegistryChangeTargetKind::DerivedRelation,
                    Some(entity_id),
                    Some(relation_id.as_str()),
                ),
            ),
        }
    }
    for relation_id in candidate.derived_relations.keys() {
        if !previous.derived_relations.contains_key(relation_id) {
            push_change(
                changes,
                CompiledRegistryChangeClass::CompatibleAdditive,
                CompiledRegistryChangeCode::DerivedRelationAdded,
                target(
                    CompiledRegistryChangeTargetKind::DerivedRelation,
                    Some(entity_id),
                    Some(relation_id.as_str()),
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
        // Turning encryption on or off renames the storage column: the flip
        // code carries that rename, and a second physical-name change for the
        // same field would break the migration plan's exactly-one cover rule.
        let encryption_presence_changed =
            previous_field.encryption.is_none() != candidate_field.encryption.is_none();
        if previous_field.physical_name != candidate_field.physical_name
            && !encryption_presence_changed
        {
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
        if encryption_presence_changed {
            let class = if candidate_field.encryption.is_some() {
                CompiledRegistryChangeClass::DataBackfillRequired
            } else {
                // Phase 1 has no keyed engine path that can open envelopes into
                // a replacement plaintext column. Refuse the evolution instead
                // of accepting authored SQL that cannot perform it safely.
                CompiledRegistryChangeClass::Unsupported
            };
            push_change(
                changes,
                class,
                CompiledRegistryChangeCode::FieldEncryptionChanged,
                target(
                    CompiledRegistryChangeTargetKind::Field,
                    Some(entity_id),
                    Some(field_id.as_str()),
                ),
            );
        }
        if previous_field.encryption.is_some()
            && candidate_field.encryption.is_some()
            && previous_field.encryption != candidate_field.encryption
        {
            push_change(
                changes,
                // Existing envelopes are the only source value. Authored SQL
                // cannot open them to derive a changed keyed blind index, and
                // the Phase 1 engine backfill only seals predecessor plaintext.
                CompiledRegistryChangeClass::Unsupported,
                CompiledRegistryChangeCode::FieldLookupChanged,
                target(
                    CompiledRegistryChangeTargetKind::Field,
                    Some(entity_id),
                    Some(field_id.as_str()),
                ),
            );
        }
        if previous_field.field_type != candidate_field.field_type
            && candidate_field
                .field_type
                .keeps_vocabulary_codes_of(&previous_field.field_type)
        {
            // Every stored code stays valid, so the change only widens the
            // column check. An encrypted column carries no check to widen.
            push_change(
                changes,
                CompiledRegistryChangeClass::CompatibleAdditive,
                CompiledRegistryChangeCode::FieldVocabularyCodesAdded,
                target(
                    CompiledRegistryChangeTargetKind::Field,
                    Some(entity_id),
                    Some(field_id.as_str()),
                ),
            );
        } else if candidate_field
            .field_type
            .widens_length_limits_of(&previous_field.field_type)
        {
            // Every stored value is within the relaxed limit, so the change
            // only replaces or drops the column's length check.
            push_change(
                changes,
                CompiledRegistryChangeClass::CompatibleAdditive,
                CompiledRegistryChangeCode::FieldLengthWidened,
                target(
                    CompiledRegistryChangeTargetKind::Field,
                    Some(entity_id),
                    Some(field_id.as_str()),
                ),
            );
        } else if previous_field.field_type != candidate_field.field_type {
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
                if previous_field.encryption.is_some() || candidate_field.encryption.is_some() {
                    // The Phase 1 keyed paths only open an existing envelope
                    // or seal the predecessor type's serialization. Neither
                    // converts a value between authored field types.
                    CompiledRegistryChangeClass::Unsupported
                } else {
                    CompiledRegistryChangeClass::DestructiveOrIrreversible
                },
                code,
                target(
                    CompiledRegistryChangeTargetKind::Field,
                    Some(entity_id),
                    Some(field_id.as_str()),
                ),
            );
        }
        if previous_field.pattern != candidate_field.pattern {
            let (class, code) = match (&previous_field.pattern, &candidate_field.pattern) {
                (None, Some(_)) => (
                    CompiledRegistryChangeClass::CompatibleAdditive,
                    CompiledRegistryChangeCode::FieldPatternAdded,
                ),
                (Some(_), None) => (
                    CompiledRegistryChangeClass::DestructiveOrIrreversible,
                    CompiledRegistryChangeCode::FieldPatternRemoved,
                ),
                _ => (
                    CompiledRegistryChangeClass::DestructiveOrIrreversible,
                    CompiledRegistryChangeCode::FieldPatternChanged,
                ),
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
        let class = if field.required && field.encryption.is_some() {
            // A new encrypted field has no predecessor plaintext for the keyed
            // engine backfill, while authored SQL cannot create envelopes.
            // Optional-first lets ordinary authorized writes populate it.
            CompiledRegistryChangeClass::Unsupported
        } else if field.required {
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

fn compare_actions(
    previous: &CompiledRegistryMigrationBaseline,
    candidate: &CompiledRegistryMigrationBaseline,
    changes: &mut Vec<CompiledRegistryChange>,
) {
    let previous_actions = previous
        .actions
        .actions
        .iter()
        .map(|action| (action.id.as_str(), action))
        .collect::<BTreeMap<_, _>>();
    let candidate_actions = candidate
        .actions
        .actions
        .iter()
        .map(|action| (action.id.as_str(), action))
        .collect::<BTreeMap<_, _>>();
    for (id, before) in &previous_actions {
        let (class, code) = match candidate_actions.get(id) {
            Some(after) if before.contract_fingerprint == after.contract_fingerprint => continue,
            // Every request the previous contract accepted keeps its meaning;
            // the action only accepts codes new to its vocabularies.
            Some(after)
                if crate::immediate_actions::contract_only_widens(
                    (before, &previous.actions.input_vocabularies),
                    &previous.entities,
                    (after, &candidate.actions.input_vocabularies),
                    &candidate.entities,
                    FieldTypeSource::keeps_vocabulary_codes_of,
                ) =>
            {
                (
                    CompiledRegistryChangeClass::CompatibleAdditive,
                    CompiledRegistryChangeCode::ActionVocabularyCodesAdded,
                )
            }
            // A target field also raised its `text` length limit, which every
            // stored and requested value already meets.
            Some(after)
                if crate::immediate_actions::contract_only_widens(
                    (before, &previous.actions.input_vocabularies),
                    &previous.entities,
                    (after, &candidate.actions.input_vocabularies),
                    &candidate.entities,
                    FieldTypeSource::admits_every_value_of,
                ) =>
            {
                (
                    CompiledRegistryChangeClass::CompatibleAdditive,
                    CompiledRegistryChangeCode::ActionTargetFieldsWidened,
                )
            }
            Some(_) => (
                CompiledRegistryChangeClass::AccessOrDisclosureChange,
                CompiledRegistryChangeCode::ActionChanged,
            ),
            None => (
                CompiledRegistryChangeClass::AccessOrDisclosureChange,
                CompiledRegistryChangeCode::ActionRemoved,
            ),
        };
        push_change(
            changes,
            class,
            code,
            target(CompiledRegistryChangeTargetKind::Action, None, Some(id)),
        );
    }
    for id in candidate_actions.keys() {
        if !previous_actions.contains_key(id) {
            push_change(
                changes,
                CompiledRegistryChangeClass::AccessOrDisclosureChange,
                CompiledRegistryChangeCode::ActionAdded,
                target(CompiledRegistryChangeTargetKind::Action, None, Some(id)),
            );
        }
    }
}

/// Recipients are project-level runtime configuration: they change no DDL, so
/// each change needs its own code for the diff to show it and for activation
/// to carry it as a metadata-only plan.
fn compare_recipients(
    previous: &CompiledRegistryMigrationBaseline,
    candidate: &CompiledRegistryMigrationBaseline,
    changes: &mut Vec<CompiledRegistryChange>,
) {
    use CompiledRegistryChangeCode as Code;
    compare_recipient_list(
        &previous.recipients.organizations,
        &candidate.recipients.organizations,
        |organization| &organization.id,
        [
            Code::RecipientOrganizationAdded,
            Code::RecipientOrganizationRemoved,
            Code::RecipientOrganizationChanged,
        ],
        changes,
    );
    compare_recipient_list(
        &previous.recipients.groups,
        &candidate.recipients.groups,
        |group| &group.id,
        [
            Code::RecipientGroupAdded,
            Code::RecipientGroupRemoved,
            Code::RecipientGroupChanged,
        ],
        changes,
    );
}

fn compare_recipient_list<T: PartialEq>(
    previous: &[T],
    candidate: &[T],
    id: impl Fn(&T) -> &String,
    [added, removed, changed]: [CompiledRegistryChangeCode; 3],
    changes: &mut Vec<CompiledRegistryChange>,
) {
    let before = previous
        .iter()
        .map(|item| (id(item), item))
        .collect::<BTreeMap<_, _>>();
    let after = candidate
        .iter()
        .map(|item| (id(item), item))
        .collect::<BTreeMap<_, _>>();
    for recipient in before.keys().chain(after.keys()).collect::<BTreeSet<_>>() {
        let code = match (before.get(recipient), after.get(recipient)) {
            (Some(left), Some(right)) if left == right => continue,
            (Some(_), Some(_)) => changed,
            (Some(_), None) => removed,
            (None, _) => added,
        };
        push_change(
            changes,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            code,
            target(
                CompiledRegistryChangeTargetKind::Recipient,
                None,
                Some(recipient),
            ),
        );
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

fn automatic_query_inventory_change(
    previous: &CompiledRegistryMigrationBaseline,
    candidate: &CompiledRegistryMigrationBaseline,
    change: &CompiledRegistryChange,
) -> bool {
    let Some(query_id) = change.target.member_id.as_deref() else {
        return false;
    };
    let before = previous
        .queries
        .operations
        .iter()
        .find(|query| query.id == query_id);
    let after = candidate
        .queries
        .operations
        .iter()
        .find(|query| query.id == query_id);
    query_changed_by_access_grant_delta(previous, candidate, before, after)
}

fn query_changed_by_access_grant_delta(
    previous: &CompiledRegistryMigrationBaseline,
    candidate: &CompiledRegistryMigrationBaseline,
    before: Option<&CompiledQueryOperation>,
    after: Option<&CompiledQueryOperation>,
) -> bool {
    match (before, after) {
        (Some(before), None) => {
            previous.entities.contains_key(&before.entity_id)
                && candidate.entities.contains_key(&before.entity_id)
                && route_grants_query(previous, before)
                && !route_grants_query(candidate, before)
        }
        (None, Some(after)) => {
            previous.entities.contains_key(&after.entity_id)
                && candidate.entities.contains_key(&after.entity_id)
                && !route_grants_query(previous, after)
                && route_grants_query(candidate, after)
        }
        _ => false,
    }
}

fn route_grants_query(
    baseline: &CompiledRegistryMigrationBaseline,
    query: &CompiledQueryOperation,
) -> bool {
    // The canonical route owns the grant: lookup shares List's execution kind,
    // and a read-path query names its target entity while its route names the source.
    baseline.routes.routes.iter().any(|route| {
        route.id == query.route_id && route.access_profiles.contains(&query.profile_id)
    })
}

fn additive_migration_plan(
    previous: &CompiledRegistryMigrationBaseline,
    candidate: &CompiledRegistry,
    from_package_digest: &str,
    changes: Vec<CompiledRegistryChange>,
) -> MigrationPlan {
    let mut new_statement_ids = BTreeSet::<String>::new();
    let mut replacement_statement_ids = BTreeSet::<String>::new();
    let mut added_columns = BTreeMap::<String, Vec<DdlStatement>>::new();
    let mut widened_checks = BTreeMap::<String, Vec<DdlStatement>>::new();
    let previous_ddl = generate_ddl_with_actions(
        &previous.entities,
        &previous.physical_names,
        &previous.actions,
    );
    // Automatic apply may reconcile candidate policies before executing DDL.
    // Only retire obsolete policies here; reconciliation owns candidate creates.
    let (policy_drops, _) = successor_managed_policy_delta(&previous_ddl, candidate.ddl());
    let mut dropped_policy_statement_ids = policy_drops
        .iter()
        .map(|statement| statement.id.clone())
        .collect::<BTreeSet<_>>();
    let mut removed_dependency_statements = policy_drops;
    let previous_probe_functions = previous_ddl
        .statements
        .iter()
        .filter(|statement| {
            statement.kind == DdlStatementKind::Function
                && is_row_probe_function_statement(&statement.id)
        })
        .map(|statement| (statement.id.as_str(), statement))
        .collect::<BTreeMap<_, _>>();
    let candidate_probe_functions = candidate
        .ddl()
        .statements
        .iter()
        .filter(|statement| {
            statement.kind == DdlStatementKind::Function
                && is_row_probe_function_statement(&statement.id)
        })
        .map(|statement| (statement.id.as_str(), statement))
        .collect::<BTreeMap<_, _>>();
    for (id, statement) in &candidate_probe_functions {
        if previous_probe_functions.get(id) != Some(statement) {
            new_statement_ids.insert((*id).to_owned());
            if previous_probe_functions.contains_key(id) {
                replacement_statement_ids.insert((*id).to_owned());
            }
        }
    }
    // A reviewed table replacement or removal runs later, but any policy that
    // depends on a retiring membership or consent helper must be removed
    // first so PostgreSQL can drop the helper function. The complete same-table
    // delta above already owns these drops; deduplicate that shared case.
    for table in &previous_ddl.tables {
        let candidate_table = candidate
            .ddl()
            .tables
            .iter()
            .find(|candidate| candidate.entity_id == table.entity_id);
        for policy in &table.policies {
            if policy_depends_on_row_probe(policy)
                && !candidate_table.is_some_and(|candidate| candidate.policies.contains(policy))
            {
                let drop = drop_policy_statement(&table.entity_id, table, &policy.name);
                if dropped_policy_statement_ids.insert(drop.id.clone()) {
                    removed_dependency_statements.push(drop);
                }
            }
        }
    }
    for function in &previous_ddl.functions {
        if ROW_PROBE_PREFIXES
            .iter()
            .any(|prefix| function.name.starts_with(prefix))
            && !candidate_probe_functions.contains_key(function.id.as_str())
        {
            removed_dependency_statements.push(DdlStatement {
                id: format!("{}.drop", function.id),
                kind: DdlStatementKind::Function,
                sql: format!(
                    "DROP FUNCTION registry_context.{}({})",
                    quote_identifier(&function.name),
                    function.arguments
                ),
            });
        }
    }
    if candidate.ddl().requires_postgis && !previous_ddl.requires_postgis {
        new_statement_ids.insert(spatial_bbox_function_statement().id);
    }
    for previous_table in &previous_ddl.tables {
        let previous_entity = &previous.entities[&previous_table.entity_id];
        let candidate_view_statement_id =
            format!("entity.{}.spatial-candidates-view", previous_entity.id);
        let previous_view_statement = previous_ddl
            .statements
            .iter()
            .find(|statement| statement.id == candidate_view_statement_id);
        let candidate_view_statement = candidate
            .ddl()
            .statements
            .iter()
            .find(|statement| statement.id == candidate_view_statement_id);
        if previous_view_statement.map(|statement| &statement.sql)
            != candidate_view_statement.map(|statement| &statement.sql)
        {
            if previous_view_statement.is_some() {
                // The view depends on the generated geometry and helper. Drop
                // it before either dependency changes, then recreate it below.
                removed_dependency_statements.push(
                    drop_spatial_candidate_view_statement(previous_entity)
                        .expect("generated candidate view has a drop statement"),
                );
            }
            if candidate_view_statement.is_some() {
                new_statement_ids.insert(candidate_view_statement_id);
            }
        }
        let previous_fields = spatial_projection_fields(previous_entity);
        let candidate_entity = candidate.entities().get(&previous_table.entity_id);
        let candidate_fields = candidate_entity
            .map(spatial_projection_fields)
            .unwrap_or_default();
        let removed_fields: Vec<_> = previous_fields.difference(&candidate_fields).collect();
        let candidate_table = candidate
            .ddl()
            .tables
            .iter()
            .find(|table| table.entity_id == previous_table.entity_id);
        for policy in &previous_table.policies {
            if policy.applies_to == DdlPolicyRole::SpatialBbox
                && (!removed_fields.is_empty()
                    || !candidate_table.is_some_and(|table| {
                        table
                            .policies
                            .iter()
                            .any(|candidate| candidate.name == policy.name)
                    }))
            {
                let drop =
                    drop_policy_statement(&previous_table.entity_id, previous_table, &policy.name);
                if dropped_policy_statement_ids.insert(drop.id.clone()) {
                    removed_dependency_statements.push(drop);
                }
            }
        }
        for field in removed_fields {
            let projection = spatial_projection_statements(previous_entity, field);
            removed_dependency_statements.extend([projection.drop_index, projection.drop_column]);
        }
    }
    if previous_ddl.requires_postgis && !candidate.ddl().requires_postgis {
        removed_dependency_statements.push(drop_spatial_bbox_function_statement());
    }

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
            // Added checks always scan existing data, including when a previously
            // unconstrained column is present. Changes/removals require reviewed
            // DDL. An encrypted column stores ciphertext, which no authored
            // pattern can match, so its DDL carries no pattern statement to add.
            if field.pattern.is_some()
                && field.encryption.is_none()
                && previous_entity
                    .fields
                    .get(field_id)
                    .is_none_or(|prior| prior.pattern.is_none())
            {
                new_statement_ids.insert(format!("entity.{entity_id}.field.{field_id}.pattern"));
            }
            if let Some(previous_field) = previous_entity.fields.get(field_id) {
                if previous_field.field_type != field.field_type
                    && field
                        .field_type
                        .keeps_vocabulary_codes_of(&previous_field.field_type)
                {
                    widened_checks.entry(entity_id.clone()).or_default().extend(
                        replace_vocabulary_check_statement(
                            candidate_entity,
                            &candidate.physical_names().entities[entity_id],
                            field,
                        ),
                    );
                }
                if field
                    .field_type
                    .widens_length_limits_of(&previous_field.field_type)
                {
                    widened_checks.entry(entity_id.clone()).or_default().extend(
                        replace_length_check_statement(
                            candidate_entity,
                            &candidate.physical_names().entities[entity_id],
                            field,
                        ),
                    );
                }
                // Turning encryption on swaps the field's storage: the envelope
                // and blind-index columns arrive nullable, a unique lookup
                // index lands empty ahead of the reviewed backfill that fills
                // it, and the plaintext column and the rekey itself belong to
                // the reviewed SQL, never to this additive prefix.
                if previous_field.encryption.is_none() && field.encryption.is_some() {
                    let columns = added_columns.entry(entity_id.clone()).or_default();
                    columns.push(add_column_statement(candidate_entity, field));
                    columns.extend(set_column_not_null_statement(candidate_entity, field));
                    if field
                        .encryption
                        .as_ref()
                        .and_then(|encryption| encryption.blind_index.as_ref())
                        .is_some()
                    {
                        columns.push(add_blind_index_column_statement(candidate_entity, field));
                    }
                    if field_requires_unique_lookup_index(field) {
                        new_statement_ids
                            .insert(format!("entity.{entity_id}.field.{field_id}.lookup-unique"));
                    }
                    let source_view_id = format!("entity.{entity_id}.source-view");
                    replacement_statement_ids.insert(source_view_id.clone());
                    new_statement_ids.insert(source_view_id);
                }
                // A lookup gained or made unique on an already-encrypted field
                // keeps the envelope column: only the blind-index sibling and
                // its unique index arrive, empty, ahead of the backfill.
                if previous_field.encryption.is_some() && field.encryption.is_some() {
                    let previous_blind = previous_field
                        .encryption
                        .as_ref()
                        .and_then(|encryption| encryption.blind_index.as_ref());
                    let blind = field
                        .encryption
                        .as_ref()
                        .and_then(|encryption| encryption.blind_index.as_ref());
                    if previous_blind.is_none() && blind.is_some() {
                        added_columns
                            .entry(entity_id.clone())
                            .or_default()
                            .push(add_blind_index_column_statement(candidate_entity, field));
                    }
                    if blind.is_some_and(|blind| blind.unique)
                        && !previous_blind.is_some_and(|blind| blind.unique)
                    {
                        new_statement_ids
                            .insert(format!("entity.{entity_id}.field.{field_id}.lookup-unique"));
                    }
                }
                continue;
            }
            // A required field's column arrives nullable and is constrained
            // by a second statement the interlock runs after the reviewed
            // backfill has populated the rows the entity already holds.
            let columns = added_columns.entry(entity_id.clone()).or_default();
            columns.push(add_column_statement(candidate_entity, field));
            columns.extend(set_column_not_null_statement(candidate_entity, field));
            if field
                .encryption
                .as_ref()
                .and_then(|encryption| encryption.blind_index.as_ref())
                .is_some()
            {
                columns.push(add_blind_index_column_statement(candidate_entity, field));
            }
            if field_requires_unique_lookup_index(field) {
                new_statement_ids
                    .insert(format!("entity.{entity_id}.field.{field_id}.lookup-unique"));
            }
            if matches!(field.field_type, FieldTypeSource::Reference { .. }) {
                new_statement_ids.insert(format!("entity.{entity_id}.field.{field_id}.reference"));
            }
            let source_view_id = format!("entity.{entity_id}.source-view");
            replacement_statement_ids.insert(source_view_id.clone());
            new_statement_ids.insert(source_view_id);
        }
        let previous_fields = spatial_projection_fields(previous_entity);
        for field_id in spatial_projection_fields(candidate_entity).difference(&previous_fields) {
            let projection = spatial_projection_statements(candidate_entity, field_id);
            added_columns
                .entry(entity_id.clone())
                .or_default()
                .push(projection.add_column);
            new_statement_ids.insert(projection.create_index.id);
        }
        for (relation_id, relation) in &candidate_entity.derived_relations {
            match previous_entity.derived_relations.get(relation_id) {
                Some(previous)
                    if previous.sql_path == relation.sql_path
                        && previous.key_field == relation.key_field
                        && previous.execution == relation.execution
                        && previous.fields == relation.fields =>
                {
                    // The wrapper around authored derived SQL is compiler-owned
                    // DDL. Refresh every retained compatible relation so a
                    // successor built by a newer compiler installs changes to
                    // that wrapper even when the authored SQL and field model
                    // are unchanged. PostgreSQL replaces the view definition
                    // without rewriting stored rows, and the final catalog
                    // fingerprint still fences the exact candidate definition.
                    let derived_view_id = format!("entity.{entity_id}.derived.{relation_id}.view");
                    replacement_statement_ids.insert(derived_view_id.clone());
                    new_statement_ids.insert(derived_view_id);
                }
                None => {
                    new_statement_ids
                        .insert(format!("entity.{entity_id}.derived.{relation_id}.view"));
                }
                _ => {}
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
        for index_id in previous_entity.indexes.keys() {
            if index_id.starts_with(REFERENCE_INDEX_PREFIX)
                && !candidate_entity.indexes.contains_key(index_id)
            {
                removed_dependency_statements.push(DdlStatement {
                    id: format!("entity.{entity_id}.index.{index_id}.drop"),
                    kind: DdlStatementKind::Index,
                    sql: format!(
                        "DROP INDEX IF EXISTS registry_data.{}",
                        quote_identifier(
                            &previous.physical_names.entities[entity_id].indexes[index_id]
                        )
                    ),
                });
            }
        }
        // Consent indexes follow the consent record: a changed key or revoke
        // set drops the prior index and builds the candidate one.
        let previous_indexes = crate::consent::index_statements(previous_entity);
        let candidate_indexes = crate::consent::index_statements(candidate_entity);
        for (id, name, sql) in &previous_indexes {
            if !candidate_indexes
                .iter()
                .any(|candidate| &candidate.2 == sql)
            {
                removed_dependency_statements.push(DdlStatement {
                    id: format!("{id}.drop"),
                    kind: DdlStatementKind::Index,
                    sql: format!(
                        "DROP INDEX IF EXISTS registry_data.{}",
                        quote_identifier(name)
                    ),
                });
            }
        }
        for (id, _, sql) in &candidate_indexes {
            if !previous_indexes.iter().any(|previous| &previous.2 == sql) {
                new_statement_ids.insert(id.clone());
            }
        }
    }

    let mut statements = removed_dependency_statements;
    for statement in &candidate.ddl().statements {
        if let Some(entity_id) = table_statement_entity_id(&statement.id) {
            if let Some(columns) = added_columns.get(entity_id) {
                statements.extend(columns.iter().cloned());
            }
            if let Some(checks) = widened_checks.get(entity_id) {
                statements.extend(checks.iter().cloned());
            }
        }
        if new_statement_ids.contains(statement.id.as_str()) {
            statements.push(
                if replacement_statement_ids.contains(statement.id.as_str()) {
                    replacement_statement(statement)
                } else {
                    statement.clone()
                },
            );
        }
    }
    MigrationPlan {
        from_package_digest: Some(from_package_digest.to_owned()),
        prior_baseline: Some(previous.clone()),
        changes,
        statements,
        reviewed_descriptors: Vec::new(),
        prior_schema_fingerprint: None,
    }
}

/// Name prefixes of the generated per-row probe helpers, membership and
/// consent, which migrations replace and drop together with their policies.
const ROW_PROBE_PREFIXES: [&str; 2] = ["membership_", "consent_"];

fn is_row_probe_function_statement(id: &str) -> bool {
    id.strip_prefix("registry_context.").is_some_and(|name| {
        ROW_PROBE_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
    })
}

fn policy_depends_on_row_probe(policy: &DdlPolicy) -> bool {
    ROW_PROBE_PREFIXES.iter().any(|prefix| {
        policy.name.starts_with(&format!("registry_{prefix}"))
            || policy
                .using_expression
                .iter()
                .chain(&policy.check_expression)
                .any(|expression| expression.contains(&format!("registry_context.\"{prefix}")))
    })
}

fn replacement_statement(statement: &DdlStatement) -> DdlStatement {
    if statement.kind == DdlStatementKind::Function
        && is_row_probe_function_statement(&statement.id)
    {
        return DdlStatement {
            id: statement.id.clone(),
            kind: statement.kind,
            sql: statement
                .sql
                .replacen("CREATE FUNCTION ", "CREATE OR REPLACE FUNCTION ", 1),
        };
    }
    if statement.kind != DdlStatementKind::View {
        return statement.clone();
    }
    DdlStatement {
        id: statement.id.clone(),
        kind: statement.kind,
        sql: statement.sql.strip_prefix("CREATE VIEW ").map_or_else(
            || statement.sql.clone(),
            |suffix| format!("CREATE OR REPLACE VIEW {suffix}"),
        ),
    }
}

fn initial_migration_plan(compiled: &CompiledRegistry) -> MigrationPlan {
    MigrationPlan {
        from_package_digest: None,
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
        &change_set.from_package_digest,
        additive_changes,
    );
    // The reviewed executor drops every managed read view before reviewed
    // steps when the plan carries any non-spatial view statement, including a
    // retained derived-view replacement. Plan the complete candidate view set
    // in that case so the views that replacement depends on are rebuilt too.
    let refresh_views = additive.statements.iter().any(|statement| {
        statement.kind == DdlStatementKind::View && !is_spatial_candidate_view_statement(statement)
    }) || change_set.changes.iter().any(|change| {
        matches!(
            change.code,
            CompiledRegistryChangeCode::EntityRemoved
                | CompiledRegistryChangeCode::FieldAddedRequired
                | CompiledRegistryChangeCode::FieldRemoved
                | CompiledRegistryChangeCode::FieldTypeChanged
                | CompiledRegistryChangeCode::FieldPhysicalNameChanged
                | CompiledRegistryChangeCode::FieldEncryptionChanged
                | CompiledRegistryChangeCode::FieldLookupChanged
                | CompiledRegistryChangeCode::DerivedRelationRemoved
                | CompiledRegistryChangeCode::DerivedRelationChanged
        )
    });
    let mut statements = additive.statements;
    if refresh_views {
        statements.retain(|statement| statement.kind != DdlStatementKind::View);
        // Candidate views depend directly on source columns too. A structural
        // change can require their removal even when the rendered predicate
        // stays identical, so remove them before compiler or reviewed DDL.
        let mut candidate_view_drops = baseline
            .entities
            .values()
            .filter_map(drop_spatial_candidate_view_statement)
            .collect::<Vec<_>>();
        candidate_view_drops.append(&mut statements);
        statements = candidate_view_drops;
        statements.extend(
            candidate
                .ddl()
                .statements
                .iter()
                .filter(|statement| statement.kind == DdlStatementKind::View)
                .cloned(),
        );
    }
    let previous_ddl = generate_ddl_with_actions(
        &baseline.entities,
        &baseline.physical_names,
        &baseline.actions,
    );
    let (_, policy_creates) = successor_managed_policy_delta(&previous_ddl, candidate.ddl());
    statements.extend(policy_creates);
    Ok(MigrationPlan {
        from_package_digest: Some(change_set.from_package_digest.clone()),
        prior_baseline: Some(baseline.clone()),
        changes: change_set.changes.clone(),
        statements,
        reviewed_descriptors: descriptor_paths,
        prior_schema_fingerprint: Some(prior_schema_fingerprint),
    })
}

fn successor_managed_policy_delta(
    previous_ddl: &DdlInventory,
    candidate_ddl: &DdlInventory,
) -> (Vec<DdlStatement>, Vec<DdlStatement>) {
    let previous_tables = previous_ddl
        .tables
        .iter()
        .map(|table| (table.entity_id.as_str(), table))
        .collect::<BTreeMap<_, _>>();
    let candidate_tables = candidate_ddl
        .tables
        .iter()
        .map(|table| (table.entity_id.as_str(), table))
        .collect::<BTreeMap<_, _>>();
    let candidate_policy_statements = candidate_ddl
        .statements
        .iter()
        .filter(|statement| statement.kind == DdlStatementKind::Policy)
        .map(|statement| (statement.id.as_str(), statement))
        .collect::<BTreeMap<_, _>>();

    let mut drops = Vec::new();
    let mut creates = Vec::new();
    for (entity_id, previous_table) in previous_tables {
        let Some(candidate_table) = candidate_tables.get(entity_id) else {
            continue;
        };
        if previous_table.physical_name != candidate_table.physical_name {
            continue;
        }
        let previous_policies = managed_policies(previous_table);
        let candidate_policies = managed_policies(candidate_table);
        let created_policies = reviewed_successor_created_policies(candidate_table);
        for (name, previous_policy) in &previous_policies {
            if candidate_policies.get(name) != Some(previous_policy) {
                drops.push(drop_policy_statement(entity_id, previous_table, name));
            }
        }
        // Runtime ACL reconciliation installs every candidate policy after the
        // complete migration. Keep compiler-plan creates to the reviewed
        // action and change-request policies it historically owned; ordinary
        // and probe policies may refer to columns installed by reviewed SQL.
        for (name, candidate_policy) in created_policies {
            if previous_policies.get(name).copied() == Some(candidate_policy) {
                continue;
            }
            let statement_id = format!("entity.{entity_id}.policy.{name}");
            if let Some(statement) = candidate_policy_statements.get(statement_id.as_str()) {
                creates.push((*statement).clone());
            }
        }
    }
    (drops, creates)
}

fn managed_policies(table: &DdlTable) -> BTreeMap<&str, &DdlPolicy> {
    table
        .policies
        .iter()
        .map(|policy| (policy.name.as_str(), policy))
        .collect()
}

fn reviewed_successor_created_policies(table: &DdlTable) -> BTreeMap<&str, &DdlPolicy> {
    table
        .policies
        .iter()
        .filter(|policy| {
            policy.name.starts_with("registry_action_rls_")
                || policy.name.starts_with("registry_action_link_rls_")
                || policy.name.starts_with("registry_cr_rls_")
                || policy.name.starts_with("registry_cr_presence_rls_")
                || policy.name.starts_with("registry_cr_action_rls_")
        })
        .map(|policy| (policy.name.as_str(), policy))
        .collect()
}

fn drop_policy_statement(entity_id: &str, table: &DdlTable, policy_name: &str) -> DdlStatement {
    // A predecessor baseline may come from an older compiler that did
    // not emit this reconstructed policy. Tolerate absence of this exact name;
    // candidate catalog verification still refuses any unmanaged policies.
    DdlStatement {
        id: format!("entity.{entity_id}.policy.{policy_name}.drop"),
        kind: DdlStatementKind::Policy,
        sql: format!(
            "DROP POLICY IF EXISTS {} ON registry_data.{}",
            quote_sql_identifier(policy_name),
            quote_sql_identifier(&table.physical_name)
        ),
    }
}

fn quote_sql_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn is_spatial_candidate_view_statement(statement: &DdlStatement) -> bool {
    statement.kind == DdlStatementKind::View
        && (statement.id.ends_with(".spatial-candidates-view")
            || statement.id.ends_with(".spatial-candidates-view.drop"))
}

fn table_statement_entity_id(statement_id: &str) -> Option<&str> {
    statement_id
        .strip_prefix("entity.")
        .and_then(|suffix| suffix.strip_suffix(".table"))
}

/// Whether the field's DDL carries a unique blind-index statement. The unique
/// lookup index is content-addressed per entity and field, so gaining or
/// rekeying it is always a new statement id, never a replacement.
fn field_requires_unique_lookup_index(field: &crate::model::CompiledField) -> bool {
    field
        .encryption
        .as_ref()
        .and_then(|encryption| encryption.blind_index.as_ref())
        .is_some_and(|blind| blind.unique)
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
    prepare_package_with_project_assets(request, Vec::new())
}

/// Prepare a package whose project-level governed source declares Rhai planner
/// scripts. The separate argument preserves the existing package build request
/// API while keeping script bytes inside the sealed source closure.
pub fn prepare_package_with_project_assets(
    mut request: PackageBuildRequest,
    mut project_assets: Vec<PackageSourceFile>,
) -> Result<PreparedPackage> {
    request
        .modules
        .sort_by(|left, right| left.id.cmp(&right.id));
    project_assets.sort_by(|left, right| left.path.cmp(&right.path));
    for module in &mut request.modules {
        module
            .assets
            .sort_by(|left, right| left.path.cmp(&right.path));
    }
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
    validate_declared_package_assets(&project, &modules, &project_assets, &request.modules)?;
    let module_assets = package_compiler_assets(&project_assets, &request.modules)?;
    let compiled = compile_project_with_assets(
        &project,
        &modules,
        &module_assets,
        CompileProfile::Production,
    )
    .map_err(|_| PackageError::Derivation)?;
    validate_build_bindings(&request, &project, &compiled)?;
    let from_package_digest = request.from_package_digest.clone();
    #[cfg(feature = "tooling")]
    let request_schema_fingerprint = request.schema_fingerprint.clone();

    let (migration_plan, reviewed_files): (MigrationPlan, BTreeMap<String, Vec<u8>>) =
        match request.migration_plan {
            PackageMigrationPlanInput::InitialCompiledDdl => {
                if from_package_digest.is_some() {
                    return Err(PackageError::MigrationPlan);
                }
                (initial_migration_plan(&compiled), BTreeMap::new())
            }
            PackageMigrationPlanInput::Successor { prior_registry } => {
                let from_package_digest = from_package_digest
                    .as_deref()
                    .ok_or(PackageError::MigrationPlan)?;
                let change_set =
                    compiled_registry_change_set(&prior_registry, &compiled, from_package_digest);
                (
                    change_set_to_applicable_migration_plan(&change_set)?,
                    BTreeMap::new(),
                )
            }
            PackageMigrationPlanInput::SuccessorFromBaseline { prior_baseline } => {
                let from_package_digest = from_package_digest
                    .as_deref()
                    .ok_or(PackageError::MigrationPlan)?;
                if prior_baseline.package_digest != from_package_digest {
                    return Err(PackageError::MigrationPlan);
                }
                let change_set = compiled_registry_change_set_from_baseline(
                    &prior_baseline,
                    &compiled,
                    from_package_digest,
                );
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
                let from_package_digest = from_package_digest
                    .as_deref()
                    .ok_or(PackageError::MigrationPlan)?;
                let baseline = CompiledRegistryMigrationBaseline::from_compiled(
                    from_package_digest,
                    &prior_registry,
                );
                reviewed_successor_inputs(
                    Some(from_package_digest),
                    &request_schema_fingerprint,
                    &compiled,
                    &baseline,
                    prior_schema_fingerprint,
                    migrations,
                )?
            }
            #[cfg(feature = "tooling")]
            PackageMigrationPlanInput::ReviewedSuccessorFromBaseline {
                prior_baseline,
                prior_schema_fingerprint,
                migrations,
            } => reviewed_successor_inputs(
                from_package_digest.as_deref(),
                &request_schema_fingerprint,
                &compiled,
                &prior_baseline,
                prior_schema_fingerprint,
                migrations,
            )?,
        };

    let mut files = BTreeMap::new();
    files.insert(request.project.path.clone(), request.project.bytes.clone());
    for asset in &project_assets {
        let path = package_project_asset_path(&asset.path)?;
        if files.insert(path, asset.bytes.clone()).is_some() {
            return Err(PackageError::Closure);
        }
    }
    for module in &request.modules {
        if files
            .insert(module.path.clone(), module.bytes.clone())
            .is_some()
        {
            return Err(PackageError::Closure);
        }
        for asset in &module.assets {
            let path = package_module_asset_path(&module.id, &asset.path)?;
            if files.insert(path, asset.bytes.clone()).is_some() {
                return Err(PackageError::Closure);
            }
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
    for asset in &project_assets {
        let path = package_project_asset_path(&asset.path)?;
        entries.push(file_entry(
            &path,
            if asset.path.ends_with(".json") {
                PackageFileRole::SourceProjectEvidenceContract
            } else {
                PackageFileRole::SourceProjectPlannerScript
            },
            &asset.bytes,
        )?);
    }
    for module in &request.modules {
        entries.push(file_entry(
            &module.path,
            PackageFileRole::SourceModule,
            &module.bytes,
        )?);
        for asset in &module.assets {
            let path = package_module_asset_path(&module.id, &asset.path)?;
            entries.push(file_entry(
                &path,
                package_module_asset_role(&asset.path)?,
                &asset.bytes,
            )?);
        }
    }
    entries.push(file_entry(
        &request.fixture_journeys.path,
        PackageFileRole::FixtureJourneys,
        &request.fixture_journeys.bytes,
    )?);
    for (path, bytes) in &files {
        if path == &request.project.path
            || path == &request.fixture_journeys.path
            || project_assets.iter().any(|asset| {
                package_project_asset_path(&asset.path).is_ok_and(|asset_path| asset_path == *path)
            })
            || request.modules.iter().any(|module| module.path == *path)
            || request.modules.iter().any(|module| {
                module.assets.iter().any(|asset| {
                    package_module_asset_path(&module.id, &asset.path)
                        .is_ok_and(|asset_path| asset_path == *path)
                })
            })
        {
            continue;
        }
        entries.push(file_entry(path, package_role_for_path(path)?, bytes)?);
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    ensure_unique_file_entries(&entries)?;

    let manifest = PackageManifest {
        package_id: compiled.registry_id().to_owned(),
        compiler: CompilerIdentity {
            id: COMPILER_ID.to_owned(),
            source_revision: request.compiler_source_revision,
            profile: PackageCompileProfile::Production,
        },
        engine_features: current_engine_features(),
        schema_fingerprint: request.schema_fingerprint,
        sources: CapturedSources {
            project: request.project.path,
            project_assets: project_assets
                .into_iter()
                .map(|asset| package_project_asset_path(&asset.path))
                .collect::<Result<Vec<_>>>()?,
            modules: request
                .modules
                .into_iter()
                .map(|module| CapturedModule {
                    assets: module.assets.into_iter().map(|asset| asset.path).collect(),
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
    Ok(PreparedPackage {
        manifest,
        registry: compiled,
        files,
    })
}

#[cfg(feature = "tooling")]
fn reviewed_successor_inputs(
    from_package_digest: Option<&str>,
    schema_fingerprint: &str,
    compiled: &CompiledRegistry,
    baseline: &CompiledRegistryMigrationBaseline,
    prior_schema_fingerprint: String,
    migrations: Vec<ReviewedMigrationSource>,
) -> Result<(MigrationPlan, BTreeMap<String, Vec<u8>>)> {
    let from_package_digest = from_package_digest.ok_or(PackageError::MigrationPlan)?;
    if !valid_digest(&prior_schema_fingerprint) || baseline.package_digest != from_package_digest {
        return Err(PackageError::MigrationPlan);
    }
    let change_set =
        compiled_registry_change_set_from_baseline(baseline, compiled, from_package_digest);
    let reviewed = prepare_reviewed_migration_plan(
        &migrations,
        &ReviewedPlanBindings {
            prior_package_digest: from_package_digest,
            prior_schema_fingerprint: &prior_schema_fingerprint,
            final_schema_fingerprint: schema_fingerprint,
            changes: &change_set.changes,
            prior_entities: &baseline.entities,
            candidate_entities: compiled.entities(),
            prior_physical_names: &baseline.physical_names,
            candidate_physical_names: compiled.physical_names(),
        },
    )
    .map_err(PackageError::ReviewedMigration)?;
    let PreparedReviewedMigrationPlan {
        descriptor_paths,
        files,
    } = reviewed;
    Ok((
        reviewed_successor_migration_plan(
            baseline,
            compiled,
            &change_set,
            descriptor_paths,
            prior_schema_fingerprint,
        )?,
        files,
    ))
}

fn package_compiler_assets(
    project_assets: &[PackageSourceFile],
    modules: &[PackageModuleSource],
) -> Result<Vec<ModuleAssetSource>> {
    let mut assets = Vec::new();
    let mut paths = BTreeSet::new();
    for asset in project_assets {
        validate_project_asset(&asset.path, &asset.bytes)?;
        if !paths.insert((None, asset.path.as_str())) {
            return Err(PackageError::Derivation);
        }
        assets.push(ModuleAssetSource {
            module: None,
            path: asset.path.clone(),
            bytes: asset.bytes.clone(),
        });
    }
    for module in modules {
        validate_relative(&module.id)?;
        for asset in &module.assets {
            validate_relative(&asset.path)?;
            validate_module_asset(&asset.path, &asset.bytes)?;
            if !paths.insert((Some(module.id.as_str()), asset.path.as_str())) {
                return Err(PackageError::Derivation);
            }
            assets.push(ModuleAssetSource {
                module: Some(module.id.clone()),
                path: asset.path.clone(),
                bytes: asset.bytes.clone(),
            });
        }
    }
    Ok(assets)
}

/// The owned asset path a handler declares: its script for Rhai, its module
/// for WASM. None means the handler declares no owned asset, a kind the
/// compiler refuses before this package is rederived.
fn handler_source_path(handler: &crate::contract::ActionHandlerSource) -> Option<&str> {
    handler.script().or_else(|| handler.module())
}

/// The owned asset path a local hook handler declares: its script for `rhai`,
/// its module for `wasm`. A `url` handler holds no program and so owns no
/// asset.
fn hook_handler_source_path(hook: &crate::contract::HookSource) -> Option<&str> {
    match hook.handler.as_ref()? {
        registry_platform_hooks::HookHandlerSource::Rhai { script, .. } => Some(script.as_str()),
        registry_platform_hooks::HookHandlerSource::Wasm { module, .. } => Some(module.as_str()),
        registry_platform_hooks::HookHandlerSource::Url { .. } => None,
    }
}

fn validate_declared_package_assets(
    project: &RegistryProject,
    modules: &[RegistryModule],
    project_assets: &[PackageSourceFile],
    module_sources: &[PackageModuleSource],
) -> Result<()> {
    let declared_project = project
        .entities
        .iter()
        .filter_map(|entity| {
            entity
                .change_request
                .as_ref()
                .and_then(|request| request.planner.as_ref())
                .map(|planner| planner.script.as_str())
        })
        .chain(
            project
                .actions
                .iter()
                .filter_map(|action| action.handler.as_ref().and_then(handler_source_path)),
        )
        .chain(
            project
                .evidence_providers
                .iter()
                .map(|provider| provider.contracts.as_str()),
        )
        .chain(
            project
                .entities
                .iter()
                .flat_map(|entity| entity.hooks.iter())
                .filter_map(hook_handler_source_path),
        )
        .collect::<BTreeSet<_>>();
    let supplied_project = project_assets
        .iter()
        .map(|asset| asset.path.as_str())
        .collect::<BTreeSet<_>>();
    if declared_project != supplied_project || supplied_project.len() != project_assets.len() {
        return Err(PackageError::Derivation);
    }

    let sources_by_id = module_sources
        .iter()
        .map(|module| (module.id.as_str(), module))
        .collect::<BTreeMap<_, _>>();
    for module in modules {
        let source = sources_by_id
            .get(module.id.as_str())
            .ok_or(PackageError::Derivation)?;
        let mut declared = module
            .actions
            .iter()
            .filter_map(|action| action.handler.as_ref().and_then(handler_source_path))
            .collect::<BTreeSet<_>>();
        for entity in &module.entities {
            declared.extend(entity.derived.iter().map(|derived| derived.sql.as_str()));
            declared.extend(entity.hooks.iter().filter_map(hook_handler_source_path));
            if let Some(script) = entity
                .change_request
                .as_ref()
                .and_then(|request| request.planner.as_ref())
                .map(|planner| planner.script.as_str())
            {
                declared.insert(script);
            }
        }
        for extension in &module.extend_entities {
            declared.extend(extension.derived.iter().map(|derived| derived.sql.as_str()));
            declared.extend(extension.hooks.iter().filter_map(hook_handler_source_path));
            if let Some(script) = extension
                .change_request
                .as_ref()
                .and_then(|request| request.planner.as_ref())
                .map(|planner| planner.script.as_str())
            {
                declared.insert(script);
            }
        }
        let supplied = source
            .assets
            .iter()
            .map(|asset| asset.path.as_str())
            .collect::<BTreeSet<_>>();
        if declared != supplied || supplied.len() != source.assets.len() {
            return Err(PackageError::Derivation);
        }
    }
    if sources_by_id.len() != modules.len() {
        return Err(PackageError::Derivation);
    }
    Ok(())
}

fn validate_project_asset(path: &str, bytes: &[u8]) -> Result<()> {
    if crate::action_evidence_contracts::valid_contract_path(path) {
        validate_relative(path)?;
        if !bytes.is_empty()
            && bytes.len() <= crate::action_evidence_contracts::MAX_EVIDENCE_CONTRACT_BYTES
        {
            return Ok(());
        }
        return Err(PackageError::Derivation);
    }
    if path.ends_with(".wasm") {
        return validate_wasm_asset(path, bytes);
    }
    validate_planner_asset(path, bytes)
}

fn validate_planner_asset(path: &str, bytes: &[u8]) -> Result<()> {
    validate_relative(path)?;
    if path.len() > MAX_RHAI_PLANNER_PATH_BYTES
        || !path.ends_with(".rhai")
        || path == "registry.yaml"
        || bytes.is_empty()
        || bytes.len() as u64 > MAX_RHAI_PLANNER_SOURCE_BYTES
    {
        return Err(PackageError::Derivation);
    }
    Ok(())
}

fn validate_wasm_asset(path: &str, bytes: &[u8]) -> Result<()> {
    validate_relative(path)?;
    if path.len() > crate::wasm_handler::MAXIMUM_WASM_MODULE_PATH_BYTES
        || !path.ends_with(".wasm")
        || path == "registry.yaml"
        || bytes.is_empty()
        || bytes.len() > crate::wasm_handler::MAXIMUM_WASM_MODULE_BYTES
    {
        return Err(PackageError::Derivation);
    }
    Ok(())
}

fn validate_module_asset(path: &str, bytes: &[u8]) -> Result<()> {
    validate_relative(path)?;
    match Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
    {
        Some("sql")
            if path != "module.yaml"
                && !bytes.is_empty()
                && bytes.len() <= MAX_DERIVED_SQL_BYTES =>
        {
            Ok(())
        }
        Some("rhai")
            if path != "module.yaml" && bytes.len() as u64 <= MAX_RHAI_PLANNER_SOURCE_BYTES =>
        {
            validate_planner_asset(path, bytes)
        }
        Some("wasm")
            if path != "module.yaml"
                && bytes.len() <= crate::wasm_handler::MAXIMUM_WASM_MODULE_BYTES =>
        {
            validate_wasm_asset(path, bytes)
        }
        _ => Err(PackageError::Derivation),
    }
}

fn package_project_asset_path(asset_path: &str) -> Result<String> {
    validate_relative(asset_path)?;
    if (!asset_path.ends_with(".rhai")
        && !asset_path.ends_with(".wasm")
        && !crate::action_evidence_contracts::valid_contract_path(asset_path))
        || asset_path == "registry.yaml"
    {
        return Err(PackageError::Derivation);
    }
    let path = format!("source/project/{asset_path}");
    validate_relative(&path)?;
    Ok(path)
}

fn project_asset_source_path(package_path: &str) -> Result<&str> {
    validate_relative(package_path)?;
    let source_path = package_path
        .strip_prefix("source/project/")
        .ok_or(PackageError::Derivation)?;
    if package_project_asset_path(source_path)? != package_path {
        return Err(PackageError::Derivation);
    }
    Ok(source_path)
}

fn package_module_asset_path(module_id: &str, asset_path: &str) -> Result<String> {
    validate_relative(module_id)?;
    validate_relative(asset_path)?;
    if (!asset_path.ends_with(".sql")
        && !asset_path.ends_with(".rhai")
        && !asset_path.ends_with(".wasm"))
        || asset_path == "module.yaml"
    {
        return Err(PackageError::Derivation);
    }
    let path = format!("source/modules/{module_id}/{asset_path}");
    validate_relative(&path)?;
    Ok(path)
}

fn package_module_asset_role(asset_path: &str) -> Result<PackageFileRole> {
    if asset_path.ends_with(".sql") {
        Ok(PackageFileRole::SourceModuleAsset)
    } else if asset_path.ends_with(".rhai") {
        Ok(PackageFileRole::SourceModulePlannerScript)
    } else if asset_path.ends_with(".wasm") {
        // A module-owned WASM handler binary rides the generic module asset
        // role; only the project-level handler source keeps its own role.
        Ok(PackageFileRole::SourceModuleAsset)
    } else {
        Err(PackageError::Derivation)
    }
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
    if !compiled.actions().is_empty() {
        insert_json_file(files, "inventories/actions.json", compiled.actions())?;
    }
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
    let registry_manifest = compiled
        .artifacts()
        .get("generated/manifest/registry-manifest.json");
    let dcat = compiled.artifacts().get("generated/manifest/dcat.jsonld");
    match (compiled.manifest_projection(), registry_manifest, dcat) {
        (Some(_), Some(registry_manifest), Some(dcat)) => {
            insert_generated(
                files,
                "manifest/registry-manifest.json",
                registry_manifest.bytes.clone(),
            )?;
            insert_generated(files, "manifest/dcat.jsonld", dcat.bytes.clone())?;
        }
        (None, None, None) => {}
        _ => return Err(PackageError::Derivation),
    }
    for (path, artifact) in compiled.artifacts().entries() {
        if let Some(schema_name) = path.strip_prefix("generated/action-schemas/") {
            insert_generated(
                files,
                &format!("action-schemas/{schema_name}"),
                artifact.bytes.clone(),
            )?;
            continue;
        }
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
            ReviewedArtifactKind::Fixture => PackageFileRole::MigrationRehearsalFixture,
        });
    }
    Ok(match path {
        FIXTURE_JOURNEYS_PATH => PackageFileRole::FixtureJourneys,
        path if path.starts_with("source/project/") && path.ends_with(".json") => {
            PackageFileRole::SourceProjectEvidenceContract
        }
        path if path.starts_with("source/project/") && path.ends_with(".rhai") => {
            PackageFileRole::SourceProjectPlannerScript
        }
        // Project-owned WASM handler modules travel as project handler
        // source; no separate role exists for the binary form.
        path if path.starts_with("source/project/") && path.ends_with(".wasm") => {
            PackageFileRole::SourceProjectPlannerScript
        }
        path if path.starts_with("source/modules/")
            && path.ends_with(".sql")
            && !path.ends_with("/module.yaml") =>
        {
            PackageFileRole::SourceModuleAsset
        }
        path if path.starts_with("source/modules/")
            && path.ends_with(".wasm")
            && !path.ends_with("/module.yaml") =>
        {
            PackageFileRole::SourceModuleAsset
        }
        path if path.starts_with("source/modules/")
            && path.ends_with(".rhai")
            && !path.ends_with("/module.yaml") =>
        {
            PackageFileRole::SourceModulePlannerScript
        }
        "effective-model.json" => PackageFileRole::GovernedModel,
        "inventories/physical-names.json" => PackageFileRole::PhysicalNameInventory,
        "inventories/routes.json" => PackageFileRole::RouteInventory,
        "inventories/access.json" => PackageFileRole::AccessInventory,
        "inventories/queries.json" => PackageFileRole::QueryInventory,
        "inventories/events.json" => PackageFileRole::EventInventory,
        "inventories/actions.json" => PackageFileRole::ActionInventory,
        "metadata/registry.json" => PackageFileRole::CallerSafeMetadata,
        "database/ddl.sql" => PackageFileRole::GeneratedDdl,
        "database/migration-plan.json" => PackageFileRole::MigrationPlan,
        "openapi/openapi.json" => PackageFileRole::GeneratedOpenapi,
        path if path.starts_with("schemas/") && path.ends_with(".schema.json") => {
            PackageFileRole::EntityJsonSchema
        }
        path if path.starts_with("action-schemas/") && path.ends_with(".schema.json") => {
            PackageFileRole::ActionJsonSchema
        }
        "manifest/registry-manifest.json" => PackageFileRole::LossyManifestProjection,
        "manifest/dcat.jsonld" => PackageFileRole::DcatCatalogProjection,
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
    if request.compiler_source_revision.is_empty()
        || !valid_digest(&request.schema_fingerprint)
        || request
            .from_package_digest
            .as_deref()
            .is_some_and(|digest| !valid_digest(digest))
    {
        return Err(PackageError::Binding);
    }
    Ok(())
}

/// The closed grammar the envelope wrapper proof budgets: no byte serde_json
/// escapes, at most `compiler::MAX_BUILD_ID_BYTES` of them.
pub(crate) fn valid_build_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::compiler::MAX_BUILD_ID_BYTES as usize
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn validate_build_bindings(
    request: &PackageBuildRequest,
    project: &RegistryProject,
    compiled: &CompiledRegistry,
) -> Result<()> {
    let identity = project.package.as_ref().ok_or(PackageError::Derivation)?;
    if project.registry.id != compiled.registry_id()
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

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    reject_symlink_components(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| PackageError::Closure)?;
    file.write_all(bytes).map_err(|_| PackageError::Read)?;
    file.sync_all().map_err(|_| PackageError::Read)?;
    set_safe_file_permissions(path)
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

/// Load one package from the caller-selected local root. This function performs
/// no network resolution and must complete before a database mutation or
/// listener construction is attempted.
pub fn load_package(root: &Path, context: &PackageLoadContext<'_>) -> Result<VerifiedPackage> {
    let shared = verify_shared_package(root)?;
    load_package_with_verified_envelope(root, context, &shared)
}

/// Load the BReg package whose complete shared envelope was just verified.
/// The package carries no deployment binding: its identity is the digest of
/// its sum file, which the caller compares with the database's active
/// package.
pub fn load_package_with_verified_envelope(
    root: &Path,
    context: &PackageLoadContext<'_>,
    shared: &SharedVerifiedPackage,
) -> Result<VerifiedPackage> {
    let production = context.database_initialization_environment != "local";
    let (manifest, _, loaded) =
        load_verified_closure(root, shared, production, EnvelopeRead::Current)?;
    let (registry, reviewed_migration_plan) = rederive(&manifest, &loaded)?;

    Ok(VerifiedPackage {
        manifest,
        registry,
        package_digest: shared.digest().to_owned(),
        reviewed_migration_plan,
    })
}

/// Verify the shared envelope of the package at `root` and return its
/// digest, the package identity every activation and startup check names.
pub fn verify_shared_package(root: &Path) -> Result<SharedVerifiedPackage> {
    registry_platform_config::package::verify_package(
        root,
        &shared_package_limits(),
        "bregctl package",
    )
    .map_err(shared_package_error)
}

fn shared_package_error(error: registry_platform_config::package::PackageError) -> PackageError {
    match error.kind() {
        // A symbolic-link, missing, or special package root or entry is a
        // path refusal, so operators get the path fix rather than a rebuild.
        registry_platform_config::package::PackageErrorKind::RootInvalid { .. }
        | registry_platform_config::package::PackageErrorKind::UnsafeEntry { .. } => {
            PackageError::UnsafePath
        }
        _ => PackageError::Envelope,
    }
}

fn bind_shared_file(shared: &SharedVerifiedPackage, relative: &str, bytes: &[u8]) -> Result<()> {
    if shared.file_digest(relative).as_deref() != Some(digest(bytes).as_str()) {
        return Err(PackageError::Envelope);
    }
    Ok(())
}

fn bind_shared_envelope_files(
    root: &Path,
    shared: &SharedVerifiedPackage,
    production: bool,
) -> Result<()> {
    let sums = read_bounded_regular(&root.join(SUM_FILE), MAX_MANIFEST_BYTES, production)?;
    if digest(&sums) != shared.digest() {
        return Err(PackageError::Envelope);
    }
    if shared.file_digest(REVISION_FILE).is_some() {
        let revision = read_bounded_regular(&root.join(REVISION_FILE), 257, production)?;
        bind_shared_file(shared, REVISION_FILE, &revision)?;
    }
    Ok(())
}

/// Which package apiVersions one read accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnvelopeRead {
    /// A package to start, check, inspect, or activate: only the apiVersion
    /// this release writes.
    Current,
    /// A deployed predecessor, which the operator cannot rebuild without
    /// losing the digest the database names: the retired apiVersion too.
    Predecessor,
}

/// Parse a package manifest under the apiVersions `read` accepts, returning
/// the manifest and whether it carries the retired apiVersion. A retired
/// package outside a predecessor read is refused with the current apiVersion
/// named; any other apiVersion, or a `kind` other than `BRegPackage`, is an
/// integrity failure, since a package is generated and never edited.
fn parse_package_envelope(bytes: &[u8], read: EnvelopeRead) -> Result<(PackageManifest, bool)> {
    let mut value: Value = parse_canonical(bytes)?;
    if read == EnvelopeRead::Predecessor {
        if let Some(baseline) = value.pointer_mut("/manifest/migrationPlan/priorBaseline") {
            retire_predecessor_anonymous(
                baseline,
                &["entities", "statisticalDatasets"],
                "/actions/actions",
            )?;
        }
    }
    let (manifest, retired) = match value.get("apiVersion").and_then(Value::as_str) {
        Some(PACKAGE_API_VERSION) => {
            let envelope: PackageEnvelope =
                serde_json::from_value(value).map_err(|_| PackageError::CanonicalJson)?;
            if envelope.kind != PACKAGE_KIND {
                return Err(PackageError::Integrity);
            }
            (envelope.manifest, false)
        }
        Some(RETIRED_PACKAGE_API_VERSION) if read == EnvelopeRead::Predecessor => {
            let envelope: RetiredPackageEnvelope =
                serde_json::from_value(value).map_err(|_| PackageError::CanonicalJson)?;
            (envelope.manifest, true)
        }
        Some(RETIRED_PACKAGE_API_VERSION) => return Err(PackageError::RetiredApiVersion),
        _ => return Err(PackageError::Integrity),
    };
    if manifest.files.is_empty() || manifest.files.len() > MAX_PACKAGE_FILES {
        return Err(PackageError::Integrity);
    }
    Ok((manifest, retired))
}

/// Read the manifest and every listed file of a package whose shared envelope
/// was verified, binding each byte to the sum file and the manifest. The
/// returned flag says whether the manifest carries the retired apiVersion,
/// which only a predecessor read accepts.
fn load_verified_closure(
    root: &Path,
    shared: &SharedVerifiedPackage,
    production: bool,
    read: EnvelopeRead,
) -> Result<(PackageManifest, bool, BTreeMap<String, Vec<u8>>)> {
    validate_root(root)?;
    if production {
        ensure_safe_permissions(root)?;
    }
    bind_shared_envelope_files(root, shared, production)?;

    let manifest_path = root.join(MANIFEST_PATH);
    let manifest_bytes = read_bounded_regular(&manifest_path, MAX_MANIFEST_BYTES, production)?;
    bind_shared_file(shared, MANIFEST_PATH, &manifest_bytes)?;
    let (manifest, retired) = parse_package_envelope(&manifest_bytes, read)?;
    validate_intrinsic_bindings(&manifest)?;
    let loaded = load_closure(
        root,
        &manifest.files,
        manifest_bytes.len(),
        production,
        shared,
    )?;
    Ok((manifest, retired, loaded))
}

/// Rederive a closed package for integrity-only comparison. Safe permissions
/// are mandatory. The returned type carries no startup or activation
/// authority.
pub fn inspect_package_integrity(root: &Path) -> Result<IntegrityInspectedPackage> {
    let shared = verify_shared_package(root)?;
    inspect_package_integrity_with_verified_envelope(root, &shared)
}

/// Inspect a BReg package through the retained shared envelope verification
/// that selected it.
pub fn inspect_package_integrity_with_verified_envelope(
    root: &Path,
    shared: &SharedVerifiedPackage,
) -> Result<IntegrityInspectedPackage> {
    let (manifest, _, loaded) = load_verified_closure(root, shared, true, EnvelopeRead::Current)?;
    let (registry, _reviewed_migration_plan) = rederive(&manifest, &loaded)?;
    #[cfg(feature = "tooling")]
    let migration = migration_inspection_summary(&manifest, _reviewed_migration_plan.as_ref())?;

    Ok(IntegrityInspectedPackage {
        package_digest: shared.digest().to_owned(),
        schema_fingerprint: manifest.schema_fingerprint,
        registry,
        #[cfg(feature = "tooling")]
        migration,
    })
}

/// Verify a predecessor package for read-only successor planning.
///
/// The predecessor's filesystem closure is verified against its sum file and
/// manifest. The caller compares the returned package digest with the
/// database's active package, or names the predecessor directly with
/// `--baseline-package`. Historical generated artifacts are not rederived
/// with the current compiler; only the packaged governed model is parsed from
/// the verified closure to expose a baseline.
pub fn load_predecessor_package(
    root: &Path,
    context: &PackageLoadContext<'_>,
) -> Result<VerifiedPredecessorPackage> {
    let shared = verify_shared_package(root)?;
    load_predecessor_package_with_verified_envelope(root, context, &shared)
}

/// Load a predecessor from the same shared envelope verification used to
/// select it.
pub fn load_predecessor_package_with_verified_envelope(
    root: &Path,
    context: &PackageLoadContext<'_>,
    shared: &SharedVerifiedPackage,
) -> Result<VerifiedPredecessorPackage> {
    load_predecessor_closure(root, context, shared).map(|(package, _)| package)
}

/// Verify a predecessor package exactly as [`load_predecessor_package`] does,
/// then compile its packaged sources with the current compiler so a successor
/// can be rehearsed over the predecessor's schema. The historical generated
/// artifacts are still not compared: the rehearsal instead holds the installed
/// schema to the packaged predecessor fingerprint, and refuses when the
/// current compiler cannot reproduce it.
#[cfg(feature = "tooling")]
pub fn load_predecessor_rehearsal_baseline(
    root: &Path,
    context: &PackageLoadContext<'_>,
) -> Result<(VerifiedPredecessorPackage, CompiledRegistry)> {
    let shared = verify_shared_package(root)?;
    load_predecessor_rehearsal_baseline_with_verified_envelope(root, context, &shared)
}

#[cfg(feature = "tooling")]
pub fn load_predecessor_rehearsal_baseline_with_verified_envelope(
    root: &Path,
    context: &PackageLoadContext<'_>,
    shared: &SharedVerifiedPackage,
) -> Result<(VerifiedPredecessorPackage, CompiledRegistry)> {
    let (package, loaded) = load_predecessor_closure(root, context, shared)?;
    let registry =
        compile_package_sources(&package.manifest, &loaded, SourceSpelling::Predecessor)?;
    Ok((package, registry))
}

fn load_predecessor_closure(
    root: &Path,
    context: &PackageLoadContext<'_>,
    shared: &SharedVerifiedPackage,
) -> Result<(VerifiedPredecessorPackage, BTreeMap<String, Vec<u8>>)> {
    let production = context.database_initialization_environment != "local";
    let (manifest, retired_api_version, loaded) =
        load_verified_closure(root, shared, production, EnvelopeRead::Predecessor)?;
    validate_source_inventory(&manifest)?;
    let governed = package_predecessor_governed_model(&manifest, &loaded)?;
    validate_predecessor_registry_bindings(&manifest, &governed)?;
    let package_digest = shared.digest().to_owned();
    let migration_baseline = governed.migration_baseline(&package_digest);
    validate_migration_baseline(&migration_baseline)?;
    let history_schema_descriptor = governed.history_schema_descriptor(&package_digest)?;
    let statistical_release_store_present = manifest
        .engine_features
        .contains(&PackageEngineFeature::StatisticalReleaseStore);

    Ok((
        VerifiedPredecessorPackage {
            manifest,
            package_digest,
            migration_baseline,
            history_schema_descriptor,
            statistical_release_store_present,
            retired_api_version,
        },
        loaded,
    ))
}

#[cfg(feature = "tooling")]
fn migration_inspection_summary(
    manifest: &PackageManifest,
    reviewed_plan: Option<&ValidatedReviewedMigrationPlan>,
) -> Result<MigrationInspectionSummary> {
    let plan = &manifest.migration_plan;
    let plan_kind = if !plan.reviewed_descriptors.is_empty() {
        MigrationInspectionPlanKind::Reviewed
    } else if plan.from_package_digest.is_some() {
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
        has_predecessor: plan.from_package_digest.is_some(),
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
            }
            | ReviewedMigrationStepDescriptor::FieldEncryptionBackfill {
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

fn validate_intrinsic_bindings(manifest: &PackageManifest) -> Result<()> {
    if manifest.package_id.is_empty()
        || manifest.compiler.id != COMPILER_ID
        || manifest.compiler.source_revision.is_empty()
        || manifest.compiler.profile != PackageCompileProfile::Production
        || !valid_digest(&manifest.schema_fingerprint)
        || manifest
            .migration_plan
            .from_package_digest
            .as_deref()
            .is_some_and(|digest| !valid_digest(digest))
    {
        return Err(PackageError::Binding);
    }
    Ok(())
}

struct PredecessorGovernedModel {
    registry_id: String,
    version: String,
    model_revision: String,
    entities: BTreeMap<String, CompiledEntity>,
    statistical_datasets: BTreeMap<String, CompiledStatisticalDataset>,
    physical_names: PhysicalNameInventory,
    routes: CompiledRouteInventory,
    access: CompiledAccessInventory,
    queries: CompiledQueryInventory,
    actions: CompiledActionInventory,
    recipients: CompiledRecipients,
}

impl PredecessorGovernedModel {
    fn migration_baseline(&self, package_digest: &str) -> CompiledRegistryMigrationBaseline {
        CompiledRegistryMigrationBaseline {
            package_digest: package_digest.to_owned(),
            registry_id: self.registry_id.clone(),
            registry_version: self.version.clone(),
            registry_revision: self.model_revision.clone(),
            entities: self.entities.clone(),
            statistical_datasets: self.statistical_datasets.clone(),
            physical_names: self.physical_names.clone(),
            routes: self.routes.clone(),
            access: self.access.clone(),
            queries: self.queries.clone(),
            actions: self.actions.clone(),
            recipients: self.recipients.clone(),
        }
    }

    fn history_schema_descriptor(&self, package_digest: &str) -> Result<HistorySchemaDescriptor> {
        let descriptor = HistorySchemaDescriptor {
            encoding_version: HISTORY_SCHEMA_ENCODING_VERSION.to_owned(),
            registry_id: self.registry_id.clone(),
            package_revision: package_digest.to_owned(),
            lifecycle: HistoryLifecycleDescriptor {
                source: HistoryLifecycleSource::RevisionJournalRecordLifecycle,
                active_value: "active".to_owned(),
                tombstoned_value: "tombstoned".to_owned(),
            },
            entities: self
                .entities
                .values()
                .map(|entity| (entity.id.clone(), HistoryEntityDescriptor::from(entity)))
                .collect(),
        };
        serialize_descriptor(&descriptor).map_err(|_| PackageError::Derivation)?;
        Ok(descriptor)
    }
}

fn package_predecessor_governed_model(
    manifest: &PackageManifest,
    loaded: &BTreeMap<String, Vec<u8>>,
) -> Result<PredecessorGovernedModel> {
    let entry = unique_manifest_file(manifest, PackageFileRole::GovernedModel)?;
    let bytes = loaded.get(&entry.path).ok_or(PackageError::Closure)?;
    let mut value = parse_canonical::<Value>(bytes).map_err(|_| PackageError::Derivation)?;
    retire_predecessor_anonymous(
        &mut value,
        &["entities", "statisticalDatasets"],
        "/actionInventory/actions",
    )?;

    let registry_id = required_str(&value, "registryId")?.to_owned();
    let version = required_str(&value, "version")?.to_owned();
    let mut entities = value
        .get("entities")
        .cloned()
        .ok_or(PackageError::Derivation)?;
    restore_effective_model_planner_origins(&mut entities).ok_or(PackageError::Derivation)?;
    let entities: BTreeMap<String, CompiledEntity> =
        serde_json::from_value(entities).map_err(|_| PackageError::Derivation)?;
    let statistical_datasets: BTreeMap<String, CompiledStatisticalDataset> = value
        .get("statisticalDatasets")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| PackageError::Derivation)?
        .unwrap_or_default();
    let effective_physical_names: PhysicalNameInventory = serde_json::from_value(
        value
            .get("physicalNames")
            .cloned()
            .ok_or(PackageError::Derivation)?,
    )
    .map_err(|_| PackageError::Derivation)?;
    let effective_queries: CompiledQueryInventory = serde_json::from_value(
        value
            .get("queryInventory")
            .cloned()
            .ok_or(PackageError::Derivation)?,
    )
    .map_err(|_| PackageError::Derivation)?;
    let effective_actions: CompiledActionInventory = value
        .get("actionInventory")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| PackageError::Derivation)?
        .unwrap_or_default();
    let recipients: CompiledRecipients = value
        .get("recipients")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| PackageError::Derivation)?
        .unwrap_or_default();

    let physical_names: PhysicalNameInventory =
        packaged_manifest_json(manifest, loaded, PackageFileRole::PhysicalNameInventory)?;
    let routes: CompiledRouteInventory =
        packaged_manifest_json(manifest, loaded, PackageFileRole::RouteInventory)?;
    let access: CompiledAccessInventory =
        packaged_manifest_json(manifest, loaded, PackageFileRole::AccessInventory)?;
    let queries: CompiledQueryInventory =
        packaged_manifest_json(manifest, loaded, PackageFileRole::QueryInventory)?;
    let mut action_entries = manifest
        .files
        .iter()
        .filter(|entry| entry.role == PackageFileRole::ActionInventory);
    let actions = match action_entries.next() {
        Some(entry) => {
            if action_entries.next().is_some() {
                return Err(PackageError::Derivation);
            }
            let bytes = loaded.get(&entry.path).ok_or(PackageError::Closure)?;
            let mut value =
                parse_canonical::<Value>(bytes).map_err(|_| PackageError::Derivation)?;
            retire_predecessor_anonymous(&mut value, &[], "/actions")?;
            serde_json::from_value(value).map_err(|_| PackageError::Derivation)?
        }
        None => CompiledActionInventory::default(),
    };

    if effective_physical_names != physical_names
        || effective_queries != queries
        || effective_actions != actions
    {
        return Err(PackageError::Derivation);
    }
    validate_predecessor_temporal_value_kinds(&entities, &queries)?;

    Ok(PredecessorGovernedModel {
        registry_id,
        version,
        model_revision: entry.sha256.clone(),
        entities,
        statistical_datasets,
        physical_names,
        routes,
        access,
        queries,
        actions,
        recipients,
    })
}

/// Packages an earlier release built carry an `anonymous` member on every
/// compiled access profile and action permission. This release serves
/// authenticated callers only, so a predecessor read removes the member where
/// it is `false`, letting the current types read the model it describes. A
/// predecessor that granted unauthenticated access is refused: a successor
/// planned over that baseline would keep row policies that admit a caller
/// without a principal.
///
/// `profile_owners` name the members of `value` that map an owner to its
/// `accessProfiles`; `actions` points at the compiled action list.
fn retire_predecessor_anonymous(
    value: &mut Value,
    profile_owners: &[&str],
    actions: &str,
) -> Result<()> {
    fn retire(member: &mut Value) -> Result<()> {
        match member
            .as_object_mut()
            .and_then(|member| member.remove("anonymous"))
        {
            None | Some(Value::Bool(false)) => Ok(()),
            Some(_) => Err(PackageError::Derivation),
        }
    }
    for owners in profile_owners {
        let Some(owners) = value.get_mut(*owners).and_then(Value::as_object_mut) else {
            continue;
        };
        for owner in owners.values_mut() {
            let Some(profiles) = owner
                .get_mut("accessProfiles")
                .and_then(Value::as_object_mut)
            else {
                continue;
            };
            for profile in profiles.values_mut() {
                retire(profile)?;
            }
        }
    }
    if let Some(actions) = value.pointer_mut(actions).and_then(Value::as_array_mut) {
        for action in actions {
            let Some(permissions) = action.get_mut("permissions").and_then(Value::as_array_mut)
            else {
                continue;
            };
            for permission in permissions {
                retire(permission)?;
            }
        }
    }
    Ok(())
}

fn packaged_manifest_json<T: for<'de> Deserialize<'de>>(
    manifest: &PackageManifest,
    loaded: &BTreeMap<String, Vec<u8>>,
    role: PackageFileRole,
) -> Result<T> {
    let value = packaged_manifest_value(manifest, loaded, role)?;
    serde_json::from_value(value).map_err(|_| PackageError::Derivation)
}

fn packaged_manifest_value(
    manifest: &PackageManifest,
    loaded: &BTreeMap<String, Vec<u8>>,
    role: PackageFileRole,
) -> Result<Value> {
    let entry = unique_manifest_file(manifest, role)?;
    let bytes = loaded.get(&entry.path).ok_or(PackageError::Closure)?;
    parse_canonical(bytes).map_err(|_| PackageError::Derivation)
}

fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(PackageError::Derivation)
}

fn validate_predecessor_temporal_value_kinds(
    entities: &BTreeMap<String, CompiledEntity>,
    queries: &CompiledQueryInventory,
) -> Result<()> {
    for operation in &queries.operations {
        let Some(temporal) = &operation.temporal else {
            continue;
        };
        let entity = entities
            .get(&operation.entity_id)
            .ok_or(PackageError::Derivation)?;
        let expected =
            temporal_value_kind_for_fields(entity, &temporal.start_field, &temporal.end_field)?;
        if temporal.value_kind != expected {
            return Err(PackageError::Derivation);
        }
    }
    Ok(())
}

fn temporal_value_kind_for_fields(
    entity: &CompiledEntity,
    start_field: &str,
    end_field: &str,
) -> Result<CompiledQueryTemporalValueKind> {
    let start = entity
        .fields
        .get(start_field)
        .ok_or(PackageError::Derivation)?;
    let end = entity
        .fields
        .get(end_field)
        .ok_or(PackageError::Derivation)?;
    match (&start.field_type, &end.field_type) {
        (FieldTypeSource::Date, FieldTypeSource::Date) => Ok(CompiledQueryTemporalValueKind::Date),
        (FieldTypeSource::Timestamp, FieldTypeSource::Timestamp) => {
            Ok(CompiledQueryTemporalValueKind::Timestamp)
        }
        _ => Err(PackageError::Derivation),
    }
}

fn unique_manifest_file(manifest: &PackageManifest, role: PackageFileRole) -> Result<&PackageFile> {
    let mut matches = manifest.files.iter().filter(|entry| entry.role == role);
    let entry = matches.next().ok_or(PackageError::Derivation)?;
    if matches.next().is_some() {
        return Err(PackageError::Derivation);
    }
    Ok(entry)
}

fn validate_predecessor_registry_bindings(
    manifest: &PackageManifest,
    governed: &PredecessorGovernedModel,
) -> Result<()> {
    if governed.registry_id != manifest.package_id {
        return Err(PackageError::Derivation);
    }
    Ok(())
}

fn load_closure(
    root: &Path,
    entries: &[PackageFile],
    manifest_size: usize,
    production: bool,
    shared: &SharedVerifiedPackage,
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
        bind_shared_file(shared, &entry.path, &bytes)?;
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
    let shared_files = shared.files().map(str::to_owned).collect::<BTreeSet<_>>();
    if shared_files.contains(REVISION_FILE) {
        expected.insert(REVISION_FILE.to_owned());
    }
    if shared_files != expected {
        return Err(PackageError::Envelope);
    }
    expected.insert(SUM_FILE.to_owned());
    if actual != expected {
        return Err(PackageError::Closure);
    }
    Ok(loaded)
}

/// How packaged authored sources are read.
#[derive(Clone, Copy)]
enum SourceSpelling {
    /// The spellings this release writes. Anything else is refused.
    Current,
    /// A predecessor's sources, which an earlier release wrote. Access members
    /// it spelled as an empty list read with the meaning that release gave
    /// them, so a rehearsal can compile the predecessor it replaces.
    Predecessor,
}

/// Rewrite the access spellings an earlier release wrote into the ones this
/// release reads, keeping their meaning: an empty `rowBoundaries` reached
/// every row, and an omitted or empty `requiredScopes` demanded no scope, so
/// both become `unrestricted`; an empty narrowing list narrowed nothing, so it
/// is omitted. Only a predecessor read calls this; a current source keeps
/// refusing the empty list.
fn retired_access_spellings_read(bytes: &[u8]) -> Result<Vec<u8>> {
    fn unrestricted_rows(owner: &mut Value) {
        let Some(owner) = owner.as_object_mut() else {
            return;
        };
        if owner.get("rowBoundaries").is_some_and(is_empty_list) {
            owner.insert("rowBoundaries".into(), json!("unrestricted"));
        }
    }
    // An earlier release wrote an absent optional member as `null`.
    fn without_nulls(value: &mut Value) {
        match value {
            Value::Object(members) => {
                members.retain(|_, member| !member.is_null());
                members.values_mut().for_each(without_nulls);
            }
            Value::Array(items) => items.iter_mut().for_each(without_nulls),
            _ => {}
        }
    }
    fn is_empty_list(value: &Value) -> bool {
        value.as_array().is_some_and(Vec::is_empty)
    }
    // `anonymous: false` said nothing; `anonymous: true` stays, and the reader
    // refuses it.
    fn retire_unauthenticated_false(members: &mut serde_json::Map<String, Value>) {
        if members.get("anonymous") == Some(&Value::Bool(false)) {
            members.remove("anonymous");
        }
    }
    fn profile(profile: &mut Value) {
        let Some(members) = profile.as_object_mut() else {
            return;
        };
        retire_unauthenticated_false(members);
        if members.get("requiredScopes").is_none_or(is_empty_list) {
            members.insert("requiredScopes".into(), json!("unrestricted"));
        }
        for narrowing in ["requiredPurposes", "requesterClients"] {
            if members.get(narrowing).is_some_and(is_empty_list) {
                members.remove(narrowing);
            }
        }
        unrestricted_rows(profile);
        for list in ["applyTargets", "requestPresence"] {
            for item in profile
                .get_mut(list)
                .and_then(Value::as_array_mut)
                .into_iter()
                .flatten()
            {
                unrestricted_rows(item);
            }
        }
        for permission in profile
            .get_mut("permissions")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            if let Some(members) = permission.as_object_mut() {
                retire_unauthenticated_false(members);
            }
            // An action has no rows of its own; its targets carry the reach.
            if permission.get("action").is_some() {
                if let Some(members) = permission.as_object_mut() {
                    if members.get("rowBoundaries").is_some_and(is_empty_list) {
                        members.remove("rowBoundaries");
                    }
                }
            } else {
                unrestricted_rows(permission);
            }
            for list in ["applyTargets", "targets"] {
                for item in permission
                    .get_mut(list)
                    .and_then(Value::as_array_mut)
                    .into_iter()
                    .flatten()
                {
                    unrestricted_rows(item);
                }
            }
        }
    }
    fn requirements(owner: &mut Value) {
        let Some(requirements) = owner
            .get_mut("accessRequirements")
            .and_then(Value::as_object_mut)
        else {
            return;
        };
        for narrowing in ["requiredScopes", "allowedPurposes", "rowBoundaries"] {
            if requirements.get(narrowing).is_some_and(is_empty_list) {
                requirements.remove(narrowing);
            }
        }
    }
    #[allow(
        clippy::disallowed_methods,
        reason = "the bytes are a sealed predecessor package the earlier release wrote, not operator configuration; the shared reader reads the rewritten bytes (CFG-YAML-1)"
    )]
    let parsed = serde_norway::from_slice(bytes);
    let mut value: Value = parsed.map_err(|_| PackageError::Derivation)?;
    without_nulls(&mut value);
    for item in value
        .get_mut("accessProfiles")
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
    {
        profile(item);
    }
    for list in ["entities", "extendEntities"] {
        for entity in value
            .get_mut(list)
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            requirements(entity);
            for item in entity
                .get_mut("accessProfiles")
                .and_then(Value::as_array_mut)
                .into_iter()
                .flatten()
            {
                profile(item);
            }
        }
    }
    serde_norway::to_string(&value)
        .map(String::into_bytes)
        .map_err(|_| PackageError::Derivation)
}

fn authored_source(bytes: &[u8], spelling: SourceSpelling) -> Result<Cow<'_, [u8]>> {
    match spelling {
        SourceSpelling::Current => Ok(Cow::Borrowed(bytes)),
        SourceSpelling::Predecessor => retired_access_spellings_read(bytes).map(Cow::Owned),
    }
}

/// Compile the sources of one verified package closure. The caller
/// decides whether generated artifacts must also match byte for byte.
fn compile_package_sources(
    manifest: &PackageManifest,
    loaded: &BTreeMap<String, Vec<u8>>,
    spelling: SourceSpelling,
) -> Result<CompiledRegistry> {
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
    let project = parse_project_yaml(&authored_source(project_bytes, spelling)?)
        .map_err(|_| PackageError::Derivation)?;
    let modules = manifest
        .sources
        .modules
        .iter()
        .map(|source| {
            loaded
                .get(&source.path)
                .ok_or(PackageError::Derivation)
                .and_then(|bytes| {
                    parse_module_yaml(&authored_source(bytes, spelling)?)
                        .map_err(|_| PackageError::Derivation)
                })
        })
        .collect::<Result<Vec<RegistryModule>>>()?;
    let module_assets = captured_compiler_assets(manifest, loaded)?;
    let project_assets = module_assets
        .iter()
        .filter(|asset| asset.module.is_none())
        .map(|asset| PackageSourceFile {
            path: asset.path.clone(),
            bytes: asset.bytes.clone(),
        })
        .collect::<Vec<_>>();
    let module_sources = manifest
        .sources
        .modules
        .iter()
        .map(|source| PackageModuleSource {
            id: source.id.clone(),
            path: source.path.clone(),
            bytes: Vec::new(),
            assets: module_assets
                .iter()
                .filter(|asset| asset.module.as_deref() == Some(source.id.as_str()))
                .map(|asset| PackageSourceFile {
                    path: asset.path.clone(),
                    bytes: asset.bytes.clone(),
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    validate_declared_package_assets(&project, &modules, &project_assets, &module_sources)?;
    validate_captured_bindings(manifest, &project, &modules)?;
    let compiled = compile_project_with_assets(
        &project,
        &modules,
        &module_assets,
        CompileProfile::Production,
    )
    .map_err(|_| PackageError::Derivation)?;
    if compiled.registry_id() != manifest.package_id {
        return Err(PackageError::Derivation);
    }
    Ok(compiled)
}

fn rederive(
    manifest: &PackageManifest,
    loaded: &BTreeMap<String, Vec<u8>>,
) -> Result<(CompiledRegistry, Option<ValidatedReviewedMigrationPlan>)> {
    if manifest.engine_features != current_engine_features() {
        return Err(PackageError::Derivation);
    }
    let compiled = compile_package_sources(manifest, loaded, SourceSpelling::Current)?;
    let expected_artifacts = expected_artifact_bytes(manifest, &compiled)?;
    let packaged_artifacts = manifest
        .files
        .iter()
        .filter(|entry| {
            !matches!(
                entry.role,
                PackageFileRole::SourceProject
                    | PackageFileRole::SourceProjectPlannerScript
                    | PackageFileRole::SourceProjectEvidenceContract
                    | PackageFileRole::SourceModule
                    | PackageFileRole::SourceModuleAsset
                    | PackageFileRole::SourceModulePlannerScript
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

fn captured_compiler_assets(
    manifest: &PackageManifest,
    loaded: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<ModuleAssetSource>> {
    let mut assets = Vec::new();
    for package_path in &manifest.sources.project_assets {
        let asset_path = project_asset_source_path(package_path)?;
        let bytes = loaded
            .get(package_path)
            .ok_or(PackageError::Derivation)?
            .clone();
        validate_project_asset(asset_path, &bytes)?;
        assets.push(ModuleAssetSource {
            module: None,
            path: asset_path.to_owned(),
            bytes,
        });
    }
    for module in &manifest.sources.modules {
        for asset_path in &module.assets {
            let package_path = package_module_asset_path(&module.id, asset_path)?;
            let bytes = loaded
                .get(&package_path)
                .ok_or(PackageError::Derivation)?
                .clone();
            validate_module_asset(asset_path, &bytes)?;
            assets.push(ModuleAssetSource {
                module: Some(module.id.clone()),
                path: asset_path.clone(),
                bytes,
            });
        }
    }
    Ok(assets)
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
    let prior_package_digest = manifest
        .migration_plan
        .from_package_digest
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
            prior_package_digest,
            prior_schema_fingerprint,
            final_schema_fingerprint: &manifest.schema_fingerprint,
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
    let mut project_asset_paths = BTreeSet::new();
    let mut prior_project_asset = None;
    for asset in &manifest.sources.project_assets {
        project_asset_source_path(asset)?;
        if prior_project_asset.is_some_and(|prior: &str| prior >= asset.as_str())
            || !project_asset_paths.insert(asset.clone())
        {
            return Err(PackageError::Derivation);
        }
        prior_project_asset = Some(asset.as_str());
    }
    let file_project_asset_paths = manifest
        .files
        .iter()
        .filter(|entry| {
            matches!(
                entry.role,
                PackageFileRole::SourceProjectPlannerScript
                    | PackageFileRole::SourceProjectEvidenceContract
            )
        })
        .map(|entry| entry.path.clone())
        .collect::<BTreeSet<_>>();
    if project_asset_paths != file_project_asset_paths {
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
    let mut asset_paths = BTreeSet::new();
    for module in &manifest.sources.modules {
        validate_relative(&module.path)?;
        if module.id.is_empty()
            || prior_id.is_some_and(|id: &str| id >= module.id.as_str())
            || !module_paths.insert(module.path.as_str())
        {
            return Err(PackageError::Derivation);
        }
        let mut prior_asset = None;
        for asset in &module.assets {
            let package_path = package_module_asset_path(&module.id, asset)?;
            if prior_asset.is_some_and(|prior: &str| prior >= asset.as_str())
                || !asset_paths.insert(package_path)
            {
                return Err(PackageError::Derivation);
            }
            prior_asset = Some(asset.as_str());
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
    let file_asset_paths = manifest
        .files
        .iter()
        .filter(|entry| {
            matches!(
                entry.role,
                PackageFileRole::SourceModuleAsset | PackageFileRole::SourceModulePlannerScript
            )
        })
        .map(|entry| entry.path.clone())
        .collect::<BTreeSet<_>>();
    if asset_paths != file_asset_paths {
        return Err(PackageError::Derivation);
    }
    for module in &manifest.sources.modules {
        for asset in &module.assets {
            let package_path = package_module_asset_path(&module.id, asset)?;
            let expected_role = package_module_asset_role(asset)?;
            if manifest
                .files
                .iter()
                .filter(|entry| entry.path == package_path && entry.role == expected_role)
                .count()
                != 1
            {
                return Err(PackageError::Derivation);
            }
        }
    }
    for entry in &manifest.files {
        if matches!(
            entry.role,
            PackageFileRole::SourceProject
                | PackageFileRole::SourceProjectPlannerScript
                | PackageFileRole::SourceProjectEvidenceContract
                | PackageFileRole::SourceModule
                | PackageFileRole::SourceModuleAsset
                | PackageFileRole::SourceModulePlannerScript
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
    match manifest.migration_plan.from_package_digest.as_deref() {
        None => {
            if manifest.migration_plan.prior_baseline.is_some()
                || !manifest.migration_plan.changes.is_empty()
                || !manifest.migration_plan.reviewed_descriptors.is_empty()
                || manifest.migration_plan.prior_schema_fingerprint.is_some()
            {
                return Err(PackageError::MigrationPlan);
            }
            Ok(initial_migration_plan(compiled))
        }
        Some(from_package_digest) => {
            let baseline = manifest
                .migration_plan
                .prior_baseline
                .as_ref()
                .ok_or(PackageError::MigrationPlan)?;
            if baseline.package_digest != from_package_digest {
                return Err(PackageError::MigrationPlan);
            }
            let change_set =
                compiled_registry_change_set_from_baseline(baseline, compiled, from_package_digest);
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
