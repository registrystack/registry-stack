use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use clap::ValueEnum;
use ed25519_dalek::{Signer as _, SigningKey};
use registry_config_report::{
    ConfigDiagnostic, ConfigDiagnosticReport, ConfigSourceKind, ConfigSourceRef,
    DiagnosticSeverity, DiagnosticSummary, RegistryctlProductReport, RegistryctlProjectRef,
    RegistryctlValidationReport, ReportStatus, REGISTRYCTL_VALIDATION_REPORT_SCHEMA_VERSION_V1,
};
use registry_notary_core::StandaloneRegistryNotaryConfig;
use registry_platform_authcommon::{fingerprint_api_key, validate_api_key_entropy};
use registry_platform_config::{
    sha256_uri, verify_config_bundle, ConfigBundleFile, ConfigBundleManifest,
    ConfigBundleSignature, ConfigBundleSignatureEnvelope, ConfigTrustAnchor,
    ConfigTrustAnchorSigner, MAX_BUNDLE_FILE_BYTES, MAX_CONFIG_BUNDLE_SEQUENCE, MAX_MANIFEST_BYTES,
    MAX_SIGNATURE_ENVELOPE_BYTES, MAX_TRUST_ANCHOR_BYTES,
};
use registry_platform_crypto::{
    canonicalize_json, parse_json_strict, sign as sign_payload, PrivateJwk, PublicJwk,
    SigningAlgorithm, MAX_JWK_JSON_BYTES,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::Zeroizing;

mod project_authoring;

pub use project_authoring::{
    authoring_error_reference, fixture_error_reference, operator_error_reference,
    validate_authoring_error_reference, validate_fixture_error_reference,
    validate_operator_error_reference, AuthoringErrorReferenceV1, ErrorReferenceEntry,
    ErrorReferenceFamily, ErrorReferenceLifecycle, ErrorReferenceOwner, ErrorReferenceProduct,
    ErrorReferenceStability, ErrorReferenceValidationError, ErrorReferenceValuePolicy,
    FixtureErrorReferenceV1, OperatorErrorOmission, OperatorErrorOmissionFamily,
    OperatorErrorOmissionReason, OperatorErrorReferenceV1,
    AUTHORING_ERROR_REFERENCE_SCHEMA_VERSION_V1, FIXTURE_ERROR_REFERENCE_SCHEMA_VERSION_V1,
    OPERATOR_ERROR_REFERENCE_SCHEMA_VERSION_V1,
};
pub use project_authoring::{
    build_project_migration_report, build_project_promotion_report, build_registry_project,
    build_registry_project_with_baselines, build_registry_project_with_baselines_and_context,
    build_registry_project_with_context, check_registry_project,
    check_registry_project_with_context, check_registry_project_with_trusted_local_authored_values,
    embedded_configuration_reference, embedded_configuration_reference_coverage,
    init_registry_project, inspect_project_capabilities, migrate_registry_project,
    migrate_registry_project_with_context, preflight_registry_project, promote_registry_project,
    redacted_project_check_failure_diagnostics, render_project_authoring_diagnostics,
    setup_registry_project_editor, test_registry_project, test_registry_project_selected,
    test_registry_project_selected_with_context, test_registry_project_with_context,
    ArtifactInputClassification, ArtifactInputDigest, AuthoredSemanticFixtureCoverage,
    AuthoringContract, AuthoringVersionSet, CapabilityDisposition, CapabilityId,
    CapabilityInventoryEvidenceGrade, CapabilityInventoryRecord, CapabilityKind,
    CapabilityMaturity, CapabilityOwner, CapabilityUsageCounts, ClassifierSafeReportedValue,
    ConfigurationFieldReference, ConfigurationReferenceCoverageV1, ConfigurationReferenceV1,
    ConfigurationState, CoverageInvariant, CoverageStatus, DefaultBehavior, DefaultDocumentation,
    DocumentationDomainIntent, DocumentationError, DocumentationFieldAddress,
    DocumentationIntentCatalog, DocumentationIntentPolicy, DocumentationSchema,
    DocumentationSchemaAddress, EmptyBehavior,
    EnvironmentBehavior as DocumentationEnvironmentBehavior, EnvironmentEnablementState,
    ExampleDocumentation, FieldIntentOverride, FieldSensitivity, FieldSourceKind,
    FieldTypeDocumentation, FixtureCapability, FixtureCompatibilityClaim,
    FixtureCoverageChangeImpact, FixtureCoverageChangeKind, FixtureCoverageClassification,
    FixtureCoverageComparisonInput, FixtureCoverageDimensions, FixtureCoverageEvidence,
    FixtureCoverageEvidenceKind, FixtureCoverageGapReason, FixtureCoverageNotApplicableReason,
    FixtureCoverageNotEvaluatedReason, FixtureCoverageRequirementCounts,
    FixtureCoverageRequirementState, FixtureCoverageReviewedNotApplicable,
    FixtureCoverageSemanticComparison, FixtureCoverageSummary, FixtureCoverageTarget,
    FixtureCoverageTargetComparisonInput, FixtureCoverageTargetContract,
    FixtureCoverageTargetIdentity, FixtureCoverageTargetSetState, FixtureDisclosureMode,
    FixtureEvidenceScope, FixtureLimit, FixtureMutationTargetClass, FixturePassState,
    FixtureProtocolHelper, FixtureRequestBindingCoverage, FixtureRequestBindingState,
    FixtureRequirementCoverage, FixtureSafeCode, FixtureSemanticExpectation,
    FixtureSemanticOutcome, FixtureSetState, FixtureStatusMapping, FixtureStatusOutcome,
    GeneratedFixtureCoverage, GeneratedNotApplicableReason, GeneratedRecipeApplicability,
    GeneratedSourceFixture, GeneratorRecipe, GeneratorRecipeId, GeneratorRecipeVersion,
    GovernedRequestEvidence, HumanIntentSource, InactiveOrUnusedDeclaration,
    InactiveOrUnusedReason, InstalledCapabilityEvidence, InstalledCapabilityState,
    LiveCompatibilityEvaluation, MigrationAffectedCount, MigrationAffectedState,
    MigrationAffectedSurfaces, MigrationApplicationPolicy, MigrationArtifact,
    MigrationAuthoredFilePolicy, MigrationBlockingReason, MigrationCandidateArtifact,
    MigrationCandidateEligibility, MigrationCandidateEmission, MigrationChange,
    MigrationChangeInput, MigrationCompatibility, MigrationDecisionKind, MigrationDecisionOwner,
    MigrationDecisionScope, MigrationDiagnostic, MigrationDiagnosticCode, MigrationDiagnosticPhase,
    MigrationDiagnosticRemediation, MigrationDisposition, MigrationDocument,
    MigrationEvidenceGrade, MigrationEvidenceLimitation, MigrationExecution, MigrationField,
    MigrationFieldAddress, MigrationFieldClassification, MigrationFieldPath,
    MigrationGateAssessment, MigrationGateResults, MigrationGateStatus, MigrationOperation,
    MigrationOutputMode, MigrationOutputPlan, MigrationOutputRequest, MigrationOwner,
    MigrationReplacement, MigrationReplacementDisposition, MigrationReplacementInput,
    MigrationRerunGate, MigrationReviewAssessment, MigrationReviewClass, MigrationReviewStatus,
    MigrationSafety, MigrationSemanticEffect, MigrationVersionDirection, MigrationVersionSupport,
    MigrationVersionSupportAssessment, MigrationVersionTransition, MigrationWriteAuthority,
    MissingSupport, NullBehavior, PlatformCoverageComponent, PlatformGeneratedCaseId,
    PlatformGeneratedFixtureCoverage, PreflightAttemptState, PreflightCheckState, PreflightContact,
    PreflightDiagnostic, PreflightDiagnosticCode, PreflightDiagnosticMessage,
    PreflightExecutionBoundary, PreflightFieldAddress, PreflightGenerationState,
    PreflightJsonPointer, PreflightMode, PreflightPermissionInvariant, PreflightPhase,
    PreflightProduct, PreflightProductCapability, PreflightProductValidatorCheck,
    PreflightProjectRelativeFile, PreflightRemediation, PreflightReportLimits, PreflightRuleId,
    PreflightRuntimeBoundary, PreflightRuntimeFileCheck, PreflightRuntimeFileKind,
    PreflightRuntimeScope, PreflightSecretCheck, PreflightSecretConsumer, PreflightSeverity,
    PreflightStaticCapability, PreflightStaticCheck, PreflightStatus, PreflightWriteState,
    ProhibitedIntentSource, ProjectArtifactManifestRef, ProjectArtifactManifestV1,
    ProjectAuthoringDiagnostic, ProjectAuthoringDiagnostics, ProjectBuildBaselineSetOptions,
    ProjectBuildOptions, ProjectCapabilityInventoryReportV1,
    ProjectCapabilityInventorySchemaVersion, ProjectCapabilityOptions, ProjectCheckOptions,
    ProjectCommandReport, ProjectCommandReportV1, ProjectDeclarationState,
    ProjectEditorSetupOptions, ProjectEditorSetupReport, ProjectExecutionContext,
    ProjectExplanationReportV1, ProjectFieldAddress, ProjectFieldExplanation,
    ProjectFixtureCoverageReportV1, ProjectFixtureCoverageSchemaVersion, ProjectInitOptions,
    ProjectMigrationBuildError, ProjectMigrationInput, ProjectMigrationOptions,
    ProjectMigrationReportV1, ProjectMigrationSchemaVersion, ProjectPreflightOptions,
    ProjectPreflightReportV1, ProjectPreflightSchemaVersion, ProjectPromotionBuildError,
    ProjectPromotionInput, ProjectPromotionOptions, ProjectPromotionReportV1,
    ProjectPromotionSchemaVersion, ProjectRelativePath, ProjectSchemaKind,
    ProjectSemanticImpactReportV1, ProjectStarter, ProjectTestOptions, ProjectTestSelection,
    ProjectTrustedLocalAuthoredValue, ProjectTrustedLocalCheck, PromotionActivationEvaluation,
    PromotionBlockingReason, PromotionBoundaryAssessment, PromotionChange, PromotionChangeEffect,
    PromotionChangeInput, PromotionChangeKind, PromotionCompatibilityAssessment,
    PromotionCompatibilityComponent, PromotionCompatibilityInput, PromotionCompatibilityState,
    PromotionDeploymentEvaluation, PromotionDisposition, PromotionDocument, PromotionEvidenceGrade,
    PromotionEvidenceLimitation, PromotionFieldAddress, PromotionFieldClassification,
    PromotionFieldOwnership, PromotionFieldPath, PromotionProductAction, PromotionRequiredActions,
    PromotionReviewClass, RedactionReason, ReferenceCoverageSummary, ReferenceSourceContract,
    RequiredFixtureCoverageRequirement, Requiredness, ReviewedCeilingAssessment,
    ReviewedCeilingInput, ReviewedRevisionComparison, RuntimeActivationEvaluation,
    SchemaConstraint, SemanticChange, Sha256Digest, SourceAccessAssertion, SourceCallExpectation,
    StructuralIntent, SupportAssessment, SupportComponent, SupportEvidence, SupportKind,
    SupportState, SupportedCapabilityVersion, TrustResolutionAssessment, TrustResolutionInput,
    UnresolvedMigrationDecision, ValidationStage, VersionChange, VersionHistoryEntry,
    CONFIGURATION_REFERENCE_COVERAGE_SCHEMA_ID, CONFIGURATION_REFERENCE_FORMAT_VERSION,
    CONFIGURATION_REFERENCE_SCHEMA_ID, PROJECT_ARTIFACT_MANIFEST_FORMAT_VERSION_V1,
    PROJECT_ARTIFACT_MANIFEST_SCHEMA_VERSION_V1, PROJECT_CAPABILITY_INVENTORY_SCHEMA_VERSION_V1,
    PROJECT_COMMAND_REPORT_SCHEMA_VERSION_V1, PROJECT_EXPLANATION_SCHEMA_VERSION_V1,
    PROJECT_FIXTURE_COVERAGE_SCHEMA_VERSION_V1, PROJECT_MIGRATION_SCHEMA_VERSION_V1,
    PROJECT_PREFLIGHT_SCHEMA_VERSION_V1, PROJECT_PROMOTION_SCHEMA_VERSION_V1,
    PROJECT_SEMANTIC_IMPACT_SCHEMA_VERSION_V1,
};
pub use project_authoring::{
    compare_registry_project_environments_semantically,
    compare_registry_project_to_embedded_starter_semantically,
    compare_registry_projects_semantically, ProjectEnvironmentSemanticComparisonOptions,
    ProjectSemanticComparisonChange, ProjectSemanticComparisonOptions,
    ProjectSemanticComparisonReportV1, ProjectSemanticComparisonSchemaVersion,
    ProjectStarterSemanticComparisonOptions, SemanticComparisonActivationRequirement,
    SemanticComparisonAffectedSubject, SemanticComparisonAffectedSubjectKind,
    SemanticComparisonAssurance, SemanticComparisonChangeSource, SemanticComparisonConsumer,
    SemanticComparisonDimension, SemanticComparisonDirection, SemanticComparisonEquivalence,
    SemanticComparisonEvidenceGrade, SemanticComparisonEvidenceLimitation,
    SemanticComparisonExternalApproval, SemanticComparisonFieldAddress,
    SemanticComparisonGeneratedArtifact, SemanticComparisonKind, SemanticComparisonPrecision,
    SemanticComparisonRequiredAction, SemanticComparisonRequirements,
    SemanticComparisonRestartRequirement, SemanticComparisonReviewClass,
    SemanticComparisonReviewPlan, SemanticComparisonReviewPlanState,
    SemanticComparisonSchemaFamily, SemanticComparisonSigningRequirement,
    PROJECT_SEMANTIC_COMPARISON_SCHEMA_VERSION_V1,
};

pub use crate::sample::Sample;

mod sample;
mod stored_zip;

const IMAGE_LOCK_SCHEMA_VERSION: &str = "registryctl.release_image_lock.v2";
const IMAGE_LOCK_MAX_BYTES: u64 = 16 * 1024;
const IMAGE_LOCK_PATH_ENV: &str = "REGISTRYCTL_IMAGE_LOCK";
const RELAY_IMAGE_REPOSITORY: &str = "ghcr.io/registrystack/registry-relay";
const NOTARY_IMAGE_REPOSITORY: &str = "ghcr.io/registrystack/registry-notary";
const RELAY_STAGING_IMAGE_REPOSITORY: &str = "ghcr.io/registrystack/registry-relay-candidate";
const NOTARY_STAGING_IMAGE_REPOSITORY: &str = "ghcr.io/registrystack/registry-notary-candidate";
const POSTGRES_IMAGE_REPOSITORY: &str = "docker.io/library/postgres";
const LINUX_AMD64_PLATFORM: &str = "linux/amd64";
const RELAY_BASE_URL: &str = "http://127.0.0.1:4242";
const NOTARY_BASE_URL: &str = "http://127.0.0.1:4255";
const CANONICAL_PROJECT_FILE: &str = "registry-stack.yaml";
const CANONICAL_LOCAL_ENVIRONMENT_FILE: &str = "environments/local.yaml";
const CANONICAL_LOCAL_ENVIRONMENT: &str = "local";
const CANONICAL_BUILD_ROOT: &str = ".registry-stack/build/local";
const CANONICAL_RELAY_CONFIG: &str = ".registry-stack/build/local/private/relay/config/relay.yaml";
const CANONICAL_CONSULTATION_RELAY_CONFIG: &str =
    ".registry-stack/build/local/private/relay/config/relay-consultation.yaml";
const CANONICAL_COMPILED_NOTARY_CONFIG: &str =
    ".registry-stack/build/local/private/notary/config/notary.yaml";
const CANONICAL_ARTIFACT_MANIFEST: &str = ".registry-stack/build/local/artifact-manifest.json";
const CANONICAL_RUNTIME_ROOT: &str = ".registry-stack/runtime/local";
const CANONICAL_RUNTIME_COMPOSE: &str = ".registry-stack/runtime/local/compose.yaml";
const CANONICAL_RUNTIME_MANIFEST: &str = ".registry-stack/runtime/local/manifest.json";
const CANONICAL_RUNTIME_SECRETS: &str = ".registry-stack/runtime/local/secrets";
const CANONICAL_RUNTIME_ENV: &str = ".registry-stack/runtime/local/secrets/local.env";
const CANONICAL_RUNTIME_RELAY_ENV: &str = ".registry-stack/runtime/local/secrets/relay.env";
const CANONICAL_RUNTIME_CONSULTATION_RELAY_ENV: &str =
    ".registry-stack/runtime/local/secrets/relay-consultation.env";
const CANONICAL_RUNTIME_RELAY_BOOTSTRAP_ENV: &str =
    ".registry-stack/runtime/local/secrets/relay-bootstrap.env";
const CANONICAL_RUNTIME_NOTARY_ENV: &str = ".registry-stack/runtime/local/secrets/notary.env";
const CANONICAL_RUNTIME_POSTGRES_ENV: &str = ".registry-stack/runtime/local/secrets/postgres.env";
const CANONICAL_RUNTIME_WORKLOAD_TOKEN: &str =
    ".registry-stack/runtime/local/secrets/relay-workload-token";
const CANONICAL_RUNTIME_NOTARY_CONFIG: &str =
    ".registry-stack/runtime/local/private/notary/config/notary.yaml";
const CANONICAL_RUNTIME_CONSULTATION_RELAY_CONFIG: &str =
    ".registry-stack/runtime/local/private/relay/config/relay-consultation.yaml";
const CANONICAL_RUNTIME_POSTGRES_CA: &str =
    ".registry-stack/runtime/local/private/relay/config/state-plane-ca.pem";
const CANONICAL_RUNTIME_DB_INIT: &str = ".registry-stack/runtime/local/private/db/init.sh";
const CANONICAL_RUNTIME_WORKLOAD_JWKS: &str =
    ".registry-stack/runtime/local/private/workload/jwks.json";
const CANONICAL_RUNTIME_WORKLOAD_PRIVATE_JWK: &str =
    ".registry-stack/runtime/local/secrets/workload-private.jwk";
const CANONICAL_RUNTIME_MANIFEST_SCHEMA: &str = "registryctl.local_runtime.v1";
const CANONICAL_RUNTIME_AUDIT_SECRET_ENV: &str = "REGISTRY_RELAY_AUDIT_HASH_SECRET";
const CANONICAL_RUNTIME_NOTARY_AUDIT_SECRET_ENV: &str = "REGISTRY_NOTARY_AUDIT_HASH_SECRET";
const CANONICAL_RUNTIME_CONSULTATION_AUDIT_SECRET_ENV: &str = "REGISTRY_RELAY_AUDIT_HASH_SECRET";
const CANONICAL_RUNTIME_PSEUDONYM_ENV: &str = "REGISTRY_RELAY_AUDIT_PSEUDONYM_EPOCH_1";
const CANONICAL_RUNTIME_RELAY_DATABASE_URL_ENV: &str = "REGISTRY_RELAY_CONSULTATION_DATABASE_URL";
const CANONICAL_RUNTIME_RELAY_MIGRATION_DATABASE_URL_ENV: &str =
    "REGISTRYCTL_LOCAL_RELAY_MIGRATION_DATABASE_URL";
const CANONICAL_RUNTIME_RELAY_MAINTENANCE_DATABASE_URL_ENV: &str =
    "REGISTRYCTL_LOCAL_RELAY_MAINTENANCE_DATABASE_URL";
const CANONICAL_RUNTIME_RELAY_READER_DATABASE_URL_ENV: &str =
    "REGISTRYCTL_LOCAL_RELAY_READER_DATABASE_URL";
const CANONICAL_RUNTIME_WORKLOAD_JWK_ENV: &str = "REGISTRYCTL_LOCAL_WORKLOAD_PUBLIC_JWK";
const CANONICAL_RUNTIME_NOTARY_SIGNING_JWK_ENV: &str =
    "REGISTRYCTL_LOCAL_NOTARY_EVIDENCE_SIGNING_JWK";
const CANONICAL_RUNTIME_RELAY_DB_PASSWORD_ENV: &str = "REGISTRYCTL_LOCAL_RELAY_DATABASE_PASSWORD";
const CANONICAL_RUNTIME_RELAY_MAINTENANCE_DB_PASSWORD_ENV: &str =
    "REGISTRYCTL_LOCAL_RELAY_MAINTENANCE_DATABASE_PASSWORD";
const CANONICAL_RUNTIME_RELAY_READER_DB_PASSWORD_ENV: &str =
    "REGISTRYCTL_LOCAL_RELAY_READER_DATABASE_PASSWORD";
const CANONICAL_RUNTIME_NOTARY_CALLER_RAW_ENV: &str = "REGISTRYCTL_LOCAL_NOTARY_CALLER_TOKEN_RAW";
const CANONICAL_RUNTIME_NOTARY_UNDER_SCOPED_RAW_ENV: &str =
    "REGISTRYCTL_LOCAL_NOTARY_UNDER_SCOPED_TOKEN_RAW";
const CANONICAL_RUNTIME_NOTARY_CALLER_HASH_ENV: &str = "REGISTRYCTL_LOCAL_NOTARY_CALLER_TOKEN_HASH";
const CANONICAL_RUNTIME_NOTARY_UNDER_SCOPED_HASH_ENV: &str =
    "REGISTRYCTL_LOCAL_NOTARY_UNDER_SCOPED_TOKEN_HASH";
const CANONICAL_RUNTIME_POSTGRES_PASSWORD_ENV: &str = "POSTGRES_PASSWORD";
const CANONICAL_RUNTIME_POSTGRES_USER_ENV: &str = "POSTGRES_USER";
const CANONICAL_RUNTIME_POSTGRES_TLS_CERTIFICATE_ENV: &str =
    "REGISTRYCTL_LOCAL_POSTGRES_TLS_CERTIFICATE_B64";
const CANONICAL_RUNTIME_POSTGRES_TLS_PRIVATE_KEY_ENV: &str =
    "REGISTRYCTL_LOCAL_POSTGRES_TLS_PRIVATE_KEY_B64";
const CANONICAL_RUNTIME_POSTGRES_USER: &str = "registryctl_bootstrap";
const CANONICAL_RUNTIME_RELAY_DB_USER: &str = "registryctl_relay";
const CANONICAL_RUNTIME_RELAY_DB_OWNER: &str = "registryctl_relay_owner";
const CANONICAL_RUNTIME_RELAY_DB_MAINTENANCE_USER: &str = "registryctl_relay_keyring_maintenance";
const CANONICAL_RUNTIME_RELAY_DB_READER_USER: &str = "registryctl_relay_keyring_reader";
const CANONICAL_RUNTIME_RELAY_DB: &str = "registryctl_relay";
const CANONICAL_RUNTIME_RELAY_KEY_WRITE_DEADLINE_MS: &str = "4102444800000";
const CANONICAL_RUNTIME_RELAY_AUDIT_RETENTION_MS: &str = "2592000000";
const CANONICAL_RUNTIME_WORKLOAD_CLIENT: &str = "registryctl-local-notary";
const CANONICAL_RUNTIME_WORKLOAD_ISSUER: &str = "http://127.0.0.1:4255";
const CANONICAL_RUNTIME_WORKLOAD_AUDIENCE: &str = "registry-relay";
const CANONICAL_RUNTIME_WORKLOAD_SCOPE: &str = "registry:consult:public-works-verification";
const CANONICAL_RUNTIME_WORKLOAD_TTL_SECONDS: u64 = 3600;
const CANONICAL_RUNTIME_WORKLOAD_KID: &str = "registryctl-local-workload";
const CANONICAL_RUNTIME_NOTARY_SIGNING_KID: &str = "registryctl-local-notary-evidence";
const CANONICAL_RUNTIME_MATCH_RAW_ENV: &str = "REGISTRYCTL_LOCAL_RELAY_MATCH_KEY_RAW";
const CANONICAL_RUNTIME_NO_MATCH_RAW_ENV: &str = "REGISTRYCTL_LOCAL_RELAY_NO_MATCH_KEY_RAW";
const CANONICAL_RUNTIME_MATCH_HASH_ENV: &str = "REGISTRYCTL_LOCAL_RELAY_MATCH_KEY_HASH";
const CANONICAL_RUNTIME_NO_MATCH_HASH_ENV: &str = "REGISTRYCTL_LOCAL_RELAY_NO_MATCH_KEY_HASH";
const CANONICAL_RUNTIME_NO_MATCH_PRINCIPAL: &str = "registryctl_local_no_match";
const REGISTRYCTL_RELAY_STAGING_IMAGE_ENV: &str = "REGISTRYCTL_RELAY_STAGING_IMAGE";
const REGISTRYCTL_NOTARY_STAGING_IMAGE_ENV: &str = "REGISTRYCTL_NOTARY_STAGING_IMAGE";
const CANONICAL_RELAY_CONFIG_MOUNT: &str = "/etc/registry-relay/config.yaml";
const CANONICAL_CONSULTATION_RELAY_CONFIG_MOUNT: &str =
    "/etc/registry-relay/config/relay-consultation.yaml";
const CANONICAL_POSTGRES_CA_MOUNT: &str = "/etc/registry-relay/config/state-plane-ca.pem";
const CANONICAL_NOTARY_CONFIG_MOUNT: &str = "/etc/registry-notary/config.yaml";
const CANONICAL_RELAY_CONTAINER_PORT: &str = "0.0.0.0:8080";
const CANONICAL_RELAY_HOST_PORT: &str = "127.0.0.1:4242:8080";
const CANONICAL_NOTARY_CONTAINER_PORT: &str = "0.0.0.0:8081";
const CANONICAL_NOTARY_HOST_PORT: &str = "127.0.0.1:4255:8081";
const RELAY_DOCS_PATH: &str = "/docs";
const TUTORIAL_PURPOSE: &str = "https://example.local/purpose/tutorial";
const TUTORIAL_IDENTITY_PURPOSE: &str = "https://example.local/purpose/identity-verification";
const BRUNO_COLLECTION_DIR: &str = "bruno/registry-api";
const BRUNO_GENERATED_MANIFEST: &str = "bruno/registry-api/.registryctl-generated";
const REGISTRY_STACK_RUNTIME_UID_ENV: &str = "REGISTRY_STACK_RUNTIME_UID";
const REGISTRY_STACK_RUNTIME_GID_ENV: &str = "REGISTRY_STACK_RUNTIME_GID";
const DEFAULT_NONROOT_CONTAINER_ID: &str = "65532";
const REGISTRYCTL_RELEASES_API: &str =
    "https://api.github.com/repos/registrystack/registry-stack/releases?per_page=100";
const REGISTRYCTL_RELEASE_DOWNLOADS: &str =
    "https://github.com/registrystack/registry-stack/releases/download";
const REGISTRYCTL_VERIFY_GUIDE: &str =
    "https://github.com/registrystack/registry-stack/blob/main/release/VERIFY.md";
const UPDATE_CHECK_CACHE_SECONDS: u64 = 60 * 60 * 24;
/// The only `schema_version` `registryctl_manifest` generates today; `Project::load` rejects
/// any other value so a future/incompatible schema file fails loudly instead of half-parsing.
const PROJECT_SCHEMA_VERSION: &str = "registryctl/v1";
const CONFIG_BUNDLE_SIGNATURE_SCHEMA: &str = "registry.platform.config_bundle_signatures.v1";
const CONFIG_TRUST_ANCHOR_SCHEMA: &str = "registry.platform.config_trust_anchor.v1";
const INIT_REPORT_SCHEMA_VERSION: &str = "registryctl.init.v1";
const ADD_NOTARY_REPORT_SCHEMA_VERSION: &str = "registryctl.add_notary.v1";

#[cfg(test)]
thread_local! {
    static ADD_NOTARY_FAIL_AFTER_PUBLISH_COUNT: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}
pub const SMOKE_REPORT_SCHEMA_V1: &str =
    include_str!("../schemas/registryctl.smoke.v1.schema.json");

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InitProjectKind {
    RegistryProject,
    RelaySpreadsheetApi,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InitSource {
    Starter {
        id: String,
        release: String,
        content_digest: String,
        content_state: &'static str,
    },
    Sample {
        id: String,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct InitArtifacts {
    pub project_file: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bruno_collection: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub editor_manifest: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
pub struct InitReport {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub project: String,
    pub project_kind: InitProjectKind,
    pub output: PathBuf,
    pub source: InitSource,
    pub artifacts: InitArtifacts,
}

#[derive(Clone, Debug, Serialize)]
pub struct AddNotaryReport {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub project: PathBuf,
    pub files: Vec<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegistryctlImageLock {
    schema_version: String,
    release_tag: String,
    manifest_source_ref: String,
    tag_target: String,
    platform: String,
    images: RegistryctlLockedImages,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RegistryctlLockedImages {
    #[serde(rename = "registry-relay")]
    registry_relay: String,
    #[serde(rename = "registry-notary")]
    registry_notary: String,
    postgresql: String,
}

impl RegistryctlImageLock {
    fn relay_image(&self) -> &str {
        &self.images.registry_relay
    }

    #[allow(dead_code)]
    fn notary_image(&self) -> &str {
        &self.images.registry_notary
    }

    #[allow(dead_code)]
    fn postgresql_image(&self) -> &str {
        &self.images.postgresql
    }
}

pub fn registryctl_image_lock_filename() -> String {
    format!("registryctl-v{}-image-lock.json", env!("CARGO_PKG_VERSION"))
}

/// Loads the release image lock located beside the running registryctl binary.
///
/// Only project-generation commands call this function. Existing projects keep
/// using the immutable image references already stored in their generated files.
pub fn load_registryctl_image_lock() -> Result<RegistryctlImageLock> {
    if let Some(path) = std::env::var_os(IMAGE_LOCK_PATH_ENV) {
        return load_registryctl_image_lock_path(&PathBuf::from(path));
    }
    let executable =
        std::env::current_exe().context("failed to locate the running registryctl binary")?;
    let directory = executable.parent().ok_or_else(|| {
        anyhow!(
            "running registryctl binary has no parent directory: {}",
            executable.display()
        )
    })?;
    load_registryctl_image_lock_path(&directory.join(registryctl_image_lock_filename()))
}

#[cfg(test)]
fn load_registryctl_image_lock_beside(executable: &Path) -> Result<RegistryctlImageLock> {
    let directory = executable.parent().ok_or_else(|| {
        anyhow!(
            "running registryctl binary has no parent directory: {}",
            executable.display()
        )
    })?;
    load_registryctl_image_lock_path(&directory.join(registryctl_image_lock_filename()))
}

fn load_registryctl_image_lock_path(path: &Path) -> Result<RegistryctlImageLock> {
    let guidance = format!(
        "reinstall registryctl v{} with its matching image lock, or set {IMAGE_LOCK_PATH_ENV} to that verified file; verify the release evidence described at {REGISTRYCTL_VERIFY_GUIDE}",
        env!("CARGO_PKG_VERSION")
    );
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "registryctl image lock is missing at {}; {guidance}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        bail!(
            "registryctl image lock must be a regular file, not a symlink or directory: {}; {guidance}",
            path.display()
        );
    }
    if metadata.len() > IMAGE_LOCK_MAX_BYTES {
        bail!(
            "registryctl image lock exceeds the {IMAGE_LOCK_MAX_BYTES}-byte limit: {}; {guidance}",
            path.display()
        );
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)
        .with_context(|| {
            format!(
                "failed to open registryctl image lock {}; {guidance}",
                path.display()
            )
        })?
        .take(IMAGE_LOCK_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| {
            format!(
                "failed to read registryctl image lock {}; {guidance}",
                path.display()
            )
        })?;
    if bytes.len() as u64 > IMAGE_LOCK_MAX_BYTES {
        bail!(
            "registryctl image lock exceeds the {IMAGE_LOCK_MAX_BYTES}-byte limit: {}; {guidance}",
            path.display()
        );
    }

    let image_lock: RegistryctlImageLock = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "registryctl image lock is not valid schema-v1 JSON: {}; {guidance}",
            path.display()
        )
    })?;
    validate_registryctl_image_lock(&image_lock).with_context(|| {
        format!(
            "registryctl image lock validation failed for {}; {guidance}",
            path.display()
        )
    })?;
    Ok(image_lock)
}

fn validate_registryctl_image_lock(image_lock: &RegistryctlImageLock) -> Result<()> {
    if image_lock.schema_version != IMAGE_LOCK_SCHEMA_VERSION {
        bail!(
            "schema_version must be {IMAGE_LOCK_SCHEMA_VERSION:?}, got {:?}",
            image_lock.schema_version
        );
    }
    let expected_release_tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    if image_lock.release_tag != expected_release_tag {
        bail!(
            "release_tag must exactly match registryctl version {expected_release_tag:?}, got {:?}",
            image_lock.release_tag
        );
    }
    validate_lowercase_commit("manifest_source_ref", &image_lock.manifest_source_ref)?;
    validate_lowercase_commit("tag_target", &image_lock.tag_target)?;
    if image_lock.platform != LINUX_AMD64_PLATFORM {
        bail!(
            "platform must be {LINUX_AMD64_PLATFORM:?}, got {:?}",
            image_lock.platform
        );
    }
    validate_locked_image_ref(
        "images.registry-relay",
        &image_lock.images.registry_relay,
        RELAY_IMAGE_REPOSITORY,
    )?;
    validate_locked_image_ref(
        "images.registry-notary",
        &image_lock.images.registry_notary,
        NOTARY_IMAGE_REPOSITORY,
    )?;
    validate_locked_image_ref(
        "images.postgresql",
        &image_lock.images.postgresql,
        POSTGRES_IMAGE_REPOSITORY,
    )?;
    Ok(())
}

fn validate_lowercase_commit(field: &str, value: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{field} must contain exactly 40 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_locked_image_ref(field: &str, value: &str, repository: &str) -> Result<()> {
    let prefix = format!("{repository}@sha256:");
    let digest = value.strip_prefix(&prefix).ok_or_else(|| {
        anyhow!("{field} must use the literal repository {repository:?} and a sha256 digest")
    })?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{field} digest must contain exactly 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn selected_canonical_relay_image(image_lock: &RegistryctlImageLock) -> Result<String> {
    let staging = std::env::var_os(REGISTRYCTL_RELAY_STAGING_IMAGE_ENV);
    select_canonical_relay_image(image_lock, staging.as_deref())
}

fn select_canonical_relay_image(
    image_lock: &RegistryctlImageLock,
    staging: Option<&OsStr>,
) -> Result<String> {
    let locked = image_lock.relay_image();
    let Some(staging) = staging else {
        return Ok(locked.to_string());
    };
    let staging = staging
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("internal Relay staging image must be valid UTF-8"))?;
    validate_locked_image_ref(
        "internal Relay staging image",
        &staging,
        RELAY_STAGING_IMAGE_REPOSITORY,
    )?;
    let locked_digest = locked
        .rsplit_once("@sha256:")
        .map(|(_, digest)| digest)
        .ok_or_else(|| anyhow!("release-locked Relay image is malformed"))?;
    let staging_digest = staging
        .rsplit_once("@sha256:")
        .map(|(_, digest)| digest)
        .ok_or_else(|| anyhow!("internal Relay staging image is malformed"))?;
    if staging_digest != locked_digest {
        bail!("internal Relay staging image digest must exactly match the release image lock");
    }
    Ok(staging)
}

fn selected_canonical_notary_image(image_lock: &RegistryctlImageLock) -> Result<String> {
    let staging = std::env::var_os(REGISTRYCTL_NOTARY_STAGING_IMAGE_ENV);
    select_canonical_notary_image(image_lock, staging.as_deref())
}

fn select_canonical_notary_image(
    image_lock: &RegistryctlImageLock,
    staging: Option<&OsStr>,
) -> Result<String> {
    let locked = image_lock.notary_image();
    let Some(staging) = staging else {
        return Ok(locked.to_string());
    };
    let staging = staging
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("internal Notary staging image must be valid UTF-8"))?;
    validate_locked_image_ref(
        "internal Notary staging image",
        &staging,
        NOTARY_STAGING_IMAGE_REPOSITORY,
    )?;
    let locked_digest = locked
        .rsplit_once("@sha256:")
        .map(|(_, digest)| digest)
        .ok_or_else(|| anyhow!("release-locked Notary image is malformed"))?;
    let staging_digest = staging
        .rsplit_once("@sha256:")
        .map(|(_, digest)| digest)
        .ok_or_else(|| anyhow!("internal Notary staging image is malformed"))?;
    if staging_digest != locked_digest {
        bail!("internal Notary staging image digest must exactly match the release image lock");
    }
    Ok(staging)
}

fn validate_canonical_runtime_image_ref(image: &str) -> Result<()> {
    if image.starts_with(&format!("{RELAY_IMAGE_REPOSITORY}@sha256:")) {
        validate_locked_image_ref("runtime relay image", image, RELAY_IMAGE_REPOSITORY)
    } else if image.starts_with(&format!("{RELAY_STAGING_IMAGE_REPOSITORY}@sha256:")) {
        validate_locked_image_ref("runtime relay image", image, RELAY_STAGING_IMAGE_REPOSITORY)
    } else {
        bail!("runtime relay image must use the closed release or staging repository")
    }
}

fn validate_canonical_runtime_notary_image_ref(image: &str) -> Result<()> {
    if image.starts_with(&format!("{NOTARY_IMAGE_REPOSITORY}@sha256:")) {
        validate_locked_image_ref("runtime Notary image", image, NOTARY_IMAGE_REPOSITORY)
    } else if image.starts_with(&format!("{NOTARY_STAGING_IMAGE_REPOSITORY}@sha256:")) {
        validate_locked_image_ref(
            "runtime Notary image",
            image,
            NOTARY_STAGING_IMAGE_REPOSITORY,
        )
    } else {
        bail!("runtime Notary image must use the closed release or staging repository")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleInspectReport {
    pub schema_version: String,
    pub manifest: ConfigBundleManifest,
    pub signature_count: usize,
    pub signature_kids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleVerifyReport {
    pub schema_version: String,
    pub product: String,
    pub environment: String,
    pub stream_id: String,
    pub instance_id: Option<String>,
    pub bundle_id: String,
    pub sequence: u64,
    pub config_path: PathBuf,
    pub config_hash: String,
    pub signer_kids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleSignReport {
    pub schema_version: String,
    pub bundle_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub signature_path: PathBuf,
    pub config_path: String,
    pub config_hash: String,
    pub kid: String,
    pub alg: String,
    pub signature_count: usize,
}

#[derive(Debug)]
pub struct BundleSignOptions {
    pub input: PathBuf,
    pub key: String,
    pub product: String,
    pub environment: String,
    pub stream_id: String,
    pub instance_id: Option<String>,
    pub sequence: u64,
    pub bundle_id: String,
    pub out: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnchorReport {
    pub schema_version: String,
    pub anchor_path: PathBuf,
    pub product: String,
    pub environment: String,
    pub stream_id: String,
    pub instance_id: String,
    pub signer_count: usize,
    pub enabled_signer_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum DoctorFormat {
    Human,
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub enum DeploymentProfile {
    Local,
    HostedLab,
    Production,
    EvidenceGrade,
}

impl DeploymentProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::HostedLab => "hosted_lab",
            Self::Production => "production",
            Self::EvidenceGrade => "evidence_grade",
        }
    }
}

pub fn inspect_config_bundle(bundle_dir: &Path) -> Result<BundleInspectReport> {
    let manifest_path = bundle_dir.join("manifest.json");
    let signature_path = bundle_dir.join("manifest.sig.json");
    let manifest: ConfigBundleManifest =
        read_bounded_strict_json(&manifest_path, MAX_MANIFEST_BYTES)?;
    manifest
        .validate()
        .with_context(|| format!("invalid config bundle manifest {}", manifest_path.display()))?;

    let envelope = read_signature_envelope_if_present(&signature_path)?;
    let signature_kids: Vec<String> = envelope
        .as_ref()
        .map(|envelope| {
            envelope
                .signatures
                .iter()
                .map(|signature| signature.kid.clone())
                .collect()
        })
        .unwrap_or_default();
    Ok(BundleInspectReport {
        schema_version: "registryctl.config_bundle.inspect.v1".to_string(),
        manifest,
        signature_count: signature_kids.len(),
        signature_kids,
    })
}

pub fn verify_config_bundle_cli(
    bundle_dir: &Path,
    anchor_path: &Path,
) -> Result<BundleVerifyReport> {
    let verified = verify_config_bundle(bundle_dir, anchor_path)
        .with_context(|| format!("failed to verify config bundle {}", bundle_dir.display()))?;
    Ok(BundleVerifyReport {
        schema_version: "registryctl.config_bundle.verify.v1".to_string(),
        product: verified.manifest.product,
        environment: verified.manifest.environment,
        stream_id: verified.manifest.stream_id,
        instance_id: verified.manifest.instance_id,
        bundle_id: verified.manifest.bundle_id,
        sequence: verified.manifest.sequence,
        config_path: verified.config_path,
        config_hash: verified.manifest.config_hash,
        signer_kids: verified.signer_kids,
    })
}

pub fn sign_config_bundle(options: BundleSignOptions) -> Result<BundleSignReport> {
    if options.sequence == 0 || options.sequence > MAX_CONFIG_BUNDLE_SEQUENCE {
        bail!("sequence must be in 1..={}", MAX_CONFIG_BUNDLE_SEQUENCE);
    }
    ensure_output_bundle_dir_is_empty(&options.out)?;
    let files = collect_config_bundle_input_files(&options.input)?;
    let primary_config_path = primary_config_path(&options.product, &files)?;
    let created_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("failed to format created_at")?;
    let manifest_files = files
        .iter()
        .map(|file| ConfigBundleFile {
            path: file.relative_path.clone(),
            sha256: file.sha256.clone(),
        })
        .collect::<Vec<_>>();
    let config_hash = files
        .iter()
        .find(|file| file.relative_path == primary_config_path)
        .map(|file| file.sha256.clone())
        .expect("primary config path was selected from files");
    let manifest = ConfigBundleManifest {
        schema: "registry.platform.config_bundle.v1".to_string(),
        product: options.product,
        environment: options.environment,
        stream_id: options.stream_id,
        instance_id: options.instance_id,
        bundle_id: options.bundle_id,
        sequence: options.sequence,
        previous_config_hash: None,
        config_hash: config_hash.clone(),
        files: manifest_files,
        created_at,
    };
    manifest
        .validate()
        .context("generated manifest is invalid")?;

    for file in &files {
        let destination = options.out.join(&file.relative_path);
        let parent = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
        fs::write(&destination, &file.bytes)
            .with_context(|| format!("failed to write {}", destination.display()))?;
    }
    let manifest_path = options.out.join("manifest.json");
    let signature_path = options.out.join("manifest.sig.json");
    write_json_file(&manifest_path, &manifest)?;
    let manifest_value =
        serde_json::to_value(&manifest).context("failed to render manifest for signing")?;

    let private_jwk_text = read_private_jwk_text(&options.key)?;
    let private_jwk = PrivateJwk::parse(&private_jwk_text).with_context(|| {
        format!(
            "failed to parse private JWK from {}",
            key_display(&options.key)
        )
    })?;
    let public_jwk = private_jwk.public();
    let kid = public_jwk
        .jkt()
        .context("failed to compute JWK thumbprint for signing key")?;
    let alg = signing_algorithm_label(private_jwk.algorithm().context("invalid signing key alg")?);
    let canonical_manifest =
        canonicalize_json(&manifest_value).context("failed to canonicalize manifest JSON")?;
    let signature = sign_payload(&canonical_manifest, &private_jwk)
        .context("failed to sign config bundle manifest")?;

    let envelope = ConfigBundleSignatureEnvelope {
        schema: CONFIG_BUNDLE_SIGNATURE_SCHEMA.to_string(),
        signatures: vec![ConfigBundleSignature {
            kid: kid.clone(),
            alg: alg.to_string(),
            sig: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature),
        }],
    };
    write_json_file(&signature_path, &envelope)?;

    Ok(BundleSignReport {
        schema_version: "registryctl.config_bundle.sign.v1".to_string(),
        bundle_dir: options.out,
        manifest_path,
        signature_path,
        config_path: primary_config_path,
        config_hash,
        kid,
        alg: alg.to_string(),
        signature_count: envelope.signatures.len(),
    })
}

pub fn init_config_anchor(
    anchor_path: &Path,
    product: String,
    environment: String,
    stream_id: String,
    instance_id: String,
) -> Result<AnchorReport> {
    let anchor = ConfigTrustAnchor {
        schema: CONFIG_TRUST_ANCHOR_SCHEMA.to_string(),
        product,
        environment,
        stream_id,
        instance_id,
        signers: Vec::new(),
    };
    write_trust_anchor_file(anchor_path, &anchor)?;
    Ok(anchor_report(anchor_path, &anchor))
}

pub fn add_config_anchor_key(
    anchor_path: &Path,
    jwk_path: &Path,
    enabled: bool,
) -> Result<AnchorReport> {
    let mut anchor = read_anchor_unvalidated(anchor_path)?;
    let jwk_text = read_bounded_utf8_file(jwk_path, MAX_JWK_JSON_BYTES)?;
    let jwk = PublicJwk::parse(&jwk_text)
        .with_context(|| format!("failed to parse public JWK {}", jwk_path.display()))?;
    let kid = jwk
        .jkt()
        .context("failed to compute JWK thumbprint for anchor key")?;
    if anchor.signers.iter().any(|signer| signer.kid == kid) {
        bail!("trust anchor already contains signer {kid}");
    }
    anchor
        .signers
        .push(ConfigTrustAnchorSigner { kid, jwk, enabled });
    anchor
        .validate()
        .with_context(|| format!("invalid trust anchor {}", anchor_path.display()))?;
    write_trust_anchor_file(anchor_path, &anchor)?;
    Ok(anchor_report(anchor_path, &anchor))
}

pub fn remove_config_anchor_key(anchor_path: &Path, kid: &str) -> Result<AnchorReport> {
    let mut anchor = read_anchor_unvalidated(anchor_path)?;
    let before = anchor.signers.len();
    anchor.signers.retain(|signer| signer.kid != kid);
    if anchor.signers.len() == before {
        bail!("trust anchor does not contain signer {kid}");
    }
    if !anchor.signers.is_empty() {
        anchor
            .validate()
            .with_context(|| format!("invalid trust anchor {}", anchor_path.display()))?;
    }
    write_trust_anchor_file(anchor_path, &anchor)?;
    Ok(anchor_report(anchor_path, &anchor))
}

#[derive(Debug)]
struct BundleInputFile {
    relative_path: String,
    bytes: Vec<u8>,
    sha256: String,
}

fn ensure_output_bundle_dir_is_empty(out: &Path) -> Result<()> {
    if out.exists() {
        if !out.is_dir() {
            bail!(
                "bundle output path exists and is not a directory: {}",
                out.display()
            );
        }
        let mut entries =
            fs::read_dir(out).with_context(|| format!("failed to read {}", out.display()))?;
        if entries.next().transpose()?.is_some() {
            bail!("bundle output directory must be empty: {}", out.display());
        }
    } else {
        fs::create_dir_all(out).with_context(|| format!("failed to create {}", out.display()))?;
    }
    Ok(())
}

fn collect_config_bundle_input_files(input: &Path) -> Result<Vec<BundleInputFile>> {
    if !input.is_dir() {
        bail!("bundle input path must be a directory: {}", input.display());
    }
    let mut files = Vec::new();
    collect_config_bundle_input_files_inner(input, input, &mut files)?;
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    if files.is_empty() {
        bail!("bundle input directory contains no regular files");
    }
    Ok(files)
}

fn collect_config_bundle_input_files_inner(
    root: &Path,
    dir: &Path,
    files: &mut Vec<BundleInputFile>,
) -> Result<()> {
    let metadata =
        fs::symlink_metadata(dir).with_context(|| format!("failed to stat {}", dir.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("bundle input symlink is not allowed: {}", dir.display());
    }
    if !metadata.is_dir() {
        bail!("bundle input path is not a directory: {}", dir.display());
    }
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("failed to read entry in {}", dir.display()))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to stat {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("bundle input symlink is not allowed: {}", path.display());
        }
        if metadata.is_dir() {
            collect_config_bundle_input_files_inner(root, &path, files)?;
        } else if metadata.is_file() {
            if metadata.len() > MAX_BUNDLE_FILE_BYTES {
                bail!("bundle input file exceeds size cap: {}", path.display());
            }
            let relative_path = bundle_relative_path(root, &path)?;
            if matches!(
                relative_path.as_str(),
                "manifest.json" | "manifest.sig.json"
            ) {
                bail!(
                    "bundle input must not contain reserved file {}",
                    relative_path
                );
            }
            let bytes =
                fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
            if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BUNDLE_FILE_BYTES {
                bail!("bundle input file exceeds size cap: {}", path.display());
            }
            let sha256 = sha256_uri(&bytes);
            files.push(BundleInputFile {
                relative_path,
                bytes,
                sha256,
            });
        }
    }
    Ok(())
}

fn bundle_relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("{} is not under {}", path.display(), root.display()))?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or_else(|| anyhow!("bundle path is not valid UTF-8: {}", path.display()))?;
                if part.is_empty() || part == "." || part == ".." {
                    bail!("bundle path is not normalized: {}", path.display());
                }
                parts.push(part.to_string());
            }
            _ => bail!("bundle path is not normalized: {}", path.display()),
        }
    }
    if parts.is_empty() {
        bail!("bundle path is empty: {}", path.display());
    }
    Ok(parts.join("/"))
}

fn primary_config_path(product: &str, files: &[BundleInputFile]) -> Result<String> {
    let expected = match product {
        "registry-notary" => Some("config/notary.yaml"),
        "registry-relay" => Some("config/relay.yaml"),
        _ => None,
    };
    if let Some(expected) = expected {
        if files.iter().any(|file| file.relative_path == expected) {
            return Ok(expected.to_string());
        }
    }
    if files.len() == 1 {
        return Ok(files[0].relative_path.clone());
    }
    bail!(
        "bundle input has multiple files; expected primary config path {}",
        expected.unwrap_or("as the only regular file")
    )
}

fn read_private_jwk_text(key_ref: &str) -> Result<Zeroizing<String>> {
    if key_ref.starts_with("op://") {
        let mut child = Command::new("op")
            .arg("read")
            .arg(key_ref)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to run op read for bundle signing key")?;
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            bail!("op read did not provide a stdout pipe");
        };
        let bytes = match read_bounded_zeroizing(stdout, MAX_JWK_JSON_BYTES, "op read output") {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        let status = child
            .wait()
            .context("failed to wait for op read bundle signing key")?;
        if !status.success() {
            bail!("op read failed for bundle signing key reference");
        }
        return zeroizing_utf8(bytes, "private JWK returned by op read is not UTF-8 JSON");
    }
    read_bounded_utf8_file(Path::new(key_ref), MAX_JWK_JSON_BYTES)
}

fn read_bounded_utf8_file(path: &Path, max_bytes: usize) -> Result<Zeroizing<String>> {
    let file =
        fs::File::open(path).with_context(|| format!("failed to read {}", path.display()))?;
    let label = path.display().to_string();
    let bytes = read_bounded_zeroizing(file, max_bytes, &label)?;
    zeroizing_utf8(bytes, &format!("{} is not UTF-8 JSON", path.display()))
}

fn read_bounded_zeroizing(
    reader: impl Read,
    max_bytes: usize,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label}"))?;
    if bytes.len() > max_bytes {
        bail!("{label} exceeds the {max_bytes}-byte limit");
    }
    Ok(bytes)
}

fn zeroizing_utf8(bytes: Zeroizing<Vec<u8>>, invalid_message: &str) -> Result<Zeroizing<String>> {
    let text = std::str::from_utf8(&bytes).with_context(|| invalid_message.to_string())?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn key_display(key_ref: &str) -> &str {
    if key_ref.starts_with("op://") {
        "op://..."
    } else {
        key_ref
    }
}

fn read_signature_envelope_if_present(
    signature_path: &Path,
) -> Result<Option<ConfigBundleSignatureEnvelope>> {
    match fs::File::open(signature_path) {
        Ok(file) => {
            decode_bounded_strict_json(file, signature_path, MAX_SIGNATURE_ENVELOPE_BYTES).map(Some)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("failed to read {}", signature_path.display()))
        }
    }
}

fn read_anchor_unvalidated(anchor_path: &Path) -> Result<ConfigTrustAnchor> {
    let anchor: ConfigTrustAnchor = read_bounded_strict_json(anchor_path, MAX_TRUST_ANCHOR_BYTES)?;
    if anchor.schema != CONFIG_TRUST_ANCHOR_SCHEMA {
        bail!("trust anchor schema is invalid");
    }
    if anchor.product.trim().is_empty()
        || anchor.environment.trim().is_empty()
        || anchor.stream_id.trim().is_empty()
        || anchor.instance_id.trim().is_empty()
    {
        bail!("trust anchor binding fields must be non-empty");
    }
    Ok(anchor)
}

fn read_bounded_strict_json<T>(path: &Path, max_bytes: u64) -> Result<T>
where
    T: DeserializeOwned,
{
    let file =
        fs::File::open(path).with_context(|| format!("failed to read {}", path.display()))?;
    decode_bounded_strict_json(file, path, max_bytes)
}

fn decode_bounded_strict_json<T>(reader: impl Read, path: &Path, max_bytes: u64) -> Result<T>
where
    T: DeserializeOwned,
{
    let mut bytes = Vec::new();
    reader
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        bail!(
            "JSON artifact exceeds the {max_bytes}-byte limit: {}",
            path.display()
        );
    }
    let value =
        parse_json_strict(&bytes).with_context(|| format!("failed to parse {}", path.display()))?;
    serde_json::from_value(value).with_context(|| format!("failed to parse {}", path.display()))
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let json = serde_json::to_vec_pretty(value).context("failed to render JSON")?;
    fs::write(path, json).with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(unix)]
fn write_trust_anchor_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let json = serde_json::to_vec_pretty(value).context("failed to render JSON")?;

    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "trust anchor path must not be a symlink: {}",
                    path.display()
                );
            }
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(path, permissions)
                .with_context(|| format!("failed to set permissions on {}", path.display()))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to stat {}", path.display()));
        }
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(&json)
        .with_context(|| format!("failed to write {}", path.display()))?;

    let mut permissions = file
        .metadata()
        .with_context(|| format!("failed to stat {}", path.display()))?
        .permissions();
    permissions.set_mode(0o600);
    file.set_permissions(permissions)
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn write_trust_anchor_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    write_json_file(path, value)
}

fn anchor_report(anchor_path: &Path, anchor: &ConfigTrustAnchor) -> AnchorReport {
    AnchorReport {
        schema_version: "registryctl.config_anchor.v1".to_string(),
        anchor_path: anchor_path.to_path_buf(),
        product: anchor.product.clone(),
        environment: anchor.environment.clone(),
        stream_id: anchor.stream_id.clone(),
        instance_id: anchor.instance_id.clone(),
        signer_count: anchor.signers.len(),
        enabled_signer_count: anchor
            .signers
            .iter()
            .filter(|signer| signer.enabled)
            .count(),
    }
}

fn signing_algorithm_label(algorithm: SigningAlgorithm) -> &'static str {
    match algorithm {
        SigningAlgorithm::EdDsa => "EdDSA",
        SigningAlgorithm::Es256 => "ES256",
        SigningAlgorithm::Rs256 => "RS256",
    }
}

pub fn init_spreadsheet_api(
    dir: &Path,
    sample: Sample,
    image_lock: &RegistryctlImageLock,
) -> Result<InitReport> {
    match sample {
        Sample::Benefits => init_benefits_project(dir, image_lock),
    }
}

pub fn maybe_warn_about_update(current_version: &str) {
    if update_check_disabled() {
        return;
    }
    let Some(cache_path) = update_check_cache_path() else {
        return;
    };

    let should_refresh = match read_update_check_cache(&cache_path) {
        Ok(Some(cache)) => {
            if let Some(notice) = update_notice(current_version, &cache.latest_tag) {
                eprintln!("{notice}");
            }
            !cache.is_fresh
        }
        Ok(None) | Err(_) => true,
    };

    if should_refresh {
        spawn_update_check_refresh();
    }
}

pub fn update_check(current_version: &str) -> Result<()> {
    let latest_tag = fetch_latest_registryctl_release()?;
    if let Some(notice) = update_notice(current_version, &latest_tag) {
        println!("{notice}");
    } else {
        println!(
            "registryctl {} is current. Latest release: {}.",
            display_version(current_version),
            latest_tag
        );
    }

    if let Some(cache_path) = update_check_cache_path() {
        let _ = write_update_check_cache(&cache_path, &latest_tag);
    }

    Ok(())
}

pub fn refresh_update_check_cache() -> Result<()> {
    let latest_tag = fetch_latest_registryctl_release()?;
    if let Some(cache_path) = update_check_cache_path() {
        write_update_check_cache(&cache_path, &latest_tag)?;
    }
    Ok(())
}

fn spawn_update_check_refresh() {
    let Ok(current_exe) = std::env::current_exe() else {
        return;
    };
    let _ = Command::new(current_exe)
        .arg("__update-check-refresh")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

fn update_check_disabled() -> bool {
    env_flag_is_set("CI")
        || env_flag_is_set("REGISTRYCTL_NO_UPDATE_CHECK")
        || matches!(
            std::env::var("REGISTRYCTL_UPDATE_CHECK"),
            Ok(value) if value == "0" || value.eq_ignore_ascii_case("false")
        )
}

fn env_flag_is_set(name: &str) -> bool {
    matches!(
        std::env::var(name),
        Ok(value) if !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false")
    )
}

fn read_update_check_cache(cache_path: &Path) -> Result<Option<CachedLatestRelease>> {
    let raw = match fs::read_to_string(cache_path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("failed to read registryctl update check cache"),
    };
    let cache: UpdateCheckCache =
        serde_json::from_str(&raw).context("failed to parse registryctl update check cache")?;
    if VersionNumber::parse_release_tag(&cache.latest_tag).is_none() {
        bail!("registryctl update check cache contains a non-canonical release tag");
    }
    let now = unix_now();
    Ok(Some(CachedLatestRelease {
        is_fresh: now.saturating_sub(cache.checked_at) <= UPDATE_CHECK_CACHE_SECONDS,
        latest_tag: cache.latest_tag,
    }))
}

fn write_update_check_cache(cache_path: &Path, latest_tag: &str) -> Result<()> {
    if VersionNumber::parse_release_tag(latest_tag).is_none() {
        bail!("refusing to cache a non-canonical registryctl release tag");
    }
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let cache = UpdateCheckCache {
        checked_at: unix_now(),
        latest_tag: latest_tag.to_string(),
    };
    let json = serde_json::to_string(&cache).context("failed to render update check cache")?;
    fs::write(cache_path, json).with_context(|| format!("failed to write {}", cache_path.display()))
}

fn update_check_cache_path() -> Option<PathBuf> {
    let cache_home = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    Some(cache_home.join("registryctl").join("update-check.json"))
}

fn fetch_latest_registryctl_release() -> Result<String> {
    let response = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(2))
        .build()
        .get(REGISTRYCTL_RELEASES_API)
        .set("Accept", "application/vnd.github+json")
        .set("User-Agent", "registryctl")
        .call()
        .map_err(registryctl_release_http_error)?;
    let body = response
        .into_string()
        .context("failed to read registryctl latest release response")?;
    let releases: Vec<GitHubRelease> =
        serde_json::from_str(&body).context("failed to parse registryctl releases response")?;
    select_latest_published_release(&releases).ok_or_else(|| {
        anyhow!(
            "registryctl releases response did not include a published canonical vMAJOR.MINOR.PATCH tag"
        )
    })
}

fn select_latest_published_release(releases: &[GitHubRelease]) -> Option<String> {
    releases
        .iter()
        .filter(|release| !release.draft)
        .filter_map(|release| {
            VersionNumber::parse_release_tag(&release.tag_name)
                .map(|version| (version, release.tag_name.as_str()))
        })
        .max_by_key(|(version, _)| *version)
        .map(|(_, tag)| tag.to_string())
}

fn registryctl_release_http_error(error: ureq::Error) -> anyhow::Error {
    match error {
        ureq::Error::Status(status, response) => {
            let body = response.into_string().unwrap_or_default();
            anyhow!(
                "GitHub returned HTTP {status} while checking registryctl releases: {}",
                body.trim()
            )
        }
        ureq::Error::Transport(error) => {
            anyhow!("failed to check registryctl releases: {error}")
        }
    }
}

fn update_notice(current_version: &str, latest_tag: &str) -> Option<String> {
    let current = VersionNumber::parse(current_version)?;
    let latest = VersionNumber::parse_release_tag(latest_tag)?;
    if latest <= current {
        return None;
    }
    let install_script =
        format!("{REGISTRYCTL_RELEASE_DOWNLOADS}/{latest_tag}/registryctl-{latest_tag}-install.sh");
    let verify_guide = format!(
        "https://github.com/registrystack/registry-stack/blob/{latest_tag}/release/VERIFY.md"
    );
    Some(format!(
        "registryctl {latest_tag} is available. You have {}.\nExecuting the quick installer trusts GitHub and TLS; the installer verifies the downloaded binary and image lock against the release checksums. For signature and provenance verification, see:\n  {verify_guide}\nUpgrade with:\n  curl -fsSL {install_script} | REGISTRYCTL_VERSION={latest_tag} bash",
        display_version(current_version),
    ))
}

fn display_version(version: &str) -> String {
    if version.starts_with('v') {
        version.to_string()
    } else {
        format!("v{version}")
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    draft: bool,
    #[allow(dead_code)]
    prerelease: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct UpdateCheckCache {
    checked_at: u64,
    latest_tag: String,
}

#[derive(Debug)]
struct CachedLatestRelease {
    is_fresh: bool,
    latest_tag: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct VersionNumber {
    major: u64,
    minor: u64,
    patch: u64,
}

impl VersionNumber {
    fn parse_release_tag(value: &str) -> Option<Self> {
        let version = value.strip_prefix('v')?;
        if !version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        {
            return None;
        }
        let parsed = Self::parse(version)?;
        if value != format!("v{}.{}.{}", parsed.major, parsed.minor, parsed.patch) {
            return None;
        }
        Some(parsed)
    }

    fn parse(value: &str) -> Option<Self> {
        let trimmed = value.trim().trim_start_matches('v');
        let without_prerelease = trimmed.split_once('-').map_or(trimmed, |(base, _)| base);
        let base = without_prerelease
            .split_once('+')
            .map_or(without_prerelease, |(base, _)| base);
        let mut parts = base.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

#[derive(Clone, Debug)]
struct CanonicalRuntime {
    compose_file: PathBuf,
    relay_config: PathBuf,
    secrets_env: PathBuf,
    image: String,
    topology: CanonicalRuntimeTopology,
}

#[derive(Clone, Debug)]
struct CanonicalSpreadsheetBinding {
    project_file_text: String,
    runtime_path: String,
    match_principal: String,
    topology: CanonicalRuntimeTopology,
    runtime_user: String,
    runtime_uid: String,
    runtime_gid: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CanonicalRuntimeTopology {
    #[default]
    RelayOnly,
    CombinedNotary,
}

impl CanonicalRuntimeTopology {
    const fn has_notary(self) -> bool {
        matches!(self, Self::CombinedNotary)
    }
}

#[derive(Clone, Debug)]
struct CanonicalRuntimeImages {
    relay: String,
    notary: Option<String>,
    postgresql: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalNotaryRuntimeManifest {
    notary_image: String,
    postgresql_image: String,
    consultation_relay_config_digest: String,
    runtime_consultation_relay_config_digest: String,
    compiled_notary_config_digest: String,
    runtime_notary_config_digest: String,
    postgres_ca_digest: String,
    database_init_digest: String,
    workload_jwks_digest: String,
    consultation_relay_env_digest: String,
    relay_bootstrap_env_digest: String,
    notary_env_digest: String,
    postgres_env_digest: String,
    workload_token_digest: String,
    workload_private_jwk_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalRuntimeManifest {
    schema_version: String,
    environment: String,
    relay_image: String,
    compose_digest: String,
    artifact_manifest_digest: String,
    relay_config_digest: String,
    workbook_digest: String,
    workbook_classification: ArtifactInputClassification,
    workbook_project_file: String,
    workbook_runtime_path: String,
    #[serde(default)]
    topology: CanonicalRuntimeTopology,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notary: Option<CanonicalNotaryRuntimeManifest>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CanonicalRuntimeValidation {
    GeneratedClosure,
    Full,
}

fn retired_legacy_project_error() -> anyhow::Error {
    anyhow!(
        "legacy pre-1.0 direct projects are retired. Reinitialize with \
         `registryctl init --from spreadsheet --project-dir <directory>` and re-express the \
         reviewed project intent; registryctl does not silently migrate or dual-model legacy \
         projects."
    )
}

fn require_canonical_project(project_dir: &Path) -> Result<()> {
    let root = fs::symlink_metadata(project_dir)
        .context("failed to inspect the Registry Stack project root")?;
    if root.file_type().is_symlink() || !root.is_dir() {
        bail!("the Registry Stack project root must be a real directory");
    }
    if fs::symlink_metadata(project_dir.join("registryctl.yaml")).is_ok() {
        return Err(retired_legacy_project_error());
    }
    let project_file = project_dir.join(CANONICAL_PROJECT_FILE);
    let metadata = fs::symlink_metadata(&project_file)
        .map_err(|_| anyhow!("the canonical project is missing registry-stack.yaml"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("registry-stack.yaml must be a regular non-symlink file");
    }
    Ok(())
}

pub fn add_notary_to_canonical_project(project_dir: &Path) -> Result<AddNotaryReport> {
    require_canonical_project(project_dir)?;
    let _ = canonical_spreadsheet_binding(project_dir)?;
    let project_file = project_dir.join(CANONICAL_PROJECT_FILE);
    let environment_file = project_dir.join(CANONICAL_LOCAL_ENVIRONMENT_FILE);
    let integration_file =
        project_dir.join("integrations/project-record-snapshot/integration.yaml");
    let match_fixture =
        project_dir.join("integrations/project-record-snapshot/fixtures/match.yaml");
    let planned_fixture =
        project_dir.join("integrations/project-record-snapshot/fixtures/planned.yaml");
    let no_match_fixture =
        project_dir.join("integrations/project-record-snapshot/fixtures/no-match.yaml");

    for path in [
        &project_file,
        &environment_file,
        &integration_file,
        &match_fixture,
        &planned_fixture,
        &no_match_fixture,
    ] {
        ensure_no_symlink_components(project_dir, path)?;
    }

    let current_project = fs::read_to_string(&project_file)
        .context("failed to read canonical registry-stack.yaml")?;
    let current_environment = fs::read_to_string(&environment_file)
        .context("failed to read canonical local environment")?;
    let desired_project = canonical_notary_project_yaml(&current_project)?;
    let desired_environment = canonical_notary_environment_yaml(&current_environment)?;
    let desired_integration = canonical_notary_integration_yaml();
    let desired_match = canonical_notary_match_fixture_yaml();
    let desired_planned = canonical_notary_planned_fixture_yaml();
    let desired_no_match = canonical_notary_no_match_fixture_yaml();

    let desired_files = [
        (&project_file, desired_project.as_str()),
        (&environment_file, desired_environment.as_str()),
        (&integration_file, desired_integration),
        (&match_fixture, desired_match),
        (&planned_fixture, desired_planned),
        (&no_match_fixture, desired_no_match),
    ];

    let already_exact = desired_files.iter().all(|(path, expected)| {
        fs::read_to_string(path)
            .map(|actual| actual == *expected)
            .unwrap_or(false)
    });
    if already_exact {
        return Ok(AddNotaryReport {
            schema_version: ADD_NOTARY_REPORT_SCHEMA_VERSION,
            status: "unchanged",
            project: project_dir.to_path_buf(),
            files: desired_files
                .iter()
                .map(|(path, _)| path.strip_prefix(project_dir).unwrap_or(path).to_path_buf())
                .collect(),
        });
    }

    if project_dir
        .join("integrations/project-record-snapshot")
        .exists()
        || current_project.contains("project-record-snapshot")
        || current_project.contains("public-works-verification")
        || current_environment.contains("notary_relay:")
        || current_environment.contains("notary:")
    {
        bail!(
            "`registryctl add notary` found an unsupported or conflicting Notary add-on shape; no files were changed"
        );
    }

    commit_canonical_notary_add_on(project_dir, &desired_files)?;

    Ok(AddNotaryReport {
        schema_version: ADD_NOTARY_REPORT_SCHEMA_VERSION,
        status: "updated",
        project: project_dir.to_path_buf(),
        files: desired_files
            .iter()
            .map(|(path, _)| path.strip_prefix(project_dir).unwrap_or(path).to_path_buf())
            .collect(),
    })
}

fn commit_canonical_notary_add_on(project_dir: &Path, files: &[(&PathBuf, &str)]) -> Result<()> {
    let transaction_root = project_dir.join(".registry-stack");
    ensure_no_symlink_components(project_dir, &transaction_root)?;
    create_private_dir_all(&transaction_root)?;
    let staging = tempfile::Builder::new()
        .prefix(".add-notary-stage-")
        .tempdir_in(&transaction_root)
        .context("failed to stage the Notary add-on")?;
    let backup = tempfile::Builder::new()
        .prefix(".add-notary-backup-")
        .tempdir_in(&transaction_root)
        .context("failed to stage Notary add-on rollback data")?;
    for (target, contents) in files {
        let relative = target
            .strip_prefix(project_dir)
            .context("Notary add-on target escaped the project root")?;
        let staged = staging.path().join(relative);
        if let Some(parent) = staged.parent() {
            fs::create_dir_all(parent).context("failed to stage Notary add-on parent")?;
        }
        fs::write(&staged, contents).context("failed to stage Notary add-on file")?;
    }

    let mut moved = Vec::<(PathBuf, PathBuf)>::new();
    let mut published_targets = Vec::<PathBuf>::new();
    let mut created_dirs = Vec::<PathBuf>::new();
    let commit = (|| -> Result<()> {
        for (target, _) in files {
            ensure_no_symlink_components(project_dir, target)?;
            let relative = target
                .strip_prefix(project_dir)
                .context("Notary add-on target escaped the project root")?;
            if let Some(parent) = target.parent() {
                ensure_no_symlink_components(project_dir, parent)?;
                if !parent.exists() {
                    fs::create_dir_all(parent).context("failed to create Notary add-on parent")?;
                    created_dirs.push(parent.to_path_buf());
                }
            }
            if target.exists() {
                let backup_target = backup.path().join(relative);
                if let Some(parent) = backup_target.parent() {
                    fs::create_dir_all(parent)
                        .context("failed to stage Notary add-on rollback parent")?;
                }
                fs::rename(target, &backup_target)
                    .context("failed to stage existing Notary add-on file for rollback")?;
                moved.push((target.to_path_buf(), backup_target));
            }
            fs::rename(staging.path().join(relative), target)
                .context("failed to publish staged Notary add-on file")?;
            published_targets.push(target.to_path_buf());
            #[cfg(test)]
            if ADD_NOTARY_FAIL_AFTER_PUBLISH_COUNT
                .with(|count| count.get() == published_targets.len())
            {
                bail!("injected Notary add-on publication failure");
            }
        }
        Ok(())
    })();
    if let Err(error) = commit {
        for target in published_targets.into_iter().rev() {
            let _ = fs::remove_file(&target);
        }
        for (target, backup_target) in moved.into_iter().rev() {
            let _ = fs::rename(&backup_target, &target);
        }
        for directory in created_dirs.into_iter().rev() {
            let _ = fs::remove_dir(&directory);
        }
        return Err(error.context("Notary add-on publication was rolled back"));
    }
    Ok(())
}

fn canonical_notary_project_yaml(current: &str) -> Result<String> {
    if current.contains("project-record-snapshot") || current.contains("public-works-verification")
    {
        return Ok(current.to_string());
    }
    let with_integration = current.replacen(
        "registry:\n  id: fictional-public-works-registry\n\nentities:\n",
        "registry:\n  id: fictional-public-works-registry\n\nintegrations:\n  project-record-snapshot: { file: integrations/project-record-snapshot/integration.yaml }\n\nentities:\n",
        1,
    );
    if with_integration == current {
        bail!("`registryctl add notary` supports only the canonical spreadsheet starter shape");
    }
    let service_block = r#"
  public-works-verification:
    kind: evidence
    version: 1
    subject_type: project
    purpose: public-works-case-management
    legal_basis: public-service-delivery
    consent: not_required
    access: { scopes: ["evidence:projects:read"] }
    consultations:
      project:
        integration: project-record-snapshot
        input: { project_id: request.target.identifiers.project_id }
    claims:
      project-record-exists: { cel: project.matched, disclosure: predicate }
      project-status-accepted: { cel: 'project.matched && project.status == "active"', disclosure: predicate }
"#;
    if !with_integration.contains("      standards: { ogc_features: false, sp_dci: false }\n") {
        bail!("`registryctl add notary` supports only the canonical spreadsheet starter service shape");
    }
    Ok(with_integration.replacen(
        "      standards: { ogc_features: false, sp_dci: false }\n",
        &format!("      standards: {{ ogc_features: false, sp_dci: false }}\n{service_block}"),
        1,
    ))
}

fn canonical_notary_environment_yaml(current: &str) -> Result<String> {
    if current.contains("notary_relay:") || current.contains("callers:") {
        return Ok(current.to_string());
    }
    if !current.contains("relay:\n")
        || !current.contains("  local_api_keys:\n")
        || !current.contains("  allowed_clients: [public-works-casework]\n")
    {
        bail!(
            "`registryctl add notary` supports only the canonical spreadsheet starter environment"
        );
    }
    let with_oidc = current.to_string();
    let callers = r#"callers:
  public-works-service:
    api_key_fingerprint: { secret: REGISTRYCTL_LOCAL_NOTARY_CALLER_TOKEN_HASH }
    scopes: ["evidence:projects:read"]
  public-works-under-scoped:
    api_key_fingerprint: { secret: REGISTRYCTL_LOCAL_NOTARY_UNDER_SCOPED_TOKEN_HASH }
    scopes: ["evidence:projects:metadata"]

"#;
    let with_callers = with_oidc.replacen("relay:\n", &format!("{callers}relay:\n"), 1);
    if with_callers == with_oidc {
        bail!("canonical Relay environment binding is absent");
    }
    let notary = r#"
notary_relay:
  base_url: http://127.0.0.1:8080
  workload_client_id: registryctl-local-notary
  token_file: /run/secrets/relay-workload-token

"#;
    let with_notary = with_callers.replacen("deployment:\n", &format!("{notary}deployment:\n"), 1);
    if with_notary == with_callers {
        bail!("canonical deployment environment binding is absent");
    }
    let with_deployment = with_notary.replacen(
        "  relay: { service: records-relay }\n",
        "  relay: { service: records-relay }\n  notary: { service: registryctl-local-notary }\n",
        1,
    );
    if with_deployment == with_notary {
        bail!("canonical Relay deployment binding is absent");
    }
    Ok(with_deployment)
}

fn canonical_notary_integration_yaml() -> &'static str {
    r#"version: 1
id: public-works-project-snapshot
revision: 1
input:
  project_id:
    role: selector
    type: string
    maxLength: 64
capability:
  snapshot:
    entity: projects
    exact:
      project_id: { input: project_id }
    freshness: 24h
outputs: [status]
not_applicable:
  ambiguity:
    rationale: The exact project selector is the entity primary key, whose materialized unique-key constraint permits at most one record.
    request_fixture: match
  subject_mismatch:
    rationale: The selected snapshot output projection omits the primary key, so it contains no identifier comparable with the requested project identifier.
    request_fixture: match
"#
}

fn canonical_notary_match_fixture_yaml() -> &'static str {
    r#"name: match
classification: synthetic
input: { project_id: pw_001 }
interactions:
  - expect: { method: GET, path: /snapshot }
    respond: { status: 200, body: { status: active } }
expect:
  outcome: match
  outputs: { status: active }
  claims:
    project-record-exists: true
    project-status-accepted: true
"#
}

fn canonical_notary_planned_fixture_yaml() -> &'static str {
    r#"name: planned
classification: synthetic
input: { project_id: PW-002 }
interactions:
  - expect: { method: GET, path: /snapshot }
    respond: { status: 200, body: { status: planned } }
expect:
  outcome: match
  outputs: { status: planned }
  claims:
    project-record-exists: true
    project-status-accepted: false
"#
}

fn canonical_notary_no_match_fixture_yaml() -> &'static str {
    r#"name: no-match
classification: synthetic
input: { project_id: pw_999 }
interactions:
  - expect: { method: GET, path: /snapshot }
    respond: { status: 200, body: [] }
expect:
  outcome: no_match
  outputs: {}
  claims:
    project-record-exists: false
    project-status-accepted: false
"#
}

fn canonical_spreadsheet_binding(project_dir: &Path) -> Result<CanonicalSpreadsheetBinding> {
    let environment_path = project_dir.join(CANONICAL_LOCAL_ENVIRONMENT_FILE);
    ensure_no_symlink_components(project_dir, &environment_path)?;
    let metadata = fs::symlink_metadata(&environment_path)
        .map_err(|_| anyhow!("the canonical project is missing environments/local.yaml"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("environments/local.yaml must be a regular non-symlink file");
    }
    let contents = fs::read_to_string(&environment_path)
        .context("failed to read the canonical local environment")?;
    let document: serde_norway::Value = serde_norway::from_str(&contents)
        .context("failed to parse the canonical local environment")?;
    let local_api_keys = &document["relay"]["local_api_keys"];
    let match_principal = local_api_keys["match_principal"]
        .as_str()
        .ok_or_else(|| anyhow!("the local spreadsheet matching principal is absent"))?
        .to_string();
    if local_api_keys["no_match_principal"].as_str() != Some(CANONICAL_RUNTIME_NO_MATCH_PRINCIPAL) {
        bail!("the local spreadsheet maintained no-match principal is invalid");
    }
    let relay_audience = document["relay"]["audience"]
        .as_str()
        .ok_or_else(|| anyhow!("the local spreadsheet Relay audience is absent"))?
        .to_string();
    let has_notary_shape = !document["notary_relay"].is_null()
        || !document["deployment"]["notary"].is_null()
        || !document["callers"].is_null();
    let topology = if has_notary_shape {
        if relay_audience != CANONICAL_RUNTIME_WORKLOAD_AUDIENCE {
            bail!("the canonical local consultation Relay audience is unsupported");
        }
        if document["notary_relay"]["base_url"].as_str() != Some("http://127.0.0.1:8080")
            || document["notary_relay"]["workload_client_id"].as_str()
                != Some(CANONICAL_RUNTIME_WORKLOAD_CLIENT)
            || document["notary_relay"]["token_file"].as_str()
                != Some("/run/secrets/relay-workload-token")
            || document["deployment"]["notary"]["service"].as_str()
                != Some("registryctl-local-notary")
        {
            bail!("the canonical local Notary topology binding is incomplete or unsupported");
        }
        let callers = document["callers"]
            .as_mapping()
            .ok_or_else(|| anyhow!("the canonical local Notary callers are absent"))?;
        if callers.len() != 2 {
            bail!("the canonical local Notary must declare exactly two tutorial callers");
        }
        let full = &document["callers"]["public-works-service"];
        let under = &document["callers"]["public-works-under-scoped"];
        if full["api_key_fingerprint"]["secret"].as_str()
            != Some(CANONICAL_RUNTIME_NOTARY_CALLER_HASH_ENV)
            || under["api_key_fingerprint"]["secret"].as_str()
                != Some(CANONICAL_RUNTIME_NOTARY_UNDER_SCOPED_HASH_ENV)
            || full["scopes"]
                .as_sequence()
                .and_then(|values| (values.len() == 1).then(|| values[0].as_str()).flatten())
                != Some("evidence:projects:read")
            || under["scopes"]
                .as_sequence()
                .and_then(|values| (values.len() == 1).then(|| values[0].as_str()).flatten())
                != Some("evidence:projects:metadata")
        {
            bail!("the canonical local Notary caller bindings are incomplete or unsupported");
        }
        CanonicalRuntimeTopology::CombinedNotary
    } else {
        CanonicalRuntimeTopology::RelayOnly
    };
    let entities = document["entities"]
        .as_mapping()
        .ok_or_else(|| anyhow!("the canonical local environment must declare entities"))?;
    let mut bindings = Vec::new();
    for binding in entities.values() {
        let provider = &binding["provider"];
        if provider["type"].as_str() != Some("xlsx") {
            continue;
        }
        let project_file = provider["project_file"]
            .as_str()
            .ok_or_else(|| anyhow!("the XLSX provider must declare project_file"))?;
        let runtime_path = provider["path"]
            .as_str()
            .ok_or_else(|| anyhow!("the XLSX provider must declare its runtime path"))?;
        bindings.push((project_file.to_string(), runtime_path.to_string()));
    }
    if bindings.len() != 1 {
        bail!("the canonical local runtime requires exactly one declared XLSX project workbook");
    }
    let (project_file_text, runtime_path) = bindings.remove(0);
    let relative = Path::new(&project_file_text);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("the declared XLSX project_file must be a contained project-relative path");
    }
    if !runtime_path.starts_with('/')
        || runtime_path.contains(':')
        || Path::new(&runtime_path)
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("the declared XLSX runtime path must be a contained absolute container path");
    }
    let project_file = project_dir.join(relative);
    ensure_no_symlink_components(project_dir, &project_file)?;
    let metadata = fs::symlink_metadata(&project_file)
        .map_err(|_| anyhow!("the declared XLSX project workbook is missing"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("the declared XLSX project workbook must be a regular non-symlink file");
    }
    let (runtime_uid, runtime_gid) = compose_runtime_identity(project_dir)?;
    Ok(CanonicalSpreadsheetBinding {
        project_file_text,
        runtime_path,
        match_principal,
        topology,
        runtime_user: format!("{runtime_uid}:{runtime_gid}"),
        runtime_uid,
        runtime_gid,
    })
}

fn canonical_compose_document(
    images: &CanonicalRuntimeImages,
    binding: &CanonicalSpreadsheetBinding,
) -> Result<serde_json::Value> {
    let mut services = serde_json::Map::new();
    services.insert(
        "registry-relay".to_string(),
        serde_json::json!({
                "image": images.relay,
                "user": binding.runtime_user,
                "command": [
                    "--config",
                    CANONICAL_RELAY_CONFIG_MOUNT,
                    "--bind",
                    CANONICAL_RELAY_CONTAINER_PORT,
                ],
                "env_file": ["secrets/relay.env"],
                "ports": [CANONICAL_RELAY_HOST_PORT],
                "networks": ["public"],
                "volumes": [
                    format!("../../build/local/private/relay/config/relay.yaml:{CANONICAL_RELAY_CONFIG_MOUNT}:ro"),
                    format!("../../../{}:{}:ro", binding.project_file_text, binding.runtime_path),
                ],
                "read_only": true,
                "init": true,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "tmpfs": [
                    "/tmp:rw,noexec,nosuid,mode=1777,size=64m",
                    format!("/var/lib/registry-relay/cache:rw,noexec,nosuid,uid={},gid={},mode=0700,size=64m", binding.runtime_uid, binding.runtime_gid),
                ],
                "healthcheck": {
                    "test": ["CMD", "registry-relay", "healthcheck", "--url", "http://127.0.0.1:8080/ready"],
                    "interval": "2s",
                    "timeout": "5s",
                    "retries": 30,
                    "start_period": "2s",
                },
            }),
    );
    if binding.topology.has_notary() {
        let notary_image = images
            .notary
            .as_deref()
            .ok_or_else(|| anyhow!("the combined runtime is missing its locked Notary image"))?;
        let postgresql_image = images.postgresql.as_deref().ok_or_else(|| {
            anyhow!("the combined runtime is missing its locked PostgreSQL image")
        })?;
        services.insert(
            "notary-network".to_string(),
            serde_json::json!({
                "image": postgresql_image,
                "user": "70:70",
                "command": ["sleep", "infinity"],
                "ports": [CANONICAL_NOTARY_HOST_PORT],
                "networks": ["notary-internal", "notary-host"],
                "read_only": true,
                "init": true,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "healthcheck": {
                    "test": ["CMD", "pg_isready", "-h", "127.0.0.1", "-U", CANONICAL_RUNTIME_POSTGRES_USER, "-d", "postgres"],
                    "interval": "2s",
                    "timeout": "5s",
                    "retries": 30,
                    "start_period": "2s",
                },
            }),
        );
        services.insert(
            "postgresql".to_string(),
            serde_json::json!({
                "image": postgresql_image,
                "user": "70:70",
                "command": [
                    "sh",
                    "-eu",
                    "-c",
                    "umask 077\nprintf '%s' \"$$REGISTRYCTL_LOCAL_POSTGRES_TLS_CERTIFICATE_B64\" | base64 -d > /run/postgresql/server.crt\nprintf '%s' \"$$REGISTRYCTL_LOCAL_POSTGRES_TLS_PRIVATE_KEY_B64\" | base64 -d > /run/postgresql/server.key\nexec docker-entrypoint.sh postgres -c listen_addresses=127.0.0.1 -c ssl=on -c ssl_cert_file=/run/postgresql/server.crt -c ssl_key_file=/run/postgresql/server.key",
                ],
                "env_file": ["secrets/postgres.env"],
                "network_mode": "service:notary-network",
                "volumes": ["./private/db/init.sh:/docker-entrypoint-initdb.d/00-registryctl.sh:ro"],
                "read_only": true,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "tmpfs": [
                    "/var/lib/postgresql/data:rw,noexec,nosuid,uid=70,gid=70,mode=0700,size=256m",
                    "/run/postgresql:rw,noexec,nosuid,uid=70,gid=70,mode=0700,size=16m",
                    "/tmp:rw,noexec,nosuid,uid=70,gid=70,mode=0700,size=32m",
                ],
                "healthcheck": {
                    "test": ["CMD", "pg_isready", "-h", "127.0.0.1", "-U", CANONICAL_RUNTIME_POSTGRES_USER, "-d", "postgres"],
                    "interval": "2s",
                    "timeout": "5s",
                    "retries": 30,
                    "start_period": "2s",
                },
            }),
        );
        services.insert(
            "registry-relay-bootstrap".to_string(),
            serde_json::json!({
                "image": images.relay,
                "user": binding.runtime_user,
                "network_mode": "service:notary-network",
                "command": [
                    "consultation",
                    "bootstrap-state",
                    "--config",
                    CANONICAL_CONSULTATION_RELAY_CONFIG_MOUNT,
                    "--migration-database-url-env",
                    CANONICAL_RUNTIME_RELAY_MIGRATION_DATABASE_URL_ENV,
                    "--owner-role",
                    CANONICAL_RUNTIME_RELAY_DB_OWNER,
                    "--keyring-maintenance-database-url-env",
                    CANONICAL_RUNTIME_RELAY_MAINTENANCE_DATABASE_URL_ENV,
                    "--keyring-reader-database-url-env",
                    CANONICAL_RUNTIME_RELAY_READER_DATABASE_URL_ENV,
                    "--active-key-id",
                    "epoch-1",
                    "--active-write-deadline-unix-ms",
                    CANONICAL_RUNTIME_RELAY_KEY_WRITE_DEADLINE_MS,
                    "--audit-event-retention-ms",
                    CANONICAL_RUNTIME_RELAY_AUDIT_RETENTION_MS,
                ],
                "env_file": ["secrets/relay-bootstrap.env"],
                "volumes": [
                    "../../build/local/private/relay:/etc/registry-relay:ro",
                    "./private/relay/config:/etc/registry-relay/config:ro",
                    "../../build/local/private/relay/config/artifacts:/etc/registry-relay/config/artifacts:ro",
                ],
                "depends_on": {
                    "postgresql": {"condition": "service_healthy"},
                },
                "restart": "no",
                "read_only": true,
                "init": true,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "tmpfs": ["/tmp:rw,noexec,nosuid,mode=1777,size=64m"],
            }),
        );
        services.insert(
            "registry-notary".to_string(),
            serde_json::json!({
                "image": notary_image,
                "user": binding.runtime_user,
                "network_mode": "service:notary-network",
                "command": [
                    "--config",
                    CANONICAL_NOTARY_CONFIG_MOUNT,
                    "--bind",
                    CANONICAL_NOTARY_CONTAINER_PORT,
                ],
                "env_file": ["secrets/notary.env"],
                "volumes": [
                    format!("./private/notary/config/notary.yaml:{CANONICAL_NOTARY_CONFIG_MOUNT}:ro"),
                    format!("./secrets/relay-workload-token:/run/secrets/relay-workload-token:ro"),
                ],
                "depends_on": {
                    "postgresql": {"condition": "service_healthy"},
                    "registry-relay-bootstrap": {"condition": "service_completed_successfully"},
                    "registry-relay-consultation": {"condition": "service_healthy"},
                },
                "read_only": true,
                "init": true,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "tmpfs": ["/tmp:rw,noexec,nosuid,mode=1777,size=64m"],
                "healthcheck": {
                    "test": ["CMD", "registry-notary", "healthcheck", "--url", "http://127.0.0.1:8081/ready"],
                    "interval": "2s",
                    "timeout": "5s",
                    "retries": 30,
                    "start_period": "2s",
                },
            }),
        );
        services.insert(
            "registry-relay-consultation".to_string(),
            serde_json::json!({
                "image": images.relay,
                "user": binding.runtime_user,
                "command": [
                    "--config",
                    CANONICAL_CONSULTATION_RELAY_CONFIG_MOUNT,
                    "--bind",
                    "127.0.0.1:8080",
                ],
                "env_file": ["secrets/relay-consultation.env"],
                "network_mode": "service:notary-network",
                "volumes": [
                    format!("../../build/local/private/relay:/etc/registry-relay:ro"),
                    format!("../../../{}:{}:ro", binding.project_file_text, binding.runtime_path),
                    "./private/relay/config:/etc/registry-relay/config:ro",
                    "../../build/local/private/relay/config/artifacts:/etc/registry-relay/config/artifacts:ro",
                ],
                "depends_on": {
                    "postgresql": {"condition": "service_healthy"},
                    "registry-relay-bootstrap": {"condition": "service_completed_successfully"},
                },
                "read_only": true,
                "init": true,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "tmpfs": [
                    "/tmp:rw,noexec,nosuid,mode=1777,size=64m",
                    format!("/var/lib/registry-relay/cache:rw,noexec,nosuid,uid={},gid={},mode=0700,size=64m", binding.runtime_uid, binding.runtime_gid),
                ],
                "healthcheck": {
                    "test": ["CMD", "registry-relay", "healthcheck", "--url", "http://127.0.0.1:8080/ready"],
                    "interval": "2s",
                    "timeout": "5s",
                    "retries": 30,
                    "start_period": "2s",
                },
            }),
        );
    } else if images.notary.is_some() || images.postgresql.is_some() {
        bail!("Relay-only runtime received unused product images");
    }
    let mut networks = serde_json::Map::new();
    networks.insert("public".to_string(), serde_json::json!({}));
    if binding.topology.has_notary() {
        networks.insert(
            "notary-internal".to_string(),
            serde_json::json!({"internal": true}),
        );
        networks.insert("notary-host".to_string(), serde_json::json!({}));
    }
    Ok(serde_json::json!({
        "services": services,
        "networks": networks,
    }))
}

fn render_canonical_compose(
    images: &CanonicalRuntimeImages,
    binding: &CanonicalSpreadsheetBinding,
) -> Result<String> {
    let document = canonical_compose_document(images, binding)?;
    let rendered =
        serde_norway::to_string(&document).context("failed to render the local Compose file")?;
    validate_canonical_compose(&rendered, images, binding)?;
    Ok(rendered)
}

fn validate_canonical_compose(
    contents: &str,
    images: &CanonicalRuntimeImages,
    binding: &CanonicalSpreadsheetBinding,
) -> Result<()> {
    let actual: serde_json::Value =
        serde_norway::from_str(contents).context("generated local Compose did not parse")?;
    if actual != canonical_compose_document(images, binding)? {
        bail!("generated local Compose does not match the closed runtime contract");
    }
    Ok(())
}

fn digest_path(path: &Path, label: &'static str) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {label}"))?;
    Ok(sha256_uri(&bytes))
}

fn validate_private_file_mode(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("private runtime input must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            bail!("private runtime input must use Unix mode 0600");
        }
    }
    Ok(())
}

fn validate_runtime_nonsecret_file_mode(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("runtime input must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o777 != 0o644 {
            bail!("non-secret container runtime input must use Unix mode 0644");
        }
    }
    Ok(())
}

fn validate_private_dir_mode(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("private runtime directory must be a real directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            bail!("private runtime directory must use Unix mode 0700");
        }
    }
    Ok(())
}

fn validate_compiled_artifact_manifest(project_dir: &Path, check_inputs: bool) -> Result<()> {
    let manifest_path = project_dir.join(CANONICAL_ARTIFACT_MANIFEST);
    ensure_no_symlink_components(project_dir, &manifest_path)?;
    let bytes = fs::read(&manifest_path)
        .context("failed to read the generated project artifact manifest")?;
    let manifest: ProjectArtifactManifestV1 = serde_json::from_slice(&bytes)
        .context("failed to parse the generated project artifact manifest")?;
    if manifest.environment != CANONICAL_LOCAL_ENVIRONMENT {
        bail!("generated project artifact manifest has the wrong environment");
    }
    for artifact in &manifest.artifacts {
        let path = project_dir.join(artifact.path.as_str());
        ensure_no_symlink_components(project_dir, &path)?;
        if digest_path(&path, "generated project artifact")? != artifact.digest.as_str() {
            bail!("generated project artifact integrity check failed");
        }
    }
    if check_inputs {
        for input in &manifest.inputs {
            let path = project_dir.join(input.path.as_str());
            ensure_no_symlink_components(project_dir, &path)
                .map_err(|_| anyhow!("generated project input containment check failed"))?;
            let label = match input.classification {
                ArtifactInputClassification::AuthoredProjectInput => "authored project input",
                ArtifactInputClassification::OperatorOwnedSourceData => {
                    "operator-owned source data"
                }
            };
            if digest_path(&path, label)? != input.digest.as_str() {
                match input.classification {
                    ArtifactInputClassification::AuthoredProjectInput => {
                        bail!("the authored project changed after the local runtime was compiled")
                    }
                    ArtifactInputClassification::OperatorOwnedSourceData => {
                        bail!(
                            "operator-owned source data changed after the local runtime was compiled"
                        )
                    }
                }
            }
        }
    }
    Ok(())
}

fn compiled_workbook_input(
    project_dir: &Path,
    binding: &CanonicalSpreadsheetBinding,
) -> Result<ArtifactInputDigest> {
    let manifest_path = project_dir.join(CANONICAL_ARTIFACT_MANIFEST);
    ensure_no_symlink_components(project_dir, &manifest_path)
        .map_err(|_| anyhow!("generated project artifact manifest containment check failed"))?;
    let manifest: ProjectArtifactManifestV1 = serde_json::from_slice(
        &fs::read(&manifest_path)
            .context("failed to read the generated project artifact manifest")?,
    )
    .context("failed to parse the generated project artifact manifest")?;
    let matches = manifest
        .inputs
        .into_iter()
        .filter(|input| input.path.as_str() == binding.project_file_text)
        .collect::<Vec<_>>();
    if matches.len() != 1
        || matches[0].classification != ArtifactInputClassification::OperatorOwnedSourceData
    {
        bail!(
            "generated project artifact manifest must contain the exact classified workbook input"
        );
    }
    Ok(matches.into_iter().next().expect("one workbook input"))
}

fn validate_compiled_local_relay_auth(
    relay_config: &Path,
    binding: &CanonicalSpreadsheetBinding,
) -> Result<()> {
    let contents =
        fs::read_to_string(relay_config).context("failed to read the compiled Relay config")?;
    let config: serde_norway::Value =
        serde_norway::from_str(&contents).context("failed to parse the compiled Relay config")?;
    if config["auth"]["mode"].as_str() != Some("api_key") {
        bail!("the compiled local spreadsheet Relay must use API-key authentication");
    }
    let keys = config["auth"]["api_keys"]
        .as_sequence()
        .ok_or_else(|| anyhow!("compiled local Relay API keys are absent"))?;
    if keys.len() != 2 {
        bail!("compiled local Relay must contain exactly two synthetic principals");
    }
    let expected = [
        (
            binding.match_principal.as_str(),
            CANONICAL_RUNTIME_MATCH_HASH_ENV,
        ),
        (
            CANONICAL_RUNTIME_NO_MATCH_PRINCIPAL,
            CANONICAL_RUNTIME_NO_MATCH_HASH_ENV,
        ),
    ];
    let mut expected_scopes: Option<Vec<&str>> = None;
    for (principal, fingerprint_env) in expected {
        let key = keys
            .iter()
            .find(|key| key["id"].as_str() == Some(principal))
            .ok_or_else(|| anyhow!("compiled local Relay principal binding is absent"))?;
        if key["fingerprint"]["provider"].as_str() != Some("env")
            || key["fingerprint"]["name"].as_str() != Some(fingerprint_env)
        {
            bail!("compiled local Relay fingerprint binding is not closed");
        }
        let scopes = key["scopes"]
            .as_sequence()
            .ok_or_else(|| anyhow!("compiled local Relay scopes are absent"))?
            .iter()
            .map(|scope| {
                scope
                    .as_str()
                    .ok_or_else(|| anyhow!("compiled local Relay scope is invalid"))
            })
            .collect::<Result<Vec<_>>>()?;
        if scopes.is_empty()
            || expected_scopes
                .as_ref()
                .is_some_and(|expected| expected != &scopes)
        {
            bail!("compiled local Relay principals must share non-empty reviewed scopes");
        }
        expected_scopes = Some(scopes);
    }
    if contents.contains(CANONICAL_RUNTIME_MATCH_RAW_ENV)
        || contents.contains(CANONICAL_RUNTIME_NO_MATCH_RAW_ENV)
    {
        bail!("compiled local Relay config must not reference raw API keys");
    }
    Ok(())
}

fn render_runtime_notary_config(compiled_path: &Path) -> Result<String> {
    let contents =
        fs::read_to_string(compiled_path).context("failed to read the compiled Notary config")?;
    let mut config: serde_json::Value =
        serde_norway::from_str(&contents).context("failed to parse the compiled Notary config")?;
    if config["state"]["storage"].as_str() != Some("in_memory")
        || config["evidence"]["relay"]["base_url"].as_str() != Some("http://127.0.0.1:8080")
        || config["evidence"]["relay"]["workload_client_id"].as_str()
            != Some(CANONICAL_RUNTIME_WORKLOAD_CLIENT)
        || config["evidence"]["relay"]["token_file"].as_str()
            != Some("/run/secrets/relay-workload-token")
    {
        bail!("compiled Notary config does not match the local evaluation-only topology");
    }
    let api_keys = config["auth"]["api_keys"]
        .as_array()
        .ok_or_else(|| anyhow!("compiled Notary API-key callers are absent"))?;
    if api_keys.len() != 2 {
        bail!("compiled Notary must contain exactly two tutorial callers");
    }
    let exact_caller = |id: &str, fingerprint_env: &str, scope: &str| {
        api_keys.iter().any(|entry| {
            entry["id"].as_str() == Some(id)
                && entry["fingerprint"]["provider"].as_str() == Some("env")
                && entry["fingerprint"]["name"].as_str() == Some(fingerprint_env)
                && entry["scopes"]
                    .as_array()
                    .is_some_and(|scopes| scopes.len() == 1 && scopes[0].as_str() == Some(scope))
        })
    };
    if !exact_caller(
        "public-works-service",
        CANONICAL_RUNTIME_NOTARY_CALLER_HASH_ENV,
        "evidence:projects:read",
    ) || !exact_caller(
        "public-works-under-scoped",
        CANONICAL_RUNTIME_NOTARY_UNDER_SCOPED_HASH_ENV,
        "evidence:projects:metadata",
    ) {
        bail!("compiled Notary caller scope contract is not exact");
    }
    // The local runtime may execute the amd64 release image under Docker's
    // architecture emulation. Keep one bounded worker and the product's
    // maximum permitted address-space ceiling so startup remains reliable
    // without widening evaluation concurrency.
    config["cel"]["worker_count"] = serde_json::json!(1);
    config["cel"]["worker_memory_bytes"] = serde_json::json!(1024 * 1024 * 1024_u64);
    config["evidence"]["signing_keys"][CANONICAL_RUNTIME_NOTARY_SIGNING_KID] = serde_json::json!({
        "provider": "local_jwk_env",
        "private_jwk_env": CANONICAL_RUNTIME_NOTARY_SIGNING_JWK_ENV,
        "alg": "EdDSA",
        "kid": CANONICAL_RUNTIME_NOTARY_SIGNING_KID,
        "status": "active",
    });
    config["evidence"]["signing_keys"][CANONICAL_RUNTIME_WORKLOAD_KID] = serde_json::json!({
        "provider": "local_jwk_env",
        "public_jwk_env": CANONICAL_RUNTIME_WORKLOAD_JWK_ENV,
        "alg": "EdDSA",
        "kid": CANONICAL_RUNTIME_WORKLOAD_KID,
        "status": "publish_only",
    });
    let rendered =
        serde_norway::to_string(&config).context("failed to render the runtime Notary config")?;
    let parsed: StandaloneRegistryNotaryConfig = serde_norway::from_str(&rendered)
        .context("runtime Notary config failed product parsing")?;
    parsed
        .validate()
        .context("runtime Notary config failed product validation")?;
    Ok(rendered)
}

fn render_runtime_consultation_relay_config(compiled_path: &Path) -> Result<String> {
    let contents = fs::read_to_string(compiled_path)
        .context("failed to read the compiled consultation Relay config")?;
    let mut config: serde_json::Value = serde_norway::from_str(&contents)
        .context("failed to parse the compiled consultation Relay config")?;
    if config["auth"]["mode"].as_str() != Some("oidc")
        || config["auth"]["oidc"]["issuer"].as_str() != Some(CANONICAL_RUNTIME_WORKLOAD_ISSUER)
        || config["consultation"]["state_plane"]["database_url_env"].as_str()
            != Some(CANONICAL_RUNTIME_RELAY_DATABASE_URL_ENV)
    {
        bail!("compiled consultation Relay config does not match the exact local topology");
    }
    config["server"]["cache_dir"] =
        serde_json::Value::String("/var/lib/registry-relay/cache".to_string());
    config["consultation"]["state_plane"]["root_certificate_path"] =
        serde_json::Value::String(CANONICAL_POSTGRES_CA_MOUNT.to_string());
    let rendered = serde_norway::to_string(&config)
        .context("failed to render the runtime consultation Relay config")?;
    let _: registry_relay::config::Config = serde_norway::from_str(&rendered)
        .context("runtime consultation Relay config failed product parsing")?;
    Ok(rendered)
}

#[derive(Clone, Debug)]
struct CanonicalRuntimeCredentials {
    audit_secret: String,
    match_raw: String,
    match_hash: String,
    no_match_raw: String,
    no_match_hash: String,
    notary: Option<CanonicalNotaryRuntimeCredentials>,
}

#[derive(Clone, Debug)]
struct CanonicalNotaryRuntimeCredentials {
    audit_secret: String,
    consultation_audit_secret: String,
    pseudonym_key: String,
    caller_raw: String,
    caller_hash: String,
    under_scoped_raw: String,
    under_scoped_hash: String,
    postgres_admin_password: String,
    relay_database_password: String,
    relay_maintenance_database_password: String,
    relay_reader_database_password: String,
    postgres_tls_certificate: String,
    postgres_tls_private_key: String,
    workload_private_jwk: String,
    workload_public_jwk: String,
    workload_jwks: String,
    notary_signing_private_jwk: String,
}

impl CanonicalRuntimeCredentials {
    fn generate() -> Result<Self> {
        let match_raw = random_token(32)?;
        let no_match_raw = random_token(32)?;
        validate_api_key_entropy(&match_raw)?;
        validate_api_key_entropy(&no_match_raw)?;
        Ok(Self {
            audit_secret: random_token(48)?,
            match_hash: fingerprint_api_key(&match_raw),
            match_raw,
            no_match_hash: fingerprint_api_key(&no_match_raw),
            no_match_raw,
            notary: None,
        })
    }

    fn enable_notary(mut self) -> Result<Self> {
        let caller_raw = random_token(32)?;
        let under_scoped_raw = random_token(32)?;
        validate_api_key_entropy(&caller_raw)?;
        validate_api_key_entropy(&under_scoped_raw)?;
        let (workload_private_jwk, workload_public_jwk) =
            generate_ed25519_jwk(CANONICAL_RUNTIME_WORKLOAD_KID)?;
        let workload_jwks = workload_jwks_from_private(&workload_private_jwk)?;
        let (notary_signing_private_jwk, _) =
            generate_ed25519_jwk(CANONICAL_RUNTIME_NOTARY_SIGNING_KID)?;
        let (postgres_tls_certificate, postgres_tls_private_key) =
            generate_loopback_postgres_tls_identity()?;
        self.notary = Some(CanonicalNotaryRuntimeCredentials {
            audit_secret: random_token(48)?,
            consultation_audit_secret: random_token(48)?,
            pseudonym_key: random_token(48)?,
            caller_hash: fingerprint_api_key(&caller_raw),
            caller_raw,
            under_scoped_hash: fingerprint_api_key(&under_scoped_raw),
            under_scoped_raw,
            postgres_admin_password: random_token(32)?,
            relay_database_password: random_token(32)?,
            relay_maintenance_database_password: random_token(32)?,
            relay_reader_database_password: random_token(32)?,
            postgres_tls_certificate,
            postgres_tls_private_key,
            workload_private_jwk,
            workload_public_jwk,
            workload_jwks,
            notary_signing_private_jwk,
        });
        validate_distinct_runtime_credentials(&self)?;
        Ok(self)
    }

    fn relay_env_file(&self) -> String {
        format!(
            "{CANONICAL_RUNTIME_AUDIT_SECRET_ENV}={}\n\
             {}={}\n\
             {}={}\n",
            self.audit_secret,
            CANONICAL_RUNTIME_MATCH_HASH_ENV,
            self.match_hash,
            CANONICAL_RUNTIME_NO_MATCH_HASH_ENV,
            self.no_match_hash,
        )
    }

    fn client_env_file(&self) -> String {
        let mut rendered = format!(
            "{CANONICAL_RUNTIME_MATCH_RAW_ENV}={}\n\
             {CANONICAL_RUNTIME_NO_MATCH_RAW_ENV}={}\n",
            self.match_raw, self.no_match_raw,
        );
        if let Some(notary) = &self.notary {
            rendered.push_str(&format!(
                "{CANONICAL_RUNTIME_NOTARY_CALLER_RAW_ENV}={}\n\
                 {CANONICAL_RUNTIME_NOTARY_UNDER_SCOPED_RAW_ENV}={}\n",
                notary.caller_raw, notary.under_scoped_raw,
            ));
        }
        rendered
    }
}

impl CanonicalNotaryRuntimeCredentials {
    fn notary_env_file(&self) -> String {
        format!(
            "{CANONICAL_RUNTIME_NOTARY_AUDIT_SECRET_ENV}={}\n\
             {CANONICAL_RUNTIME_NOTARY_CALLER_HASH_ENV}={}\n\
             {CANONICAL_RUNTIME_NOTARY_UNDER_SCOPED_HASH_ENV}={}\n\
             {CANONICAL_RUNTIME_NOTARY_SIGNING_JWK_ENV}={}\n\
             {CANONICAL_RUNTIME_WORKLOAD_JWK_ENV}={}\n",
            self.audit_secret,
            self.caller_hash,
            self.under_scoped_hash,
            self.notary_signing_private_jwk,
            self.workload_public_jwk,
        )
    }

    fn consultation_relay_env_file(&self) -> String {
        format!(
            "{CANONICAL_RUNTIME_CONSULTATION_AUDIT_SECRET_ENV}={}\n\
             {CANONICAL_RUNTIME_RELAY_DATABASE_URL_ENV}=postgresql://{}:{}@127.0.0.1:5432/{}?sslmode=require\n\
             {CANONICAL_RUNTIME_PSEUDONYM_ENV}={}\n",
            self.consultation_audit_secret,
            CANONICAL_RUNTIME_RELAY_DB_USER,
            self.relay_database_password,
            CANONICAL_RUNTIME_RELAY_DB,
            self.pseudonym_key,
        )
    }

    fn relay_bootstrap_env_file(&self) -> String {
        format!(
            "{CANONICAL_RUNTIME_CONSULTATION_AUDIT_SECRET_ENV}={}\n\
             {CANONICAL_RUNTIME_PSEUDONYM_ENV}={}\n\
             {CANONICAL_RUNTIME_RELAY_DATABASE_URL_ENV}=postgresql://{}:{}@127.0.0.1:5432/{}?sslmode=require\n\
             {CANONICAL_RUNTIME_RELAY_MIGRATION_DATABASE_URL_ENV}=postgresql://{}:{}@127.0.0.1:5432/{}?sslmode=require\n\
             {CANONICAL_RUNTIME_RELAY_MAINTENANCE_DATABASE_URL_ENV}=postgresql://{}:{}@127.0.0.1:5432/{}?sslmode=require\n\
             {CANONICAL_RUNTIME_RELAY_READER_DATABASE_URL_ENV}=postgresql://{}:{}@127.0.0.1:5432/{}?sslmode=require\n",
            self.consultation_audit_secret,
            self.pseudonym_key,
            CANONICAL_RUNTIME_RELAY_DB_USER,
            self.relay_database_password,
            CANONICAL_RUNTIME_RELAY_DB,
            CANONICAL_RUNTIME_POSTGRES_USER,
            self.postgres_admin_password,
            CANONICAL_RUNTIME_RELAY_DB,
            CANONICAL_RUNTIME_RELAY_DB_MAINTENANCE_USER,
            self.relay_maintenance_database_password,
            CANONICAL_RUNTIME_RELAY_DB,
            CANONICAL_RUNTIME_RELAY_DB_READER_USER,
            self.relay_reader_database_password,
            CANONICAL_RUNTIME_RELAY_DB,
        )
    }

    fn postgres_env_file(&self) -> String {
        format!(
            "{CANONICAL_RUNTIME_POSTGRES_USER_ENV}={CANONICAL_RUNTIME_POSTGRES_USER}\n\
             {CANONICAL_RUNTIME_POSTGRES_PASSWORD_ENV}={}\n\
             {CANONICAL_RUNTIME_RELAY_DB_PASSWORD_ENV}={}\n\
             {CANONICAL_RUNTIME_RELAY_MAINTENANCE_DB_PASSWORD_ENV}={}\n\
             {CANONICAL_RUNTIME_RELAY_READER_DB_PASSWORD_ENV}={}\n\
             {CANONICAL_RUNTIME_POSTGRES_TLS_CERTIFICATE_ENV}={}\n\
             {CANONICAL_RUNTIME_POSTGRES_TLS_PRIVATE_KEY_ENV}={}\n\
             PGDATA=/var/lib/postgresql/data/pgdata\n",
            self.postgres_admin_password,
            self.relay_database_password,
            self.relay_maintenance_database_password,
            self.relay_reader_database_password,
            base64::engine::general_purpose::STANDARD
                .encode(self.postgres_tls_certificate.as_bytes()),
            base64::engine::general_purpose::STANDARD
                .encode(self.postgres_tls_private_key.as_bytes()),
        )
    }

    fn database_init_sql(&self) -> String {
        format!(
            "#!/bin/sh\n\
             set -eu\n\
             psql --set=ON_ERROR_STOP=1 --username \"$POSTGRES_USER\" --dbname postgres \\\n\
               --set=relay_password=\"$REGISTRYCTL_LOCAL_RELAY_DATABASE_PASSWORD\" \\\n\
               --set=maintenance_password=\"${CANONICAL_RUNTIME_RELAY_MAINTENANCE_DB_PASSWORD_ENV}\" \\\n\
               --set=reader_password=\"${CANONICAL_RUNTIME_RELAY_READER_DB_PASSWORD_ENV}\" <<'SQL'\n\
             CREATE ROLE {CANONICAL_RUNTIME_RELAY_DB_OWNER} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;\n\
             CREATE ROLE {CANONICAL_RUNTIME_RELAY_DB_USER} LOGIN PASSWORD :'relay_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;\n\
             CREATE ROLE {CANONICAL_RUNTIME_RELAY_DB_MAINTENANCE_USER} LOGIN PASSWORD :'maintenance_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;\n\
             CREATE ROLE {CANONICAL_RUNTIME_RELAY_DB_READER_USER} LOGIN PASSWORD :'reader_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;\n\
             CREATE DATABASE {CANONICAL_RUNTIME_RELAY_DB};\n\
             REVOKE ALL ON DATABASE {CANONICAL_RUNTIME_RELAY_DB} FROM PUBLIC;\n\
             GRANT CREATE ON DATABASE {CANONICAL_RUNTIME_RELAY_DB} TO {CANONICAL_RUNTIME_RELAY_DB_OWNER};\n\
             GRANT CONNECT ON DATABASE {CANONICAL_RUNTIME_RELAY_DB} TO {CANONICAL_RUNTIME_RELAY_DB_USER}, {CANONICAL_RUNTIME_RELAY_DB_MAINTENANCE_USER}, {CANONICAL_RUNTIME_RELAY_DB_READER_USER};\n\
             SQL\n"
        )
    }

    fn workload_token(&self) -> Result<String> {
        sign_workload_jwt(&self.workload_private_jwk)
    }
}

fn generate_loopback_postgres_tls_identity() -> Result<(String, String)> {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
            .context("failed to generate the local PostgreSQL TLS identity")?;
    Ok((
        pem_block("CERTIFICATE", cert.der().as_ref()),
        pem_block("PRIVATE KEY", &key_pair.serialize_der()),
    ))
}

fn pem_block(label: &str, der: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let body = encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).expect("base64 is ASCII"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

fn generate_ed25519_jwk(kid: &str) -> Result<(String, String)> {
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret).map_err(|error| anyhow!("random generation failed: {error}"))?;
    let signing_key = SigningKey::from_bytes(&secret);
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(signing_key.verifying_key().as_bytes());
    let d = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);
    let private = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "d": d,
        "x": x.clone(),
        "alg": "EdDSA",
        "kid": kid,
    });
    let public = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
        "alg": "EdDSA",
        "kid": kid,
        "use": "sig",
    });
    Ok((
        serde_json::to_string(&private).context("failed to render workload private JWK")?,
        serde_json::to_string(&public).context("failed to render workload public JWK")?,
    ))
}

fn sign_workload_jwt(private_jwk: &str) -> Result<String> {
    let jwk: serde_json::Value =
        serde_json::from_str(private_jwk).context("failed to parse workload private JWK")?;
    let encoded_secret = jwk["d"]
        .as_str()
        .ok_or_else(|| anyhow!("workload private JWK is missing its private member"))?;
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_secret)
        .context("workload private JWK contains an invalid private member")?;
    let secret: [u8; 32] = secret
        .try_into()
        .map_err(|_| anyhow!("workload private JWK has the wrong private member length"))?;
    let signing_key = SigningKey::from_bytes(&secret);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let header = serde_json::json!({
        "alg": "EdDSA",
        "kid": CANONICAL_RUNTIME_WORKLOAD_KID,
        "typ": "at+jwt",
    });
    let claims = serde_json::json!({
        "iss": CANONICAL_RUNTIME_WORKLOAD_ISSUER,
        "sub": CANONICAL_RUNTIME_WORKLOAD_CLIENT,
        "aud": CANONICAL_RUNTIME_WORKLOAD_AUDIENCE,
        "client_id": CANONICAL_RUNTIME_WORKLOAD_CLIENT,
        "azp": CANONICAL_RUNTIME_WORKLOAD_CLIENT,
        "scope": CANONICAL_RUNTIME_WORKLOAD_SCOPE,
        "iat": now,
        "nbf": now.saturating_sub(1),
        "exp": now + CANONICAL_RUNTIME_WORKLOAD_TTL_SECONDS,
        "jti": random_token(16)?,
    });
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).context("failed to render workload JWT header")?);
    let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&claims).context("failed to render workload JWT claims")?);
    let signing_input = format!("{header}.{claims}");
    let signature = signing_key.sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn validate_distinct_runtime_credentials(credentials: &CanonicalRuntimeCredentials) -> Result<()> {
    let Some(notary) = &credentials.notary else {
        return Ok(());
    };
    let values = [
        credentials.audit_secret.as_str(),
        credentials.match_raw.as_str(),
        credentials.no_match_raw.as_str(),
        notary.audit_secret.as_str(),
        notary.consultation_audit_secret.as_str(),
        notary.pseudonym_key.as_str(),
        notary.caller_raw.as_str(),
        notary.under_scoped_raw.as_str(),
        notary.postgres_admin_password.as_str(),
        notary.relay_database_password.as_str(),
        notary.relay_maintenance_database_password.as_str(),
        notary.relay_reader_database_password.as_str(),
        notary.postgres_tls_private_key.as_str(),
        notary.workload_private_jwk.as_str(),
        notary.notary_signing_private_jwk.as_str(),
    ];
    if values.iter().copied().collect::<BTreeSet<_>>().len() != values.len() {
        bail!("local runtime credentials were reused across trust boundaries");
    }
    Ok(())
}

fn strict_runtime_credentials(
    relay_path: &Path,
    client_path: &Path,
) -> Result<CanonicalRuntimeCredentials> {
    validate_private_file_mode(relay_path)?;
    validate_private_file_mode(client_path)?;
    let relay_contents =
        fs::read_to_string(relay_path).context("failed to read Relay runtime credentials")?;
    let client_contents =
        fs::read_to_string(client_path).context("failed to read local client credentials")?;
    let relay_values = parse_local_env(&relay_contents);
    let client_values = parse_local_env(&client_contents);
    let relay_expected = [
        CANONICAL_RUNTIME_AUDIT_SECRET_ENV,
        CANONICAL_RUNTIME_MATCH_HASH_ENV,
        CANONICAL_RUNTIME_NO_MATCH_HASH_ENV,
    ];
    let client_expected = [
        CANONICAL_RUNTIME_MATCH_RAW_ENV,
        CANONICAL_RUNTIME_NO_MATCH_RAW_ENV,
    ];
    if relay_values.len() != relay_expected.len()
        || relay_expected
            .iter()
            .any(|name| !relay_values.contains_key(*name))
        || !matches!(client_values.len(), 2 | 4)
        || client_expected
            .iter()
            .any(|name| !client_values.contains_key(*name))
    {
        bail!("local runtime credentials contain unexpected entries");
    }
    let relay_required = |name: &str| {
        relay_values
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow!("local runtime credentials have an unexpected shape"))
    };
    let client_required = |name: &str| {
        client_values
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow!("local runtime credentials have an unexpected shape"))
    };
    let credentials = CanonicalRuntimeCredentials {
        audit_secret: relay_required(CANONICAL_RUNTIME_AUDIT_SECRET_ENV)?,
        match_raw: client_required(CANONICAL_RUNTIME_MATCH_RAW_ENV)?,
        match_hash: relay_required(CANONICAL_RUNTIME_MATCH_HASH_ENV)?,
        no_match_raw: client_required(CANONICAL_RUNTIME_NO_MATCH_RAW_ENV)?,
        no_match_hash: relay_required(CANONICAL_RUNTIME_NO_MATCH_HASH_ENV)?,
        notary: None,
    };
    if credentials.audit_secret.len() < 32 {
        bail!("local runtime credentials do not meet the minimum entropy shape");
    }
    validate_api_key_entropy(&credentials.match_raw)
        .map_err(|_| anyhow!("local runtime credentials do not meet the minimum entropy shape"))?;
    validate_api_key_entropy(&credentials.no_match_raw)
        .map_err(|_| anyhow!("local runtime credentials do not meet the minimum entropy shape"))?;
    if fingerprint_api_key(&credentials.match_raw) != credentials.match_hash
        || fingerprint_api_key(&credentials.no_match_raw) != credentials.no_match_hash
    {
        bail!("local runtime raw keys and fingerprints do not match");
    }
    Ok(credentials)
}

fn strict_canonical_runtime_credentials(
    project_dir: &Path,
    topology: CanonicalRuntimeTopology,
) -> Result<CanonicalRuntimeCredentials> {
    let mut credentials = strict_runtime_credentials(
        &project_dir.join(CANONICAL_RUNTIME_RELAY_ENV),
        &project_dir.join(CANONICAL_RUNTIME_ENV),
    )?;
    if !topology.has_notary() {
        let client = parse_local_env(
            &fs::read_to_string(project_dir.join(CANONICAL_RUNTIME_ENV))
                .context("failed to read local client credentials")?,
        );
        if client.len() != 2 {
            bail!("Relay-only runtime credentials contain unexpected entries");
        }
        return Ok(credentials);
    }
    let notary_env_path = project_dir.join(CANONICAL_RUNTIME_NOTARY_ENV);
    let consultation_env_path = project_dir.join(CANONICAL_RUNTIME_CONSULTATION_RELAY_ENV);
    let relay_bootstrap_env_path = project_dir.join(CANONICAL_RUNTIME_RELAY_BOOTSTRAP_ENV);
    let postgres_env_path = project_dir.join(CANONICAL_RUNTIME_POSTGRES_ENV);
    let workload_token_path = project_dir.join(CANONICAL_RUNTIME_WORKLOAD_TOKEN);
    let workload_private_jwk_path = project_dir.join(CANONICAL_RUNTIME_WORKLOAD_PRIVATE_JWK);
    let database_init_path = project_dir.join(CANONICAL_RUNTIME_DB_INIT);
    let workload_jwks_path = project_dir.join(CANONICAL_RUNTIME_WORKLOAD_JWKS);
    let postgres_ca_path = project_dir.join(CANONICAL_RUNTIME_POSTGRES_CA);
    for path in [
        &notary_env_path,
        &consultation_env_path,
        &relay_bootstrap_env_path,
        &postgres_env_path,
        &workload_token_path,
        &workload_private_jwk_path,
        &workload_jwks_path,
    ] {
        validate_private_file_mode(path)?;
    }
    validate_runtime_nonsecret_file_mode(&database_init_path)?;
    validate_runtime_nonsecret_file_mode(&postgres_ca_path)?;
    let notary_values = parse_local_env(
        &fs::read_to_string(&notary_env_path)
            .context("failed to read Notary runtime credentials")?,
    );
    let consultation_values = parse_local_env(
        &fs::read_to_string(&consultation_env_path)
            .context("failed to read consultation Relay runtime credentials")?,
    );
    let postgres_values = parse_local_env(
        &fs::read_to_string(&postgres_env_path)
            .context("failed to read PostgreSQL runtime credentials")?,
    );
    let client_values = parse_local_env(
        &fs::read_to_string(project_dir.join(CANONICAL_RUNTIME_ENV))
            .context("failed to read local client credentials")?,
    );
    let required = |values: &BTreeMap<String, String>, name: &str| {
        values
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow!("combined runtime credentials have an unexpected shape"))
    };
    if notary_values.len() != 5
        || consultation_values.len() != 3
        || postgres_values.len() != 8
        || client_values.len() != 4
        || postgres_values
            .get(CANONICAL_RUNTIME_POSTGRES_USER_ENV)
            .map(String::as_str)
            != Some(CANONICAL_RUNTIME_POSTGRES_USER)
        || postgres_values.get("PGDATA").map(String::as_str)
            != Some("/var/lib/postgresql/data/pgdata")
    {
        bail!("combined runtime credentials contain unexpected entries");
    }
    let caller_raw = required(&client_values, CANONICAL_RUNTIME_NOTARY_CALLER_RAW_ENV)?;
    let under_scoped_raw = required(
        &client_values,
        CANONICAL_RUNTIME_NOTARY_UNDER_SCOPED_RAW_ENV,
    )?;
    validate_api_key_entropy(&caller_raw).map_err(|_| {
        anyhow!("combined runtime credentials do not meet the minimum entropy shape")
    })?;
    validate_api_key_entropy(&under_scoped_raw).map_err(|_| {
        anyhow!("combined runtime credentials do not meet the minimum entropy shape")
    })?;
    let notary = CanonicalNotaryRuntimeCredentials {
        audit_secret: required(&notary_values, CANONICAL_RUNTIME_NOTARY_AUDIT_SECRET_ENV)?,
        consultation_audit_secret: required(
            &consultation_values,
            CANONICAL_RUNTIME_CONSULTATION_AUDIT_SECRET_ENV,
        )?,
        pseudonym_key: required(&consultation_values, CANONICAL_RUNTIME_PSEUDONYM_ENV)?,
        caller_hash: required(&notary_values, CANONICAL_RUNTIME_NOTARY_CALLER_HASH_ENV)?,
        caller_raw,
        under_scoped_hash: required(
            &notary_values,
            CANONICAL_RUNTIME_NOTARY_UNDER_SCOPED_HASH_ENV,
        )?,
        under_scoped_raw,
        postgres_admin_password: required(
            &postgres_values,
            CANONICAL_RUNTIME_POSTGRES_PASSWORD_ENV,
        )?,
        relay_database_password: database_password_from_url(&required(
            &consultation_values,
            CANONICAL_RUNTIME_RELAY_DATABASE_URL_ENV,
        )?)?,
        relay_maintenance_database_password: required(
            &postgres_values,
            CANONICAL_RUNTIME_RELAY_MAINTENANCE_DB_PASSWORD_ENV,
        )?,
        relay_reader_database_password: required(
            &postgres_values,
            CANONICAL_RUNTIME_RELAY_READER_DB_PASSWORD_ENV,
        )?,
        postgres_tls_certificate: decode_runtime_pem(&required(
            &postgres_values,
            CANONICAL_RUNTIME_POSTGRES_TLS_CERTIFICATE_ENV,
        )?)?,
        postgres_tls_private_key: decode_runtime_pem(&required(
            &postgres_values,
            CANONICAL_RUNTIME_POSTGRES_TLS_PRIVATE_KEY_ENV,
        )?)?,
        workload_private_jwk: fs::read_to_string(&workload_private_jwk_path)
            .context("failed to read workload private JWK")?,
        workload_public_jwk: required(&notary_values, CANONICAL_RUNTIME_WORKLOAD_JWK_ENV)?,
        workload_jwks: fs::read_to_string(&workload_jwks_path)
            .context("failed to read workload JWKS")?,
        notary_signing_private_jwk: required(
            &notary_values,
            CANONICAL_RUNTIME_NOTARY_SIGNING_JWK_ENV,
        )?,
    };
    if fingerprint_api_key(&notary.caller_raw) != notary.caller_hash
        || fingerprint_api_key(&notary.under_scoped_raw) != notary.under_scoped_hash
        || notary.audit_secret.len() < 32
        || notary.consultation_audit_secret.len() < 32
        || notary.pseudonym_key.len() < 32
        || notary.postgres_admin_password.len() < 32
        || notary.relay_database_password.len() < 32
        || notary.relay_maintenance_database_password.len() < 32
        || notary.relay_reader_database_password.len() < 32
        || !notary
            .postgres_tls_certificate
            .starts_with("-----BEGIN CERTIFICATE-----")
        || !notary
            .postgres_tls_private_key
            .starts_with("-----BEGIN PRIVATE KEY-----")
        || postgres_values
            .get(CANONICAL_RUNTIME_RELAY_DB_PASSWORD_ENV)
            .map(String::as_str)
            != Some(notary.relay_database_password.as_str())
    {
        bail!("combined runtime credentials do not meet the closed credential contract");
    }
    credentials.notary = Some(notary);
    validate_distinct_runtime_credentials(&credentials)?;
    let notary = credentials.notary.as_ref().expect("Notary credentials set");
    if fs::read_to_string(&database_init_path).context("failed to read database initialization")?
        != notary.database_init_sql()
        || fs::read_to_string(&notary_env_path)
            .context("failed to read Notary runtime credentials")?
            != notary.notary_env_file()
        || fs::read_to_string(&consultation_env_path)
            .context("failed to read consultation Relay runtime credentials")?
            != notary.consultation_relay_env_file()
        || fs::read_to_string(&relay_bootstrap_env_path)
            .context("failed to read consultation Relay bootstrap credentials")?
            != notary.relay_bootstrap_env_file()
        || fs::read_to_string(&postgres_env_path)
            .context("failed to read PostgreSQL runtime credentials")?
            != notary.postgres_env_file()
        || fs::read_to_string(&postgres_ca_path).context("failed to read PostgreSQL trust root")?
            != notary.postgres_tls_certificate
        || notary.workload_jwks != workload_jwks_from_private(&notary.workload_private_jwk)?
        || notary.workload_public_jwk != public_jwk_from_private(&notary.workload_private_jwk)?
    {
        bail!("combined runtime private files do not match the closed credential contract");
    }
    validate_workload_jwt(
        &fs::read_to_string(&workload_token_path).context("failed to read workload token")?,
        &notary.workload_private_jwk,
    )?;
    Ok(credentials)
}

fn public_jwk_from_private(private_jwk: &str) -> Result<String> {
    let jwk: serde_json::Value =
        serde_json::from_str(private_jwk).context("failed to parse private JWK")?;
    serde_json::to_string(&serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": jwk["x"]
            .as_str()
            .ok_or_else(|| anyhow!("private JWK is missing its public member"))?,
        "alg": "EdDSA",
        "kid": jwk["kid"]
            .as_str()
            .ok_or_else(|| anyhow!("private JWK is missing its kid"))?,
        "use": "sig",
    }))
    .context("failed to render public JWK")
}

fn database_password_from_url(url: &str) -> Result<String> {
    let prefix = format!("postgresql://{CANONICAL_RUNTIME_RELAY_DB_USER}:");
    let suffix = format!("@127.0.0.1:5432/{CANONICAL_RUNTIME_RELAY_DB}?sslmode=require");
    url.strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix(&suffix))
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("consultation Relay database binding is not closed"))
}

fn decode_runtime_pem(encoded: &str) -> Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("combined runtime TLS material is not valid base64")?;
    String::from_utf8(bytes).context("combined runtime TLS material is not UTF-8 PEM")
}

fn workload_jwks_from_private(private_jwk: &str) -> Result<String> {
    let jwk: serde_json::Value =
        serde_json::from_str(private_jwk).context("failed to parse workload private JWK")?;
    let x = jwk["x"]
        .as_str()
        .ok_or_else(|| anyhow!("workload private JWK is missing its public member"))?;
    serde_json::to_string_pretty(&serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "alg": "EdDSA",
            "kid": CANONICAL_RUNTIME_WORKLOAD_KID,
            "use": "sig",
        }]
    }))
    .context("failed to render workload JWKS")
}

fn validate_workload_jwt(token: &str, private_jwk: &str) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier as _};

    let token = token.trim();
    let segments = token.split('.').collect::<Vec<_>>();
    if segments.len() != 3 {
        bail!("workload token is not a compact JWT");
    }
    let decode_json = |segment: &str| -> Result<serde_json::Value> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .context("workload JWT segment is not base64url")?;
        serde_json::from_slice(&bytes).context("workload JWT segment is not JSON")
    };
    let header = decode_json(segments[0])?;
    let claims = decode_json(segments[1])?;
    if header
        != serde_json::json!({
            "alg": "EdDSA",
            "kid": CANONICAL_RUNTIME_WORKLOAD_KID,
            "typ": "at+jwt",
        })
        || claims["iss"].as_str() != Some(CANONICAL_RUNTIME_WORKLOAD_ISSUER)
        || claims["sub"].as_str() != Some(CANONICAL_RUNTIME_WORKLOAD_CLIENT)
        || claims["aud"].as_str() != Some(CANONICAL_RUNTIME_WORKLOAD_AUDIENCE)
        || claims["client_id"].as_str() != Some(CANONICAL_RUNTIME_WORKLOAD_CLIENT)
        || claims["azp"].as_str() != Some(CANONICAL_RUNTIME_WORKLOAD_CLIENT)
        || claims["scope"].as_str() != Some(CANONICAL_RUNTIME_WORKLOAD_SCOPE)
    {
        bail!("workload JWT claims do not match the exact local trust binding");
    }
    let iat = claims["iat"]
        .as_u64()
        .ok_or_else(|| anyhow!("workload JWT is missing iat"))?;
    let nbf = claims["nbf"]
        .as_u64()
        .ok_or_else(|| anyhow!("workload JWT is missing nbf"))?;
    let exp = claims["exp"]
        .as_u64()
        .ok_or_else(|| anyhow!("workload JWT is missing exp"))?;
    if nbf > iat
        || exp <= iat
        || exp - iat > CANONICAL_RUNTIME_WORKLOAD_TTL_SECONDS
        || claims["jti"].as_str().is_none()
    {
        bail!("workload JWT lifetime or identifier is invalid");
    }
    let jwk: serde_json::Value =
        serde_json::from_str(private_jwk).context("failed to parse workload private JWK")?;
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(
            jwk["d"]
                .as_str()
                .ok_or_else(|| anyhow!("workload private JWK is missing its private member"))?,
        )
        .context("workload private JWK contains an invalid private member")?;
    let secret: [u8; 32] = secret
        .try_into()
        .map_err(|_| anyhow!("workload private JWK has the wrong private member length"))?;
    let signature = Signature::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segments[2])
            .context("workload JWT signature is not base64url")?,
    )
    .context("workload JWT signature has the wrong length")?;
    SigningKey::from_bytes(&secret)
        .verifying_key()
        .verify(
            format!("{}.{}", segments[0], segments[1]).as_bytes(),
            &signature,
        )
        .context("workload JWT signature is invalid")
}

fn prepare_canonical_runtime(
    project_dir: &Path,
    image_lock: &RegistryctlImageLock,
) -> Result<CanonicalRuntime> {
    require_canonical_project(project_dir)?;
    let binding = canonical_spreadsheet_binding(project_dir)?;
    let images = CanonicalRuntimeImages {
        relay: selected_canonical_relay_image(image_lock)?,
        notary: binding
            .topology
            .has_notary()
            .then(|| selected_canonical_notary_image(image_lock))
            .transpose()?,
        postgresql: binding
            .topology
            .has_notary()
            .then(|| image_lock.postgresql_image().to_string()),
    };
    prepare_canonical_runtime_with_images(project_dir, &images)
}

#[cfg(test)]
fn prepare_canonical_runtime_with_image(
    project_dir: &Path,
    relay_image: &str,
) -> Result<CanonicalRuntime> {
    prepare_canonical_runtime_with_images(
        project_dir,
        &CanonicalRuntimeImages {
            relay: relay_image.to_string(),
            notary: None,
            postgresql: None,
        },
    )
}

fn prepare_canonical_runtime_with_images(
    project_dir: &Path,
    images: &CanonicalRuntimeImages,
) -> Result<CanonicalRuntime> {
    require_canonical_project(project_dir)?;
    validate_canonical_runtime_image_ref(&images.relay)?;
    if project_dir.join(CANONICAL_RUNTIME_ROOT).exists() {
        let _ = load_canonical_runtime(project_dir, CanonicalRuntimeValidation::GeneratedClosure)?;
    }
    if project_dir.join(CANONICAL_ARTIFACT_MANIFEST).exists() {
        validate_compiled_artifact_manifest(project_dir, false)?;
    }
    let binding = canonical_spreadsheet_binding(project_dir)?;
    if binding.topology.has_notary() {
        validate_canonical_runtime_notary_image_ref(
            images
                .notary
                .as_deref()
                .ok_or_else(|| anyhow!("locked Notary image is absent"))?,
        )?;
        validate_locked_image_ref(
            "images.postgresql",
            images
                .postgresql
                .as_deref()
                .ok_or_else(|| anyhow!("locked PostgreSQL image is absent"))?,
            POSTGRES_IMAGE_REPOSITORY,
        )?;
    } else if images.notary.is_some() || images.postgresql.is_some() {
        bail!("Relay-only runtime received unused product images");
    }
    let report = build_registry_project(&ProjectBuildOptions {
        project_directory: project_dir.to_path_buf(),
        environment: CANONICAL_LOCAL_ENVIRONMENT.to_string(),
        against: None,
        anchor: None,
    })?;
    if report.status != "built"
        || report.output.as_deref() != Some(CANONICAL_BUILD_ROOT)
        || report.artifact_manifest.is_none()
    {
        bail!("the canonical local project build did not produce its closed artifact manifest");
    }
    validate_compiled_artifact_manifest(project_dir, true)?;
    validate_compiled_local_relay_auth(&project_dir.join(CANONICAL_RELAY_CONFIG), &binding)?;
    if binding.topology.has_notary() {
        for path in [
            project_dir.join(CANONICAL_CONSULTATION_RELAY_CONFIG),
            project_dir.join(CANONICAL_COMPILED_NOTARY_CONFIG),
        ] {
            ensure_no_symlink_components(project_dir, &path)?;
            validate_private_file_mode(&path)?;
        }
        let _ = render_runtime_notary_config(&project_dir.join(CANONICAL_COMPILED_NOTARY_CONFIG))?;
    }
    publish_canonical_runtime(project_dir, images, &binding)?;
    load_canonical_runtime(project_dir, CanonicalRuntimeValidation::Full)
}

fn publish_canonical_runtime(
    project_dir: &Path,
    images: &CanonicalRuntimeImages,
    binding: &CanonicalSpreadsheetBinding,
) -> Result<()> {
    validate_canonical_runtime_image_ref(&images.relay)?;
    let runtime_parent = project_dir.join(".registry-stack/runtime");
    ensure_no_symlink_components(project_dir, &runtime_parent)?;
    create_private_dir_all(&runtime_parent)?;
    let runtime_dir = project_dir.join(CANONICAL_RUNTIME_ROOT);
    let prior_credentials = if runtime_dir.exists() {
        let prior_manifest: CanonicalRuntimeManifest = serde_json::from_slice(
            &fs::read(project_dir.join(CANONICAL_RUNTIME_MANIFEST))
                .context("failed to read the prior local runtime manifest")?,
        )
        .context("failed to parse the prior local runtime manifest")?;
        Some(strict_canonical_runtime_credentials(
            project_dir,
            prior_manifest.topology,
        )?)
    } else {
        None
    };
    let mut credentials = prior_credentials
        .map(Ok)
        .unwrap_or_else(CanonicalRuntimeCredentials::generate)?;
    if binding.topology.has_notary() && credentials.notary.is_none() {
        credentials = credentials.enable_notary()?;
    } else if !binding.topology.has_notary() {
        credentials.notary = None;
    }
    validate_distinct_runtime_credentials(&credentials)?;
    let staging = tempfile::Builder::new()
        .prefix(".local.runtime-")
        .tempdir_in(&runtime_parent)
        .context("failed to stage the local runtime")?;
    create_private_dir_all(staging.path())?;
    create_private_dir_all(&staging.path().join("secrets"))?;
    let compose = render_canonical_compose(images, binding)?;
    let workbook_input = compiled_workbook_input(project_dir, binding)?;
    write_private_text(&staging.path().join("compose.yaml"), &compose)?;
    write_private_text(
        &staging.path().join("secrets/relay.env"),
        &credentials.relay_env_file(),
    )?;
    write_private_text(
        &staging.path().join("secrets/local.env"),
        &credentials.client_env_file(),
    )?;
    let notary_manifest = if let Some(notary) = credentials.notary.as_ref() {
        for relative in [
            "private",
            "private/db",
            "private/notary",
            "private/notary/config",
            "private/relay",
            "private/relay/config",
            "private/relay/config/artifacts",
            "private/workload",
        ] {
            create_private_dir_all(&staging.path().join(relative))?;
        }
        let runtime_notary_config =
            render_runtime_notary_config(&project_dir.join(CANONICAL_COMPILED_NOTARY_CONFIG))?;
        let runtime_consultation_relay_config = render_runtime_consultation_relay_config(
            &project_dir.join(CANONICAL_CONSULTATION_RELAY_CONFIG),
        )?;
        let workload_token = format!("{}\n", notary.workload_token()?);
        let consultation_env = notary.consultation_relay_env_file();
        let relay_bootstrap_env = notary.relay_bootstrap_env_file();
        let notary_env = notary.notary_env_file();
        let postgres_env = notary.postgres_env_file();
        let database_init = notary.database_init_sql();
        write_private_text(
            &staging.path().join("secrets/relay-consultation.env"),
            &consultation_env,
        )?;
        write_private_text(
            &staging.path().join("secrets/relay-bootstrap.env"),
            &relay_bootstrap_env,
        )?;
        write_private_text(&staging.path().join("secrets/notary.env"), &notary_env)?;
        write_private_text(&staging.path().join("secrets/postgres.env"), &postgres_env)?;
        write_private_text(
            &staging.path().join("secrets/relay-workload-token"),
            &workload_token,
        )?;
        write_private_text(
            &staging.path().join("secrets/workload-private.jwk"),
            &notary.workload_private_jwk,
        )?;
        write_runtime_nonsecret_text(&staging.path().join("private/db/init.sh"), &database_init)?;
        write_runtime_nonsecret_text(
            &staging.path().join("private/notary/config/notary.yaml"),
            &runtime_notary_config,
        )?;
        write_runtime_nonsecret_text(
            &staging
                .path()
                .join("private/relay/config/relay-consultation.yaml"),
            &runtime_consultation_relay_config,
        )?;
        write_runtime_nonsecret_text(
            &staging
                .path()
                .join("private/relay/config/state-plane-ca.pem"),
            &notary.postgres_tls_certificate,
        )?;
        write_private_text(
            &staging.path().join("private/workload/jwks.json"),
            &notary.workload_jwks,
        )?;
        Some(CanonicalNotaryRuntimeManifest {
            notary_image: images
                .notary
                .clone()
                .ok_or_else(|| anyhow!("locked Notary image is absent"))?,
            postgresql_image: images
                .postgresql
                .clone()
                .ok_or_else(|| anyhow!("locked PostgreSQL image is absent"))?,
            consultation_relay_config_digest: digest_path(
                &project_dir.join(CANONICAL_CONSULTATION_RELAY_CONFIG),
                "compiled consultation Relay config",
            )?,
            runtime_consultation_relay_config_digest: sha256_uri(
                runtime_consultation_relay_config.as_bytes(),
            ),
            compiled_notary_config_digest: digest_path(
                &project_dir.join(CANONICAL_COMPILED_NOTARY_CONFIG),
                "compiled Notary config",
            )?,
            runtime_notary_config_digest: sha256_uri(runtime_notary_config.as_bytes()),
            postgres_ca_digest: sha256_uri(notary.postgres_tls_certificate.as_bytes()),
            database_init_digest: sha256_uri(database_init.as_bytes()),
            workload_jwks_digest: sha256_uri(notary.workload_jwks.as_bytes()),
            consultation_relay_env_digest: sha256_uri(consultation_env.as_bytes()),
            relay_bootstrap_env_digest: sha256_uri(relay_bootstrap_env.as_bytes()),
            notary_env_digest: sha256_uri(notary_env.as_bytes()),
            postgres_env_digest: sha256_uri(postgres_env.as_bytes()),
            workload_token_digest: sha256_uri(workload_token.as_bytes()),
            workload_private_jwk_digest: sha256_uri(notary.workload_private_jwk.as_bytes()),
        })
    } else {
        None
    };
    let manifest = CanonicalRuntimeManifest {
        schema_version: CANONICAL_RUNTIME_MANIFEST_SCHEMA.to_string(),
        environment: CANONICAL_LOCAL_ENVIRONMENT.to_string(),
        relay_image: images.relay.clone(),
        compose_digest: sha256_uri(compose.as_bytes()),
        artifact_manifest_digest: digest_path(
            &project_dir.join(CANONICAL_ARTIFACT_MANIFEST),
            "generated project artifact manifest",
        )?,
        relay_config_digest: digest_path(
            &project_dir.join(CANONICAL_RELAY_CONFIG),
            "compiled Relay config",
        )?,
        workbook_digest: workbook_input.digest.as_str().to_string(),
        workbook_classification: workbook_input.classification,
        workbook_project_file: binding.project_file_text.clone(),
        workbook_runtime_path: binding.runtime_path.clone(),
        topology: binding.topology,
        notary: notary_manifest,
    };
    write_private_text(
        &staging.path().join("manifest.json"),
        &serde_json::to_string_pretty(&manifest)
            .context("failed to render the local runtime manifest")?,
    )?;
    let staged = staging.keep();
    let backup = runtime_parent.join(format!(".local.previous-{}", std::process::id()));
    if backup.exists() {
        fs::remove_dir_all(&backup).context("failed to discard stale local runtime backup")?;
    }
    if runtime_dir.exists() {
        fs::rename(&runtime_dir, &backup).context("failed to stage the prior local runtime")?;
    }
    if let Err(error) = fs::rename(&staged, &runtime_dir) {
        if backup.exists() {
            let _ = fs::rename(&backup, &runtime_dir);
        }
        return Err(error).context("failed to publish the local runtime");
    }
    if backup.exists() {
        fs::remove_dir_all(&backup).context("failed to discard the prior local runtime")?;
    }
    Ok(())
}

fn load_canonical_runtime(
    project_dir: &Path,
    validation: CanonicalRuntimeValidation,
) -> Result<CanonicalRuntime> {
    require_canonical_project(project_dir)?;
    let runtime_dir = project_dir.join(CANONICAL_RUNTIME_ROOT);
    let secrets_dir = project_dir.join(CANONICAL_RUNTIME_SECRETS);
    let compose_file = project_dir.join(CANONICAL_RUNTIME_COMPOSE);
    let manifest_file = project_dir.join(CANONICAL_RUNTIME_MANIFEST);
    let secrets_env = project_dir.join(CANONICAL_RUNTIME_ENV);
    let relay_env = project_dir.join(CANONICAL_RUNTIME_RELAY_ENV);
    for path in [
        &runtime_dir,
        &secrets_dir,
        &compose_file,
        &manifest_file,
        &secrets_env,
        &relay_env,
    ] {
        ensure_no_symlink_components(project_dir, path)?;
    }
    validate_private_dir_mode(&runtime_dir)
        .map_err(|_| anyhow!("local runtime is absent or unsafe; rerun `registryctl start`"))?;
    validate_private_dir_mode(&secrets_dir)?;
    validate_private_file_mode(&compose_file)?;
    validate_private_file_mode(&manifest_file)?;
    let manifest: CanonicalRuntimeManifest = serde_json::from_slice(
        &fs::read(&manifest_file).context("failed to read the local runtime manifest")?,
    )
    .context("failed to parse the local runtime manifest")?;
    if manifest.schema_version != CANONICAL_RUNTIME_MANIFEST_SCHEMA
        || manifest.environment != CANONICAL_LOCAL_ENVIRONMENT
    {
        bail!("local runtime manifest has an unsupported contract");
    }
    validate_canonical_runtime_image_ref(&manifest.relay_image)?;
    if manifest.topology.has_notary() != manifest.notary.is_some() {
        bail!("local runtime manifest topology is incomplete");
    }
    let _ = strict_canonical_runtime_credentials(project_dir, manifest.topology)?;
    validate_runtime_file_closure(project_dir, manifest.topology)?;
    let authored_binding = canonical_spreadsheet_binding(project_dir)?;
    if validation == CanonicalRuntimeValidation::Full
        && authored_binding.topology != manifest.topology
    {
        bail!("the authored topology changed; rerun `registryctl start` to regenerate the runtime");
    }
    let mut binding = authored_binding;
    binding.topology = manifest.topology;
    let workbook_input = compiled_workbook_input(project_dir, &binding)?;
    if binding.project_file_text != manifest.workbook_project_file
        || binding.runtime_path != manifest.workbook_runtime_path
    {
        bail!("the authored project changed after the local runtime was compiled");
    }
    if workbook_input.digest.as_str() != manifest.workbook_digest
        || workbook_input.classification != manifest.workbook_classification
        || manifest.workbook_classification != ArtifactInputClassification::OperatorOwnedSourceData
    {
        bail!("local runtime workbook provenance does not match the artifact manifest");
    }
    let compose = fs::read_to_string(&compose_file).context("failed to read local Compose")?;
    if sha256_uri(compose.as_bytes()) != manifest.compose_digest {
        bail!("generated local Compose integrity check failed");
    }
    let images = CanonicalRuntimeImages {
        relay: manifest.relay_image.clone(),
        notary: manifest
            .notary
            .as_ref()
            .map(|notary| notary.notary_image.clone()),
        postgresql: manifest
            .notary
            .as_ref()
            .map(|notary| notary.postgresql_image.clone()),
    };
    validate_canonical_compose(&compose, &images, &binding)?;
    let relay_config = project_dir.join(CANONICAL_RELAY_CONFIG);
    ensure_no_symlink_components(project_dir, &relay_config)?;
    if digest_path(&relay_config, "compiled Relay config")? != manifest.relay_config_digest {
        bail!("compiled Relay config integrity check failed");
    }
    validate_compiled_local_relay_auth(&relay_config, &binding)?;
    if let Some(notary) = &manifest.notary {
        validate_canonical_runtime_notary_image_ref(&notary.notary_image)?;
        validate_locked_image_ref(
            "manifest.postgresql_image",
            &notary.postgresql_image,
            POSTGRES_IMAGE_REPOSITORY,
        )?;
        let consultation_config = project_dir.join(CANONICAL_CONSULTATION_RELAY_CONFIG);
        let compiled_notary_config = project_dir.join(CANONICAL_COMPILED_NOTARY_CONFIG);
        let runtime_notary_config = project_dir.join(CANONICAL_RUNTIME_NOTARY_CONFIG);
        let runtime_consultation_config =
            project_dir.join(CANONICAL_RUNTIME_CONSULTATION_RELAY_CONFIG);
        let postgres_ca = project_dir.join(CANONICAL_RUNTIME_POSTGRES_CA);
        for path in [&consultation_config, &compiled_notary_config] {
            ensure_no_symlink_components(project_dir, path)?;
            validate_private_file_mode(path)?;
        }
        ensure_no_symlink_components(project_dir, &runtime_notary_config)?;
        ensure_no_symlink_components(project_dir, &runtime_consultation_config)?;
        ensure_no_symlink_components(project_dir, &postgres_ca)?;
        validate_runtime_nonsecret_file_mode(&runtime_notary_config)?;
        validate_runtime_nonsecret_file_mode(&runtime_consultation_config)?;
        validate_runtime_nonsecret_file_mode(&postgres_ca)?;
        if digest_path(&consultation_config, "compiled consultation Relay config")?
            != notary.consultation_relay_config_digest
            || digest_path(
                &runtime_consultation_config,
                "runtime consultation Relay config",
            )? != notary.runtime_consultation_relay_config_digest
            || digest_path(&compiled_notary_config, "compiled Notary config")?
                != notary.compiled_notary_config_digest
            || digest_path(&runtime_notary_config, "runtime Notary config")?
                != notary.runtime_notary_config_digest
            || digest_path(&postgres_ca, "PostgreSQL trust root")? != notary.postgres_ca_digest
            || digest_path(
                &project_dir.join(CANONICAL_RUNTIME_DB_INIT),
                "database initialization",
            )? != notary.database_init_digest
            || digest_path(
                &project_dir.join(CANONICAL_RUNTIME_WORKLOAD_JWKS),
                "workload JWKS",
            )? != notary.workload_jwks_digest
            || digest_path(
                &project_dir.join(CANONICAL_RUNTIME_CONSULTATION_RELAY_ENV),
                "consultation Relay credentials",
            )? != notary.consultation_relay_env_digest
            || digest_path(
                &project_dir.join(CANONICAL_RUNTIME_RELAY_BOOTSTRAP_ENV),
                "consultation Relay bootstrap credentials",
            )? != notary.relay_bootstrap_env_digest
            || digest_path(
                &project_dir.join(CANONICAL_RUNTIME_NOTARY_ENV),
                "Notary credentials",
            )? != notary.notary_env_digest
            || digest_path(
                &project_dir.join(CANONICAL_RUNTIME_POSTGRES_ENV),
                "PostgreSQL credentials",
            )? != notary.postgres_env_digest
            || digest_path(
                &project_dir.join(CANONICAL_RUNTIME_WORKLOAD_TOKEN),
                "workload token",
            )? != notary.workload_token_digest
            || digest_path(
                &project_dir.join(CANONICAL_RUNTIME_WORKLOAD_PRIVATE_JWK),
                "workload private JWK",
            )? != notary.workload_private_jwk_digest
        {
            bail!("combined runtime generated-input integrity check failed");
        }
        let expected_notary_config = render_runtime_notary_config(&compiled_notary_config)?;
        if fs::read_to_string(&runtime_notary_config)
            .context("failed to read runtime Notary config")?
            != expected_notary_config
        {
            bail!("runtime Notary config does not match its compiled source");
        }
        let expected_consultation_config =
            render_runtime_consultation_relay_config(&consultation_config)?;
        if fs::read_to_string(&runtime_consultation_config)
            .context("failed to read runtime consultation Relay config")?
            != expected_consultation_config
        {
            bail!("runtime consultation Relay config does not match its compiled source");
        }
    }
    if digest_path(
        &project_dir.join(CANONICAL_ARTIFACT_MANIFEST),
        "generated project artifact manifest",
    )? != manifest.artifact_manifest_digest
    {
        bail!("generated project artifact manifest integrity check failed");
    }
    validate_compiled_artifact_manifest(
        project_dir,
        validation == CanonicalRuntimeValidation::Full,
    )?;
    Ok(CanonicalRuntime {
        compose_file,
        relay_config,
        secrets_env,
        image: manifest.relay_image,
        topology: manifest.topology,
    })
}

fn validate_runtime_file_closure(
    project_dir: &Path,
    topology: CanonicalRuntimeTopology,
) -> Result<()> {
    let mut expected = BTreeSet::from([
        "compose.yaml".to_string(),
        "manifest.json".to_string(),
        "secrets/local.env".to_string(),
        "secrets/relay.env".to_string(),
    ]);
    if topology.has_notary() {
        expected.extend(
            [
                "secrets/relay-consultation.env",
                "secrets/relay-bootstrap.env",
                "secrets/notary.env",
                "secrets/postgres.env",
                "secrets/relay-workload-token",
                "secrets/workload-private.jwk",
                "private/db/init.sh",
                "private/notary/config/notary.yaml",
                "private/relay/config/relay-consultation.yaml",
                "private/relay/config/state-plane-ca.pem",
                "private/workload/jwks.json",
            ]
            .into_iter()
            .map(str::to_string),
        );
    }
    let root = project_dir.join(CANONICAL_RUNTIME_ROOT);
    let mut actual = BTreeSet::new();
    let mut pending = vec![root.clone()];
    while let Some(directory) = pending.pop() {
        validate_private_dir_mode(&directory)?;
        for entry in fs::read_dir(&directory).context("failed to inspect local runtime closure")? {
            let entry = entry.context("failed to inspect local runtime entry")?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .context("failed to inspect local runtime entry metadata")?;
            if metadata.file_type().is_symlink() {
                bail!("local runtime closure contains a symlink");
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(&root)
                    .context("local runtime entry escaped its root")?
                    .to_string_lossy()
                    .into_owned();
                if matches!(
                    relative.as_str(),
                    "private/db/init.sh"
                        | "private/notary/config/notary.yaml"
                        | "private/relay/config/relay-consultation.yaml"
                        | "private/relay/config/state-plane-ca.pem"
                ) {
                    validate_runtime_nonsecret_file_mode(&path)?;
                } else {
                    validate_private_file_mode(&path)?;
                }
                if relative != "smoke-results.json" {
                    actual.insert(relative);
                }
            } else {
                bail!("local runtime closure contains a non-regular entry");
            }
        }
    }
    if actual != expected {
        bail!("local runtime generated-input closure is incomplete or contains unexpected files");
    }
    Ok(())
}

pub fn start_project(project_dir: &Path) -> Result<()> {
    start_project_with_timeout(project_dir, Duration::from_secs(60))
}

fn start_project_with_timeout(project_dir: &Path, timeout: Duration) -> Result<()> {
    let image_lock = load_registryctl_image_lock()?;
    let runtime = prepare_canonical_runtime(project_dir, &image_lock)?;
    if runtime.topology.has_notary() {
        let wait_timeout = timeout.as_secs().max(1).to_string();
        run_compose_for_canonical_runtime(
            project_dir,
            &runtime,
            &[
                "up",
                "-d",
                "--wait",
                "--wait-timeout",
                wait_timeout.as_str(),
            ],
        )?;
    } else {
        run_compose_for_canonical_runtime(project_dir, &runtime, &["up", "-d"])?;
    }
    wait_for_ready("Relay", RELAY_BASE_URL, timeout).map_err(|_| {
        anyhow!(
            "local Relay did not become ready; the compiled configuration or declared workbook \
             was rejected. Inspect `registryctl logs`; no workbook values were included in this \
             diagnostic."
        )
    })?;
    println!("PASS readiness: compiled workbook source is ready");
    if runtime.topology.has_notary() {
        wait_for_ready("Registry Notary", NOTARY_BASE_URL, timeout).map_err(|_| {
            anyhow!(
                "local Registry Notary did not become ready; inspect `registryctl logs`; no \
                 credentials or workbook values were included in this diagnostic."
            )
        })?;
        println!("PASS readiness: Registry Notary is ready");
        println!("Relay API:   {RELAY_BASE_URL}");
        println!("Relay docs:  {RELAY_BASE_URL}{RELAY_DOCS_PATH}");
        println!("Notary API:  {NOTARY_BASE_URL}");
        println!("Notary docs: {NOTARY_BASE_URL}{RELAY_DOCS_PATH}");
    } else {
        println!("Relay API:  {RELAY_BASE_URL}");
        println!("API docs:   {RELAY_BASE_URL}{RELAY_DOCS_PATH}");
    }
    Ok(())
}

pub fn stop_project(project_dir: &Path) -> Result<()> {
    let runtime =
        load_canonical_runtime(project_dir, CanonicalRuntimeValidation::GeneratedClosure)?;
    run_compose_for_canonical_runtime(project_dir, &runtime, &["down"])?;
    Ok(())
}

/// Stops and starts the project so edits to the bind-mounted config files
/// take effect; a plain `start` leaves an already-running container as is.
pub fn restart_project(project_dir: &Path) -> Result<()> {
    stop_project(project_dir)?;
    start_project(project_dir)
}

pub fn status_project(project_dir: &Path) -> Result<()> {
    let runtime = load_canonical_runtime(project_dir, CanonicalRuntimeValidation::Full)?;
    run_compose_for_canonical_runtime(project_dir, &runtime, &["ps"])?;
    print_probe_status("healthz", &format!("{RELAY_BASE_URL}/healthz"));
    print_probe_status("ready", &format!("{RELAY_BASE_URL}/ready"));
    println!("Relay API:  {RELAY_BASE_URL}");
    println!("API docs:   {RELAY_BASE_URL}{RELAY_DOCS_PATH}");
    if runtime.topology.has_notary() {
        print_probe_status("notary healthz", &format!("{NOTARY_BASE_URL}/healthz"));
        print_probe_status("notary ready", &format!("{NOTARY_BASE_URL}/ready"));
        println!("Notary API:  {NOTARY_BASE_URL}");
        println!("Notary docs: {NOTARY_BASE_URL}{RELAY_DOCS_PATH}");
    }
    Ok(())
}

pub fn open_project(project_dir: &Path) -> Result<()> {
    let _ = load_canonical_runtime(project_dir, CanonicalRuntimeValidation::Full)?;
    let docs_url = format!("{RELAY_BASE_URL}{RELAY_DOCS_PATH}");
    // Always surface the URL: `open` reports success even in headless macOS
    // sessions where nothing actually launches, so a conditional fallback would
    // silently print nothing. Then best-effort open a browser for desktops.
    for line in relay_open_lines(&docs_url) {
        println!("{line}");
    }
    let _ = Command::new("open").arg(&docs_url).status();
    Ok(())
}

fn relay_open_lines(docs_url: &str) -> Vec<String> {
    vec![docs_url.to_string()]
}

pub fn logs_project(project_dir: &Path) -> Result<()> {
    let runtime = load_canonical_runtime(project_dir, CanonicalRuntimeValidation::Full)?;
    run_compose_for_canonical_runtime(project_dir, &runtime, &["logs"])?;
    Ok(())
}

pub fn smoke_project(project_dir: &Path) -> Result<()> {
    let runtime = load_canonical_runtime(project_dir, CanonicalRuntimeValidation::Full)?;
    let credentials = strict_canonical_runtime_credentials(project_dir, runtime.topology)?;
    let report = run_canonical_smoke_checks(RELAY_BASE_URL, NOTARY_BASE_URL, &credentials);
    let output_path = project_dir
        .join(CANONICAL_RUNTIME_ROOT)
        .join("smoke-results.json");
    let json =
        serde_json::to_string_pretty(&report).context("failed to render smoke result JSON")?;
    parse_smoke_report(&json)?;
    write_private_text(&output_path, &json)?;

    for check in &report.checks {
        let status = if check.passed { "PASS" } else { "FAIL" };
        println!("{status} {}", check.name);
    }

    if report.passed {
        Ok(())
    } else {
        bail!("one or more smoke checks failed")
    }
}

pub fn bruno_generate_project(project_dir: &Path, force: bool) -> Result<PathBuf> {
    let project = Project::load(project_dir)?;
    let secrets = LocalEnv::load(&project_dir.join(&project.local.secrets_env))?;
    let collection_dir = project_dir.join(BRUNO_COLLECTION_DIR);
    let files = bruno_files(&project, &secrets)?;
    write_generated_files(project_dir, &collection_dir, files, force)?;
    Ok(collection_dir)
}

pub fn bruno_open_project(project_dir: &Path) -> Result<()> {
    Project::load(project_dir)?;
    let collection_dir = project_dir.join(BRUNO_COLLECTION_DIR);
    if !collection_dir.exists() {
        println!("Bruno collection has not been generated yet. Run `registryctl bruno generate`.");
        return Ok(());
    }

    let open_result = Command::new("open")
        .arg("-a")
        .arg("Bruno")
        .arg(&collection_dir)
        .status();
    if matches!(open_result, Ok(status) if status.success()) {
        return Ok(());
    }

    println!("Bruno collection generated at:");
    println!("  {}", collection_dir.display());
    println!("Install Bruno to open it visually:");
    println!("  https://www.usebruno.com/downloads");
    println!("The API still works without Bruno:");
    println!("  registryctl smoke");
    Ok(())
}

pub fn bruno_run_project(project_dir: &Path) -> Result<()> {
    Project::load(project_dir)?;
    let collection_dir = project_dir.join(BRUNO_COLLECTION_DIR);
    let env_file = collection_dir.join("environments/local.bru");
    if !collection_dir.exists() || !env_file.exists() {
        println!("Bruno collection has not been generated yet. Run `registryctl bruno generate`.");
        return Ok(());
    }

    let status = Command::new("bru")
        .arg("run")
        .arg("--env-file")
        .arg("environments/local.bru")
        .current_dir(&collection_dir)
        .status();
    match status {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => bail!("bru run exited with {status}"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            println!("Bruno CLI `bru` is not installed.");
            println!("Install Bruno CLI to run the collection from the terminal:");
            println!("  https://docs.usebruno.com/bru-cli/overview");
            println!("The API still works without Bruno:");
            println!("  registryctl smoke");
            Ok(())
        }
        Err(err) => Err(err).context("failed to run bru"),
    }
}

pub fn doctor_project(
    project_dir: &Path,
    format: DoctorFormat,
    deployment_profile: Option<DeploymentProfile>,
) -> Result<()> {
    let image_lock = load_registryctl_image_lock()?;
    let _ = prepare_canonical_runtime(project_dir, &image_lock)?;
    let report = run_doctor_report_with_path(project_dir, deployment_profile, None)?;
    match format {
        DoctorFormat::Human => println!("{}", render_doctor_report(&report)),
        DoctorFormat::Json => {
            let json = serde_json::to_string_pretty(&report)
                .context("failed to render doctor report JSON")?;
            println!("{json}");
        }
    }
    ensure_doctor_report_ok(&report)
}

fn render_doctor_report(report: &DoctorReport) -> String {
    use std::fmt::Write as _;

    let mut output = format!("Registry Stack doctor: {}", report.status.as_str());
    let _ = write!(
        output,
        "\nProject: {}\nProfile: {}",
        human_line_value(&report.project.path),
        human_line_value(&report.project.profile)
    );
    for product in &report.products {
        let _ = write!(
            output,
            "\n{}: {} ({} errors, {} warnings)",
            human_line_value(&product.product),
            product.status.as_str(),
            product.report.summary.error_count,
            product.report.summary.warning_count
        );
        if let Some(path) = &product.report.source.path {
            let _ = write!(output, "\n  Config: {}", human_line_value(path));
        }
        if !product.report.required_env.is_empty() {
            let present = product
                .report
                .required_env
                .iter()
                .filter(|entry| entry.status.as_str() == "present")
                .count();
            let missing = product
                .report
                .required_env
                .iter()
                .filter(|entry| entry.status.as_str() == "missing")
                .count();
            let not_checked = product.report.required_env.len() - present - missing;
            let _ = write!(
                output,
                "\n  Required environment: {present} present, {missing} missing, {not_checked} not checked"
            );
        }
        if !product.report.context_constraints.is_empty() {
            let _ = write!(
                output,
                "\n  Context constraints: {}",
                product.report.context_constraints.len()
            );
        }
        if let Some(shipping) = &product.report.audit_shipping {
            let _ = write!(
                output,
                "\n  Audit shipping: sink={}, target={}, health={}",
                human_line_value(&shipping.sink_type),
                human_line_value(&shipping.shipping_target),
                shipping
                    .shipping_health
                    .as_deref()
                    .map_or("not observed".to_string(), human_line_value)
            );
        }
        for diagnostic in &product.report.diagnostics {
            let _ = write!(
                output,
                "\n  [{}] {}: {}",
                diagnostic.severity.as_str(),
                human_line_value(&diagnostic.code),
                human_line_value(&diagnostic.message)
            );
            if let Some(path) = &diagnostic.path {
                let _ = write!(output, " ({})", human_line_value(path));
            }
        }
    }
    if !report.cross_product_diagnostics.is_empty() {
        output.push_str("\nCross-product diagnostics:");
        for diagnostic in &report.cross_product_diagnostics {
            let _ = write!(
                output,
                "\n  [{}] {}: {}",
                diagnostic.severity.as_str(),
                human_line_value(&diagnostic.code),
                human_line_value(&diagnostic.message)
            );
        }
    }
    output
}

fn human_line_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                write!(escaped, "\\u{:04x}", character as u32)
                    .expect("writing to a String cannot fail");
            }
            character => escaped.push(character),
        }
    }
    escaped
}

struct ProductDoctorInvocation {
    product: &'static str,
    binary: &'static str,
    cwd: PathBuf,
    config_path: PathBuf,
    args: Vec<String>,
    platform_override: Option<&'static str>,
}

fn run_doctor_report_with_path(
    project_dir: &Path,
    deployment_profile: Option<DeploymentProfile>,
    path: Option<&Path>,
) -> Result<DoctorReport> {
    #[cfg(test)]
    if project_dir.join("registryctl.yaml").is_file() {
        return run_legacy_doctor_report_with_path(project_dir, deployment_profile, path);
    }
    let runtime = load_canonical_runtime(project_dir, CanonicalRuntimeValidation::Full)?;
    let _ = strict_runtime_credentials(
        &project_dir.join(CANONICAL_RUNTIME_RELAY_ENV),
        &runtime.secrets_env,
    )?;
    let mut values = parse_local_env(
        &fs::read_to_string(project_dir.join(CANONICAL_RUNTIME_RELAY_ENV))
            .context("failed to read Relay runtime credentials")?,
    );
    values.extend(parse_local_env(
        &fs::read_to_string(&runtime.secrets_env)
            .context("failed to read local client credentials")?,
    ));
    let secrets = LocalEnv { values };
    let redactor = SecretRedactor::new(&secrets);
    let generated_at = rfc3339_now();
    let products = product_doctor_invocations(
        project_dir,
        &runtime,
        deployment_profile,
        path.map(Path::as_os_str),
    )?
    .into_iter()
    .map(|invocation| {
        run_product_doctor(
            invocation,
            path.map(Path::as_os_str),
            &redactor,
            &generated_at,
        )
    })
    .collect::<Vec<_>>();
    Ok(RegistryctlValidationReport {
        schema_version: REGISTRYCTL_VALIDATION_REPORT_SCHEMA_VERSION_V1.to_string(),
        project: RegistryctlProjectRef {
            path: ".".to_string(),
            profile: deployment_profile
                .map_or("project", DeploymentProfile::as_str)
                .to_string(),
        },
        status: registryctl_report_status(&products),
        products,
        cross_product_diagnostics: Vec::new(),
        generated_at,
    })
}

#[cfg(test)]
fn run_legacy_doctor_report_with_path(
    project_dir: &Path,
    deployment_profile: Option<DeploymentProfile>,
    path: Option<&Path>,
) -> Result<DoctorReport> {
    let project = Project::load(project_dir)?;
    let secrets_path = project_dir.join(&project.local.secrets_env);
    let secrets = LocalEnv::load(&secrets_path)?;
    let redactor = SecretRedactor::new(&secrets);
    let generated_at = rfc3339_now();
    let products = legacy_product_doctor_invocations(
        project_dir,
        &project,
        deployment_profile,
        path.map(Path::as_os_str),
    )?
    .into_iter()
    .map(|invocation| {
        run_product_doctor(
            invocation,
            path.map(Path::as_os_str),
            &redactor,
            &generated_at,
        )
    })
    .collect::<Vec<_>>();
    Ok(RegistryctlValidationReport {
        schema_version: REGISTRYCTL_VALIDATION_REPORT_SCHEMA_VERSION_V1.to_string(),
        project: RegistryctlProjectRef {
            path: project_dir.display().to_string(),
            profile: deployment_profile
                .map_or("project", DeploymentProfile::as_str)
                .to_string(),
        },
        status: registryctl_report_status(&products),
        products,
        cross_product_diagnostics: Vec::new(),
        generated_at,
    })
}

#[cfg(test)]
fn legacy_product_doctor_invocations(
    project_dir: &Path,
    project: &Project,
    deployment_profile: Option<DeploymentProfile>,
    path: Option<&OsStr>,
) -> Result<Vec<ProductDoctorInvocation>> {
    let mut invocations = Vec::new();
    if let Some(relay) = &project.relay {
        let mut doctor_args = vec![
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "registry-relay",
            "doctor",
            "--config",
            CANONICAL_RELAY_CONFIG_MOUNT,
            "--format",
            "json",
        ];
        if let Some(profile) = deployment_profile {
            doctor_args.push("--profile");
            doctor_args.push(profile.as_str());
        }
        invocations.push(ProductDoctorInvocation {
            product: "registry-relay",
            binary: project.runtime.engine.binary(),
            cwd: project_dir.to_path_buf(),
            config_path: project_dir.join(&relay.config),
            args: compose_command_args(&project.runtime.compose_file, &doctor_args),
            platform_override: compose_platform_for_project_with_path(
                project,
                project.runtime.engine.binary(),
                true,
                path,
            ),
        });
    }
    Ok(invocations)
}

type DoctorReport = RegistryctlValidationReport;

fn ensure_doctor_report_ok(report: &DoctorReport) -> Result<()> {
    if report
        .products
        .iter()
        .all(|product| matches!(product.status, ReportStatus::Ok | ReportStatus::Warning))
    {
        Ok(())
    } else {
        bail!("one or more product doctor checks failed")
    }
}

fn registryctl_report_status(products: &[RegistryctlProductReport]) -> ReportStatus {
    if products
        .iter()
        .any(|product| matches!(product.status, ReportStatus::Error | ReportStatus::NotRun))
    {
        ReportStatus::Error
    } else if products
        .iter()
        .any(|product| product.status == ReportStatus::Warning)
    {
        ReportStatus::Warning
    } else {
        ReportStatus::Ok
    }
}

fn rfc3339_now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn product_doctor_invocations(
    project_dir: &Path,
    runtime: &CanonicalRuntime,
    deployment_profile: Option<DeploymentProfile>,
    path: Option<&OsStr>,
) -> Result<Vec<ProductDoctorInvocation>> {
    let mut doctor_args = vec![
        "run",
        "--rm",
        "--no-deps",
        "-T",
        "registry-relay",
        "doctor",
        "--config",
        CANONICAL_RELAY_CONFIG_MOUNT,
        "--format",
        "json",
    ];
    if let Some(profile) = deployment_profile {
        doctor_args.push("--profile");
        doctor_args.push(profile.as_str());
    }
    let compose_file = runtime
        .compose_file
        .strip_prefix(project_dir)
        .map_err(|_| anyhow!("local Compose path escaped the canonical project"))?;
    Ok(vec![ProductDoctorInvocation {
        product: "registry-relay",
        binary: "docker",
        cwd: project_dir.to_path_buf(),
        config_path: runtime.relay_config.clone(),
        args: compose_command_args(compose_file, &doctor_args),
        platform_override: canonical_compose_platform_override(&runtime.image, true, path),
    }])
}

fn run_product_doctor(
    invocation: ProductDoctorInvocation,
    path: Option<&OsStr>,
    redactor: &SecretRedactor,
    generated_at: &str,
) -> RegistryctlProductReport {
    let mut command = Command::new(invocation.binary);
    command.args(&invocation.args);
    command.current_dir(&invocation.cwd);
    if let Some(path) = path {
        command.env("PATH", path);
    }
    if let Some(platform) = invocation.platform_override {
        command.env("DOCKER_DEFAULT_PLATFORM", platform);
    }
    match command.output() {
        Ok(output) => product_report_from_output(invocation, output, redactor, generated_at),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => RegistryctlProductReport {
            product: invocation.product.to_string(),
            status: ReportStatus::NotRun,
            report: fallback_product_report(
                invocation.product,
                &invocation.config_path,
                ReportStatus::NotRun,
                "registryctl.product_doctor.binary_missing",
                DiagnosticSeverity::Error,
                "Install Docker Engine or Docker Desktop with Docker Compose v2, then rerun `registryctl doctor`."
                    .to_string(),
                generated_at,
            ),
        },
        Err(err) => RegistryctlProductReport {
            product: invocation.product.to_string(),
            status: ReportStatus::Error,
            report: fallback_product_report(
                invocation.product,
                &invocation.config_path,
                ReportStatus::Error,
                "registryctl.product_doctor.start_failed",
                DiagnosticSeverity::Error,
                format!("failed to run {}: {err}", invocation.binary),
                generated_at,
            ),
        },
    }
}

fn product_report_from_output(
    invocation: ProductDoctorInvocation,
    output: Output,
    redactor: &SecretRedactor,
    generated_at: &str,
) -> RegistryctlProductReport {
    let stdout = redactor.redact_output(&output.stdout);
    let stderr = redactor.redact_output(&output.stderr);
    let passed = output.status.success();
    if let Some(report) = stdout.as_deref().and_then(parse_product_report) {
        let status = if passed {
            report.status
        } else {
            ReportStatus::Error
        };
        return RegistryctlProductReport {
            product: invocation.product.to_string(),
            status,
            report,
        };
    }

    let (code, message) = if passed {
        (
            "registryctl.product_doctor.report_missing",
            "product doctor exited successfully but did not emit a JSON diagnostic report"
                .to_string(),
        )
    } else {
        (
            "registryctl.product_doctor.report_missing_after_failure",
            format!(
                "product doctor exited nonzero without a JSON diagnostic report; exit_code={:?}; stdout_present={}; stderr_present={}",
                output.status.code(),
                stdout.is_some(),
                stderr.is_some()
            ),
        )
    };
    RegistryctlProductReport {
        product: invocation.product.to_string(),
        status: ReportStatus::Error,
        report: fallback_product_report(
            invocation.product,
            &invocation.config_path,
            ReportStatus::Error,
            code,
            DiagnosticSeverity::Error,
            message,
            generated_at,
        ),
    }
}

fn parse_product_report(stdout: &str) -> Option<ConfigDiagnosticReport> {
    serde_json::from_str(stdout).ok()
}

fn fallback_product_report(
    product: &str,
    config_path: &Path,
    status: ReportStatus,
    code: &str,
    severity: DiagnosticSeverity,
    message: String,
    generated_at: &str,
) -> ConfigDiagnosticReport {
    let diagnostics = vec![ConfigDiagnostic {
        code: code.to_string(),
        severity,
        path: None,
        message,
        replacement: None,
        documentation_key: None,
    }];
    ConfigDiagnosticReport {
        schema_version: "registry.config.diagnostic_report.v1".to_string(),
        product: product.to_string(),
        config_schema_version: product_config_schema_version(product).to_string(),
        source: ConfigSourceRef {
            kind: ConfigSourceKind::GeneratedFile,
            path: Some(config_path.display().to_string()),
            uri: None,
        },
        status,
        summary: diagnostic_summary(&diagnostics),
        diagnostics,
        required_env: Vec::new(),
        context_constraints: Vec::new(),
        audit_shipping: None,
        hashes: None,
        generated_at: generated_at.to_string(),
    }
}

fn product_config_schema_version(product: &str) -> &'static str {
    match product {
        "registry-relay" => "registry.relay.config.v1",
        "registry-notary" => "registry.notary.config.v1",
        _ => "registry.config.unknown.v1",
    }
}

fn diagnostic_summary(diagnostics: &[ConfigDiagnostic]) -> DiagnosticSummary {
    DiagnosticSummary {
        error_count: diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
            .count() as u64,
        warning_count: diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Warning)
            .count() as u64,
    }
}

struct SecretRedactor {
    secrets: Vec<String>,
}

impl SecretRedactor {
    fn new(secrets: &LocalEnv) -> Self {
        let mut secrets = secrets
            .values
            .values()
            .filter(|value| !value.is_empty())
            .cloned()
            .collect::<Vec<_>>();
        secrets.sort();
        secrets.dedup();
        secrets.sort_by_key(|value| std::cmp::Reverse(value.len()));
        Self { secrets }
    }

    fn redact_output(&self, bytes: &[u8]) -> Option<String> {
        if bytes.is_empty() {
            return None;
        }
        let mut output = String::from_utf8_lossy(bytes).into_owned();
        for secret in &self.secrets {
            output = output.replace(secret, "[REDACTED]");
        }
        Some(output)
    }
}

#[cfg(unix)]
fn write_private_text(path: &Path, contents: &str) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    reject_private_path_symlinks(path)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    let mut permissions = file.metadata()?.permissions();
    permissions.set_mode(0o600);
    file.set_permissions(permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_text(path: &Path, contents: &str) -> Result<()> {
    reject_private_path_symlinks(path)?;
    write_text(path.to_path_buf(), contents)
}

#[cfg(unix)]
fn write_runtime_nonsecret_text(path: &Path, contents: &str) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    reject_private_path_symlinks(path)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    let mut permissions = file.metadata()?.permissions();
    permissions.set_mode(0o644);
    file.set_permissions(permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_runtime_nonsecret_text(path: &Path, contents: &str) -> Result<()> {
    reject_private_path_symlinks(path)?;
    write_text(path.to_path_buf(), contents)
}

fn reject_private_path_symlinks(path: &Path) -> Result<()> {
    for candidate in [path.parent(), Some(path)].into_iter().flatten() {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "private path must not be a symlink: {}",
                    candidate.display()
                )
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", candidate.display()))
            }
        }
    }
    Ok(())
}

fn init_benefits_project(dir: &Path, image_lock: &RegistryctlImageLock) -> Result<InitReport> {
    if dir.exists() {
        let mut entries =
            fs::read_dir(dir).with_context(|| format!("failed to inspect {}", dir.display()))?;
        if entries.next().is_some() {
            bail!(
                "target directory already exists and is not empty: {}",
                dir.display()
            );
        }
    }

    fs::create_dir_all(dir.join("relay"))?;
    fs::create_dir_all(dir.join("data"))?;
    create_private_dir_all(&dir.join("secrets"))?;
    fs::create_dir_all(dir.join("output"))?;
    create_relay_state_dirs(dir)?;
    write_compose_runtime_env(dir)?;

    let credentials = LocalCredentials::generate()?;
    write_text(
        dir.join("registryctl.yaml"),
        &registryctl_manifest(dir, image_lock)?,
    )?;
    write_text(dir.join("compose.yaml"), &compose_yaml(image_lock)?)?;
    write_text(dir.join("README.md"), project_readme())?;
    write_text(dir.join(".gitignore"), include_str!("templates/gitignore"))?;
    write_text(dir.join("relay/config.yaml"), &relay_config(&credentials))?;
    write_private_text(&dir.join("secrets/local.env"), &credentials.env_file())?;
    write_text(dir.join("output/.gitkeep"), "")?;
    sample::write_benefits_workbook(&dir.join("data/benefits_casework.xlsx"))?;
    let bruno_collection = bruno_generate_project(dir, false)?;
    Ok(InitReport {
        schema_version: INIT_REPORT_SCHEMA_VERSION,
        status: "initialized",
        project: generated_project_name(dir),
        project_kind: InitProjectKind::RelaySpreadsheetApi,
        output: dir.to_path_buf(),
        source: InitSource::Sample {
            id: Sample::Benefits.id().to_string(),
        },
        artifacts: InitArtifacts {
            project_file: dir.join("registryctl.yaml"),
            bruno_collection: Some(bruno_collection),
            editor_manifest: None,
        },
    })
}

fn write_text(path: PathBuf, contents: &str) -> Result<()> {
    fs::write(&path, contents).with_context(|| format!("failed to write {}", path.display()))
}

fn create_relay_state_dirs(dir: &Path) -> Result<()> {
    create_state_dirs(
        dir,
        &[
            "state",
            "state/relay",
            "state/relay/cache",
            "state/relay/config-state",
            "state/relay/audit",
        ],
    )
}

fn create_state_dirs(dir: &Path, paths: &[&str]) -> Result<()> {
    #[cfg(unix)]
    let identity = compose_runtime_identity_values(dir)?;

    for path in paths {
        let path = dir.join(path);
        create_private_dir_all(&path)?;
        #[cfg(unix)]
        ensure_private_state_owner(&path, identity)?;
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy)]
pub(crate) struct RuntimeIdentity {
    uid: u32,
    gid: u32,
}

#[cfg(not(unix))]
#[derive(Clone, Copy)]
pub(crate) struct RuntimeIdentity;

#[cfg(unix)]
fn compose_runtime_identity_values(dir: &Path) -> Result<RuntimeIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata =
        fs::metadata(dir).with_context(|| format!("failed to stat {}", dir.display()))?;
    Ok(runtime_identity_for_owner(metadata.uid(), metadata.gid()))
}

#[cfg(unix)]
fn runtime_identity_for_owner(uid: u32, gid: u32) -> RuntimeIdentity {
    let default_id = DEFAULT_NONROOT_CONTAINER_ID
        .parse()
        .expect("default nonroot container id is numeric");
    RuntimeIdentity {
        uid: if uid == 0 { default_id } else { uid },
        gid: if gid == 0 { default_id } else { gid },
    }
}

#[cfg(unix)]
fn ensure_private_state_owner(path: &Path, identity: RuntimeIdentity) -> Result<()> {
    use std::os::unix::fs::{lchown, MetadataExt};

    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.uid() == identity.uid {
        return Ok(());
    }

    lchown(path, Some(identity.uid), Some(identity.gid)).with_context(|| {
        format!(
            "failed to set owner of {} to {}:{}",
            path.display(),
            identity.uid,
            identity.gid
        )
    })?;
    Ok(())
}

fn write_compose_runtime_env(dir: &Path) -> Result<()> {
    let path = dir.join(".env");
    let values = compose_runtime_env_values(dir)?;
    let body = if path.exists() {
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        upsert_env_values(&contents, &values)
    } else {
        format!(
            "# Generated by registryctl. Docker Compose uses these values to run product\n\
             # containers as the project runtime owner so private state directories stay writable.\n\
             {REGISTRY_STACK_RUNTIME_UID_ENV}={}\n\
             {REGISTRY_STACK_RUNTIME_GID_ENV}={}\n",
            values[0].1, values[1].1
        )
    };
    write_text(path, &body)
}

fn compose_runtime_env_values(dir: &Path) -> Result<Vec<(String, String)>> {
    let (uid, gid) = compose_runtime_identity(dir)?;
    Ok(vec![
        (REGISTRY_STACK_RUNTIME_UID_ENV.to_string(), uid),
        (REGISTRY_STACK_RUNTIME_GID_ENV.to_string(), gid),
    ])
}

#[cfg(unix)]
fn compose_runtime_identity(dir: &Path) -> Result<(String, String)> {
    let identity = compose_runtime_identity_values(dir)?;
    Ok((identity.uid.to_string(), identity.gid.to_string()))
}

#[cfg(not(unix))]
fn compose_runtime_identity(_dir: &Path) -> Result<(String, String)> {
    Ok((
        DEFAULT_NONROOT_CONTAINER_ID.to_string(),
        DEFAULT_NONROOT_CONTAINER_ID.to_string(),
    ))
}

#[cfg(unix)]
fn create_private_dir_all(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .with_context(|| format!("failed to create {}", path.display()))?;

    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "private directory path must not be a symlink: {}",
            path.display()
        );
    }
    if !metadata.is_dir() {
        bail!(
            "private directory path must be a directory: {}",
            path.display()
        );
    }

    let mut permissions = metadata.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn create_private_dir_all(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))?;
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "private directory path must not be a symlink: {}",
            path.display()
        );
    }
    if !metadata.is_dir() {
        bail!(
            "private directory path must be a directory: {}",
            path.display()
        );
    }
    Ok(())
}

#[derive(Debug)]
struct GeneratedFile {
    relative_path: String,
    contents: String,
    sensitivity: GeneratedFileSensitivity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GeneratedFileSensitivity {
    Public,
    Private,
}

fn write_generated_files(
    project_dir: &Path,
    collection_dir: &Path,
    mut files: Vec<GeneratedFile>,
    force: bool,
) -> Result<()> {
    let mut manifest_paths: Vec<_> = files
        .iter()
        .map(|file| file.relative_path.clone())
        .collect();
    manifest_paths.push(".registryctl-generated".to_string());
    files.push(GeneratedFile {
        relative_path: ".registryctl-generated".to_string(),
        contents: generated_manifest_contents(&manifest_paths),
        sensitivity: GeneratedFileSensitivity::Public,
    });
    let known = read_generated_manifest(project_dir);

    for file in &files {
        let path = collection_dir.join(&file.relative_path);
        ensure_no_symlink_components(project_dir, &path)?;
        if path.exists() && !force && !known.contains_key(&file.relative_path) {
            bail!(
                "{} already exists and is not marked as registryctl-generated; rerun with --force to overwrite it",
                path.display()
            );
        }
    }

    for file in files {
        let path = collection_dir.join(&file.relative_path);
        fs::create_dir_all(path.parent().unwrap_or(collection_dir))?;
        ensure_no_symlink_components(project_dir, &path)?;
        match file.sensitivity {
            GeneratedFileSensitivity::Private => write_private_text(&path, &file.contents)?,
            GeneratedFileSensitivity::Public => write_text(path, &file.contents)?,
        }
    }

    Ok(())
}

fn ensure_no_symlink_components(project_dir: &Path, path: &Path) -> Result<()> {
    let relative = path.strip_prefix(project_dir).with_context(|| {
        format!(
            "generated path {} must stay inside project {}",
            path.display(),
            project_dir.display()
        )
    })?;
    let mut candidate = project_dir.to_path_buf();
    for component in relative.components() {
        candidate.push(component);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "generated path must not contain a symlink: {}",
                    candidate.display()
                )
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", candidate.display()))
            }
        }
    }
    Ok(())
}

fn read_generated_manifest(project_dir: &Path) -> BTreeMap<String, bool> {
    let path = project_dir.join(BRUNO_GENERATED_MANIFEST);
    let Ok(contents) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| (line.to_string(), true))
        .collect()
}

fn generated_manifest_contents(paths: &[String]) -> String {
    let mut paths: Vec<_> = paths.iter().map(String::as_str).collect();
    paths.sort_unstable();
    let mut output = paths.join("\n");
    output.push('\n');
    output
}

fn bruno_files(project: &Project, secrets: &LocalEnv) -> Result<Vec<GeneratedFile>> {
    let mut files = vec![
        generated_file(
            "bruno.json",
            r#"{
  "version": "1",
  "name": "Registry API",
  "type": "collection",
  "ignore": [
    "node_modules",
    ".git"
  ]
}
"#,
        ),
        generated_file(
            "collection.bru",
            "docs {\nGenerated local Registry Stack API collection.\n}\n",
        ),
    ];

    if project.relay.is_some() {
        files.extend(bruno_relay_files(project.relay_base_url()?, secrets));
    }
    files.push(generated_private_file(
        "environments/local.bru",
        &bruno_local_env(project, secrets)?,
    ));
    files.push(generated_file(
        "environments/local.example.bru",
        &bruno_example_env(project)?,
    ));
    Ok(files)
}

fn generated_file(path: &str, contents: &str) -> GeneratedFile {
    GeneratedFile {
        relative_path: path.to_string(),
        contents: contents.to_string(),
        sensitivity: GeneratedFileSensitivity::Public,
    }
}

fn generated_private_file(path: &str, contents: &str) -> GeneratedFile {
    GeneratedFile {
        relative_path: path.to_string(),
        contents: contents.to_string(),
        sensitivity: GeneratedFileSensitivity::Private,
    }
}

fn bruno_relay_files(relay_base_url: &str, _secrets: &LocalEnv) -> Vec<GeneratedFile> {
    let application_query_body = r#"{
  "measures": ["application_count"],
  "group_by": ["program", "application_status"],
  "filters": {
    "program": "cash_transfer"
  }
}"#;

    vec![
        bruno_get(
            "Relay/Health.bru",
            "Relay health",
            1,
            "{{relay_base_url}}/healthz",
            &[],
        ),
        bruno_get("Relay/Ready.bru", "Relay ready", 2, "{{relay_base_url}}/ready", &[]),
        bruno_get(
            "Relay/OpenAPI.bru",
            "Relay OpenAPI",
            3,
            "{{relay_base_url}}/openapi.json",
            &[],
        ),
        bruno_get(
            "Relay/Unauthorized datasets.bru",
            "Unauthorized datasets",
            4,
            "{{relay_base_url}}/v1/datasets",
            &[],
        ),
        bruno_get(
            "Relay/List datasets.bru",
            "List datasets",
            5,
            "{{relay_base_url}}/v1/datasets",
            &[("Authorization", "Bearer {{relay_metadata_key}}")],
        ),
        bruno_get(
            "Relay/Get dataset detail.bru",
            "Get dataset detail",
            6,
            "{{relay_base_url}}/v1/datasets/benefits_casework",
            &[("Authorization", "Bearer {{relay_metadata_key}}")],
        ),
        bruno_get(
            "Relay/Metadata catalog.bru",
            "Metadata catalog",
            7,
            "{{relay_base_url}}/metadata/catalog",
            &[("Authorization", "Bearer {{relay_metadata_key}}")],
        ),
        bruno_get(
            "Relay/Household schema.bru",
            "Household schema",
            8,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/household/schema",
            &[("Authorization", "Bearer {{relay_metadata_key}}")],
        ),
        bruno_get(
            "Relay/Person schema.bru",
            "Person schema",
            9,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/person/schema",
            &[("Authorization", "Bearer {{relay_metadata_key}}")],
        ),
        bruno_get(
            "Relay/Application schema.bru",
            "Application schema",
            10,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/application/schema",
            &[("Authorization", "Bearer {{relay_metadata_key}}")],
        ),
        bruno_get(
            "Relay/Read households by district.bru",
            "Read households by district",
            11,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/household/records?district=south",
            &[
                ("Authorization", "Bearer {{relay_row_key}}"),
                ("Data-Purpose", "{{purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/Read household with members.bru",
            "Read household with members",
            12,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/household/records/hh-1001?expand=members",
            &[
                ("Authorization", "Bearer {{relay_row_key}}"),
                ("Data-Purpose", "{{purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/Read sample people.bru",
            "Read sample people",
            13,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/person/records?household_id=hh-1001",
            &[
                ("Authorization", "Bearer {{relay_row_key}}"),
                ("Data-Purpose", "{{purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/Read pending people.bru",
            "Read pending registrations",
            14,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/person/records?registration_status=pending",
            &[
                ("Authorization", "Bearer {{relay_row_key}}"),
                ("Data-Purpose", "{{purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/Read person with household.bru",
            "Read person with household",
            15,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/person/records/per-2001?expand=household",
            &[
                ("Authorization", "Bearer {{relay_row_key}}"),
                ("Data-Purpose", "{{purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/Read approved applications.bru",
            "Read approved applications",
            16,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/application/records?application_status=approved",
            &[
                ("Authorization", "Bearer {{relay_row_key}}"),
                ("Data-Purpose", "{{purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/Read application with applicant.bru",
            "Read application with applicant",
            17,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/application/records/app-3001?expand=applicant",
            &[
                ("Authorization", "Bearer {{relay_row_key}}"),
                ("Data-Purpose", "{{purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/People missing purpose.bru",
            "People missing purpose",
            18,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/person/records?household_id=hh-1001",
            &[("Authorization", "Bearer {{relay_row_key}}")],
        ),
        bruno_get(
            "Relay/Metadata key cannot read people.bru",
            "Metadata key cannot read people",
            19,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/person/records?household_id=hh-1001",
            &[
                ("Authorization", "Bearer {{relay_metadata_key}}"),
                ("Data-Purpose", "{{purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/Row key cannot read identity.bru",
            "Row key cannot read identity",
            20,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/person_identity/records/per-2001?expand=household_contact",
            &[
                ("Authorization", "Bearer {{relay_row_key}}"),
                ("Data-Purpose", "{{identity_purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/Read restricted identity.bru",
            "Read restricted identity",
            21,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/person_identity/records/per-2001?expand=household_contact",
            &[
                ("Authorization", "Bearer {{relay_identity_key}}"),
                ("Data-Purpose", "{{identity_purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/List aggregates.bru",
            "List aggregates",
            22,
            "{{relay_base_url}}/v1/datasets/benefits_casework/aggregates",
            &[("Authorization", "Bearer {{relay_aggregate_key}}")],
        ),
        bruno_get(
            "Relay/Run households by district aggregate.bru",
            "Run households by district aggregate",
            23,
            "{{relay_base_url}}/v1/datasets/benefits_casework/aggregates/by_district",
            &[
                ("Authorization", "Bearer {{relay_aggregate_key}}"),
                ("Data-Purpose", "{{purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/Run applications aggregate as CSV.bru",
            "Run applications aggregate as CSV",
            24,
            "{{relay_base_url}}/v1/datasets/benefits_casework/aggregates/applications_by_program_status?f=csv",
            &[
                ("Authorization", "Bearer {{relay_aggregate_key}}"),
                ("Data-Purpose", "{{purpose}}"),
                ("Accept", "text/csv"),
            ],
        ),
        bruno_post_json(
            "Relay/Query applications aggregate.bru",
            "Query applications aggregate",
            25,
            "{{relay_base_url}}/v1/datasets/benefits_casework/aggregates/applications_by_program_status/query",
            &[
                ("Authorization", "Bearer {{relay_aggregate_key}}"),
                ("Data-Purpose", "{{purpose}}"),
                ("Content-Type", "application/json"),
                ("Accept", "application/json"),
            ],
            application_query_body,
        ),
        generated_file(
            "Relay/folder.bru",
            "meta {\n  name: Relay\n  type: folder\n  seq: 1\n}\n",
        ),
        generated_file(
            "Relay/README.md",
            &format!(
                "Relay requests use the generated local API at {relay_base_url}. Request files use Bruno variables and do not contain raw keys.\n"
            ),
        ),
    ]
}

fn bruno_get(
    path: &str,
    name: &str,
    seq: u32,
    url: &str,
    headers: &[(&str, &str)],
) -> GeneratedFile {
    let mut contents = format!(
        "meta {{\n  name: {name}\n  type: http\n  seq: {seq}\n}}\n\nget {{\n  url: {url}\n  body: none\n  auth: none\n}}\n"
    );
    contents.push_str(&bruno_headers(headers));
    generated_file(path, &contents)
}

fn bruno_post_json(
    path: &str,
    name: &str,
    seq: u32,
    url: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> GeneratedFile {
    let mut contents = format!(
        "meta {{\n  name: {name}\n  type: http\n  seq: {seq}\n}}\n\npost {{\n  url: {url}\n  body: json\n  auth: none\n}}\n"
    );
    contents.push_str(&bruno_headers(headers));
    contents.push_str("\nbody:json {\n");
    contents.push_str(body);
    contents.push_str("\n}\n");
    generated_file(path, &contents)
}

fn bruno_headers(headers: &[(&str, &str)]) -> String {
    if headers.is_empty() {
        return String::new();
    }
    let mut contents = "\nheaders {\n".to_string();
    for (name, value) in headers {
        contents.push_str("  ");
        contents.push_str(name);
        contents.push_str(": ");
        contents.push_str(value);
        contents.push('\n');
    }
    contents.push_str("}\n");
    contents
}

fn bruno_local_env(project: &Project, secrets: &LocalEnv) -> Result<String> {
    bruno_env(project, secrets, false)
}

fn bruno_example_env(project: &Project) -> Result<String> {
    bruno_env(
        project,
        &LocalEnv {
            values: BTreeMap::new(),
        },
        true,
    )
}

fn bruno_env(project: &Project, secrets: &LocalEnv, example: bool) -> Result<String> {
    let mut values = Vec::new();
    values.push(("purpose", TUTORIAL_PURPOSE.to_string()));
    values.push(("identity_purpose", TUTORIAL_IDENTITY_PURPOSE.to_string()));
    if project.relay.is_some() {
        values.push(("relay_base_url", project.relay_base_url()?.to_string()));
        values.push((
            "relay_metadata_key",
            bruno_env_value(secrets, "METADATA_READER_RAW", example),
        ));
        values.push((
            "relay_row_key",
            bruno_env_value(secrets, "ROW_READER_RAW", example),
        ));
        values.push((
            "relay_aggregate_key",
            bruno_env_value(secrets, "AGGREGATE_READER_RAW", example),
        ));
        values.push((
            "relay_identity_key",
            bruno_env_value(secrets, "IDENTITY_READER_RAW", example),
        ));
    }

    let mut contents = "vars {\n".to_string();
    for (name, value) in values {
        contents.push_str("  ");
        contents.push_str(name);
        contents.push_str(": ");
        contents.push_str(&value);
        contents.push('\n');
    }
    contents.push_str("}\n");
    Ok(contents)
}

fn bruno_env_value(secrets: &LocalEnv, name: &str, example: bool) -> String {
    if example {
        format!("replace-with-{}", name.to_ascii_lowercase())
    } else {
        secrets.value(name).to_string()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Project {
    // Not read anywhere today beyond load-time validation (see `deserialize_schema_version`);
    // modeled so `deny_unknown_fields` doesn't reject registryctl's own generated files
    // (see `registryctl_manifest`).
    #[allow(dead_code)]
    #[serde(deserialize_with = "deserialize_schema_version")]
    schema_version: String,
    #[allow(dead_code)]
    project: ProjectMeta,
    #[serde(default)]
    relay: Option<ProjectRelay>,
    runtime: ProjectRuntime,
    local: ProjectLocal,
}

/// The `project:` metadata block `registryctl_manifest` writes into every generated
/// `registryctl.yaml` (see `ProjectSection`); not consumed elsewhere today, but modeled here
/// so `deny_unknown_fields` doesn't reject registryctl's own generated files.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectMeta {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    kind: String,
    #[allow(dead_code)]
    products: Vec<String>,
}

impl Project {
    fn load(project_dir: &Path) -> Result<Self> {
        let path = project_dir.join("registryctl.yaml");
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_norway::from_str(&contents)
            .with_context(|| format!("failed to parse {}", path.display()))
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectRelay {
    config: PathBuf,
    #[serde(default)]
    metadata: Option<PathBuf>,
    #[serde(default)]
    data: Vec<PathBuf>,
}

/// Validates `schema_version` against `PROJECT_SCHEMA_VERSION`, the only version
/// `registryctl_manifest` generates today, so a future/incompatible schema file fails project
/// load instead of half-parsing.
fn deserialize_schema_version<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;

    let schema_version = String::deserialize(deserializer)?;
    if schema_version != PROJECT_SCHEMA_VERSION {
        return Err(D::Error::custom(format!(
            "invalid schema_version {schema_version:?}; expected {PROJECT_SCHEMA_VERSION:?}"
        )));
    }
    Ok(schema_version)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectRuntime {
    engine: RuntimeEngine,
    #[serde(deserialize_with = "deserialize_compose_file")]
    compose_file: PathBuf,
    #[serde(default)]
    relay_image: Option<String>,
    #[serde(default)]
    relay_base_url: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeEngine {
    DockerCompose,
}

impl RuntimeEngine {
    #[allow(dead_code)]
    const fn binary(self) -> &'static str {
        match self {
            Self::DockerCompose => "docker",
        }
    }
}

fn deserialize_compose_file<'de, D>(deserializer: D) -> std::result::Result<PathBuf, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;

    let path = PathBuf::deserialize(deserializer)?;
    if path != Path::new("compose.yaml") {
        return Err(D::Error::custom(format!(
            "unsupported runtime compose_file {path:?}; expected \"compose.yaml\""
        )));
    }
    Ok(path)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectLocal {
    secrets_env: PathBuf,
    output_dir: PathBuf,
}

impl Project {
    fn relay_base_url(&self) -> Result<&str> {
        if self.relay.is_none() {
            bail!("project does not have a Relay section");
        }
        self.runtime
            .relay_base_url
            .as_deref()
            .ok_or_else(|| anyhow!("project runtime is missing relay_base_url"))
    }
}

#[derive(Debug)]
struct LocalEnv {
    values: BTreeMap<String, String>,
}

impl LocalEnv {
    fn load(path: &Path) -> Result<Self> {
        reject_private_path_symlinks(path)?;
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Ok(Self {
            values: parse_local_env(&contents),
        })
    }

    fn required(&self, name: &str) -> Result<&str> {
        self.values
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("missing required local env value {name}"))
    }

    fn value(&self, name: &str) -> &str {
        self.values.get(name).map(String::as_str).unwrap_or("")
    }
}

fn parse_local_env(contents: &str) -> BTreeMap<String, String> {
    contents
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn upsert_env_values(contents: &str, values: &[(String, String)]) -> String {
    let replacements: BTreeMap<&str, &str> = values
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let mut seen = BTreeMap::new();
    let mut lines = Vec::new();

    for line in contents.lines() {
        if let Some((key, _)) = line.split_once('=') {
            if let Some(value) = replacements.get(key) {
                lines.push(format!("{key}={value}"));
                seen.insert(key.to_string(), true);
                continue;
            }
        }
        lines.push(line.to_string());
    }

    for (key, value) in values {
        if !seen.contains_key(key) {
            lines.push(format!("{key}={value}"));
        }
    }

    let mut output = lines.join("\n");
    output.push('\n');
    output
}

#[allow(dead_code)]
fn run_compose_for_project(project_dir: &Path, project: &Project, args: &[&str]) -> Result<()> {
    let binary = project.runtime.engine.binary();
    let platform_override =
        compose_platform_for_project(project, binary, should_probe_compose_platform(args));
    run_compose_command_with_platform(
        project_dir,
        binary,
        &project.runtime.compose_file,
        args,
        platform_override,
    )
}

fn run_compose_for_canonical_runtime(
    project_dir: &Path,
    runtime: &CanonicalRuntime,
    args: &[&str],
) -> Result<()> {
    let compose_file = runtime
        .compose_file
        .strip_prefix(project_dir)
        .map_err(|_| anyhow!("local Compose path escaped the canonical project"))?;
    let platform_override = canonical_compose_platform_override(
        &runtime.image,
        should_probe_compose_platform(args),
        None,
    );
    run_compose_command_with_platform(project_dir, "docker", compose_file, args, platform_override)
}

fn canonical_compose_platform_override(
    image: &str,
    probe_server_platform: bool,
    path: Option<&OsStr>,
) -> Option<&'static str> {
    if std::env::var("DOCKER_DEFAULT_PLATFORM")
        .ok()
        .is_some_and(|platform| !platform.trim().is_empty())
        || !(image.starts_with(&format!("{RELAY_IMAGE_REPOSITORY}@sha256:"))
            || image.starts_with("ghcr.io/registrystack/registry-relay-candidate@sha256:"))
        || !probe_server_platform
    {
        return None;
    }
    docker_server_platform("docker", path)
        .filter(|platform| is_linux_arm64_platform(platform))
        .map(|_| LINUX_AMD64_PLATFORM)
}

#[allow(dead_code)]
fn compose_platform_for_project(
    project: &Project,
    binary: &str,
    probe_server_platform: bool,
) -> Option<&'static str> {
    compose_platform_for_project_with_path(project, binary, probe_server_platform, None)
}

#[allow(dead_code)]
fn compose_platform_for_project_with_path(
    project: &Project,
    binary: &str,
    probe_server_platform: bool,
    path: Option<&OsStr>,
) -> Option<&'static str> {
    let explicit_platform = std::env::var("DOCKER_DEFAULT_PLATFORM").ok();
    let server_platform = probe_server_platform
        .then(|| docker_server_platform(binary, path))
        .flatten();
    compose_platform_override(
        project,
        explicit_platform.as_deref(),
        server_platform.as_deref(),
    )
}

fn run_compose_command_with_platform(
    project_dir: &Path,
    binary: &str,
    compose_file: &Path,
    args: &[&str],
    platform_override: Option<&str>,
) -> Result<()> {
    let command_args = compose_command_args(compose_file, args);
    let mut command = Command::new(binary);
    command.args(&command_args).current_dir(project_dir);
    if let Some(platform) = platform_override {
        eprintln!("Using DOCKER_DEFAULT_PLATFORM={platform} for Registry Stack release images on this Docker host.");
        command.env("DOCKER_DEFAULT_PLATFORM", platform);
    }
    let status = command
        .status()
        .with_context(|| format!("failed to run {binary} compose"))?;
    if status.success() {
        Ok(())
    } else {
        bail!("{binary} compose exited with {status}")
    }
}

fn should_probe_compose_platform(args: &[&str]) -> bool {
    args.first().is_some_and(|arg| *arg == "up")
}

fn docker_server_platform(binary: &str, path: Option<&OsStr>) -> Option<String> {
    let mut command = Command::new(binary);
    command.args(["version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"]);
    if let Some(path) = path {
        command.env("PATH", path);
    }
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let platform = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!platform.is_empty()).then_some(platform)
}

#[allow(dead_code)]
fn compose_platform_override(
    project: &Project,
    explicit_platform: Option<&str>,
    docker_server_platform: Option<&str>,
) -> Option<&'static str> {
    if explicit_platform.is_some_and(|platform| !platform.trim().is_empty()) {
        return None;
    }
    if !project_uses_amd64_only_release_image(project) {
        return None;
    }
    docker_server_platform
        .filter(|platform| is_linux_arm64_platform(platform))
        .map(|_| LINUX_AMD64_PLATFORM)
}

#[allow(dead_code)]
fn project_uses_amd64_only_release_image(project: &Project) -> bool {
    let relay_is_amd64_only = project
        .runtime
        .relay_image
        .as_deref()
        .is_some_and(|image| image.starts_with(&format!("{RELAY_IMAGE_REPOSITORY}@sha256:")));
    relay_is_amd64_only
}

fn is_linux_arm64_platform(platform: &str) -> bool {
    let normalized = platform.trim().to_ascii_lowercase();
    matches!(normalized.as_str(), "linux/arm64" | "linux/aarch64")
        || normalized.starts_with("linux/arm64/")
}

fn compose_command_args(compose_file: &Path, args: &[&str]) -> Vec<String> {
    let mut command = vec![
        "compose".to_string(),
        "-f".to_string(),
        compose_file.display().to_string(),
    ];
    command.extend(args.iter().map(|arg| (*arg).to_string()));
    command
}

#[allow(dead_code)]
fn validate_project_fingerprints(project_dir: &Path, project: &Project) -> Result<()> {
    let secrets = LocalEnv::load(&project_dir.join(&project.local.secrets_env))?;
    if let Some(relay) = &project.relay {
        validate_config_api_key_fingerprints(&project_dir.join(&relay.config), "Relay", &secrets)?;
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_config_api_key_fingerprints(
    config_path: &Path,
    product: &str,
    secrets: &LocalEnv,
) -> Result<()> {
    let config = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let config: serde_norway::Value = serde_norway::from_str(&config)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;
    let api_keys = config["auth"]["api_keys"]
        .as_sequence()
        .ok_or_else(|| anyhow!("{product} config auth.api_keys must be a list"))?;
    for api_key in api_keys {
        let id = api_key["id"]
            .as_str()
            .ok_or_else(|| anyhow!("{product} config api key entry is missing id"))?;
        let hash_env = api_key["fingerprint"]["name"].as_str().ok_or_else(|| {
            anyhow!("{product} config api key {id} is missing fingerprint env name")
        })?;
        let fingerprint = secrets.required(hash_env)?;
        let raw_key = secrets.required(raw_env_name_for(id)?)?;
        if fingerprint != fingerprint_api_key(raw_key) {
            bail!("local raw key and fingerprint do not match for {id}");
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn raw_env_name_for(id: &str) -> Result<&'static str> {
    match id {
        "metadata_reader" => Ok("METADATA_READER_RAW"),
        "row_reader" => Ok("ROW_READER_RAW"),
        "aggregate_reader" => Ok("AGGREGATE_READER_RAW"),
        "identity_reader" => Ok("IDENTITY_READER_RAW"),
        "tutorial-evaluator" => Ok("TUTORIAL_EVALUATOR_RAW"),
        _ => bail!("unknown generated api key id {id}"),
    }
}

fn wait_for_ready(label: &str, base_url: &str, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let health = http_get(&format!("{base_url}/healthz"), &[]).ok();
        let ready = http_get(&format!("{base_url}/ready"), &[]).ok();
        if matches!(health.as_ref().map(|response| response.status), Some(200))
            && matches!(ready.as_ref().map(|response| response.status), Some(200))
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(500));
    }
    bail!("{label} did not become healthy and ready before timeout")
}

fn print_probe_status(name: &str, url: &str) {
    match http_get(url, &[]) {
        Ok(response) => println!("{name}: {}", response.status),
        Err(err) => println!("{name}: unavailable ({err})"),
    }
}

#[derive(Debug)]
struct LocalCredentials {
    metadata_reader: Credential,
    row_reader: Credential,
    aggregate_reader: Credential,
    identity_reader: Credential,
    audit_hash_secret: String,
}

impl LocalCredentials {
    fn generate() -> Result<Self> {
        Ok(Self {
            metadata_reader: Credential::generate("metadata_reader")?,
            row_reader: Credential::generate("row_reader")?,
            aggregate_reader: Credential::generate("aggregate_reader")?,
            identity_reader: Credential::generate("identity_reader")?,
            audit_hash_secret: random_token(48)?,
        })
    }

    fn env_file(&self) -> String {
        format!(
            "\
METADATA_READER_RAW={metadata_raw}
METADATA_READER_HASH={metadata_hash}
ROW_READER_RAW={row_raw}
ROW_READER_HASH={row_hash}
AGGREGATE_READER_RAW={aggregate_raw}
AGGREGATE_READER_HASH={aggregate_hash}
IDENTITY_READER_RAW={identity_raw}
IDENTITY_READER_HASH={identity_hash}
REGISTRY_RELAY_AUDIT_HASH_SECRET={audit_hash_secret}
",
            metadata_raw = self.metadata_reader.raw,
            metadata_hash = self.metadata_reader.fingerprint,
            row_raw = self.row_reader.raw,
            row_hash = self.row_reader.fingerprint,
            aggregate_raw = self.aggregate_reader.raw,
            aggregate_hash = self.aggregate_reader.fingerprint,
            identity_raw = self.identity_reader.raw,
            identity_hash = self.identity_reader.fingerprint,
            audit_hash_secret = self.audit_hash_secret,
        )
    }
}

#[derive(Debug)]
struct Credential {
    id: &'static str,
    raw: String,
    fingerprint: String,
}

impl Credential {
    fn generate(id: &'static str) -> Result<Self> {
        let raw = random_token(32)?;
        validate_api_key_entropy(&raw)?;
        let fingerprint = fingerprint_api_key(&raw);
        Ok(Self {
            id,
            raw,
            fingerprint,
        })
    }
}

fn random_token(byte_len: usize) -> Result<String> {
    let mut bytes = vec![0_u8; byte_len];
    getrandom::fill(&mut bytes).map_err(|err| anyhow!("random generation failed: {err}"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

#[derive(Serialize)]
struct ProjectManifest<'a> {
    schema_version: &'a str,
    project: ProjectSection<'a>,
    runtime: RuntimeSection<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay: Option<RelaySection<'a>>,
    local: LocalSection<'a>,
}

#[derive(Serialize)]
struct ProjectSection<'a> {
    name: String,
    kind: &'a str,
    products: Vec<&'a str>,
}

#[derive(Serialize)]
struct RuntimeSection<'a> {
    engine: &'a str,
    compose_file: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_image: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_base_url: Option<&'a str>,
}

#[derive(Serialize)]
struct RelaySection<'a> {
    config: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<&'a str>,
    data: Vec<&'a str>,
}

#[derive(Serialize)]
struct LocalSection<'a> {
    secrets_env: &'a str,
    output_dir: &'a str,
}

fn registryctl_manifest(dir: &Path, image_lock: &RegistryctlImageLock) -> Result<String> {
    let name = generated_project_name(dir);
    let manifest = ProjectManifest {
        schema_version: PROJECT_SCHEMA_VERSION,
        project: ProjectSection {
            name,
            kind: "spreadsheet-api",
            products: vec!["registry-relay"],
        },
        runtime: RuntimeSection {
            engine: "docker_compose",
            compose_file: "compose.yaml",
            relay_image: Some(image_lock.relay_image()),
            relay_base_url: Some(RELAY_BASE_URL),
        },
        relay: Some(RelaySection {
            config: "relay/config.yaml",
            metadata: None,
            data: vec!["data/benefits_casework.xlsx"],
        }),
        local: LocalSection {
            secrets_env: "secrets/local.env",
            output_dir: "output",
        },
    };
    serde_norway::to_string(&manifest).context("failed to render registryctl manifest")
}

fn generated_project_name(dir: &Path) -> String {
    dir.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("my-first-api")
        .to_string()
}

fn compose_yaml(image_lock: &RegistryctlImageLock) -> Result<String> {
    let rendered =
        include_str!("templates/compose.yaml").replace("{{relay_image}}", image_lock.relay_image());
    validate_generated_compose_ports(&rendered)?;
    Ok(rendered)
}

fn validate_generated_compose_ports(contents: &str) -> Result<()> {
    let compose: serde_norway::Value =
        serde_norway::from_str(contents).context("failed to parse generated Compose file")?;
    validate_generated_service_port(&compose, "registry-relay", "127.0.0.1:4242:8080")?;
    Ok(())
}

fn validate_generated_service_port(
    compose: &serde_norway::Value,
    service: &str,
    expected: &str,
) -> Result<()> {
    let ports = compose["services"][service]["ports"]
        .as_sequence()
        .ok_or_else(|| anyhow!("generated Compose service {service} must declare ports"))?;
    if ports.len() != 1 || ports[0].as_str() != Some(expected) {
        bail!(
            "generated Compose service {service} must publish exactly {expected:?} on IPv4 loopback"
        );
    }
    Ok(())
}

fn project_readme() -> &'static str {
    include_str!("templates/project_readme.md")
}

fn relay_config(credentials: &LocalCredentials) -> String {
    include_str!("templates/relay_config.yaml.tmpl")
        .replace("{{metadata_id}}", credentials.metadata_reader.id)
        .replace("{{row_id}}", credentials.row_reader.id)
        .replace("{{aggregate_id}}", credentials.aggregate_reader.id)
        .replace("{{identity_id}}", credentials.identity_reader.id)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SmokeReport {
    schema_version: SmokeReportSchema,
    base_url: String,
    passed: bool,
    checks: Vec<SmokeCheck>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum SmokeReportSchema {
    #[serde(rename = "registryctl.smoke.v1")]
    V1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SmokeCheck {
    name: String,
    method: String,
    path: String,
    expected_status: u16,
    actual_status: Option<u16>,
    passed: bool,
    error: Option<String>,
}

fn run_canonical_smoke_checks(
    base_url: &str,
    notary_base_url: &str,
    credentials: &CanonicalRuntimeCredentials,
) -> SmokeReport {
    const RECORDS_PATH: &str = "/v1/datasets/projects/entities/projects/records";
    const PURPOSE: &str = "public-works-case-management";

    let mut checks = Vec::new();
    record_smoke_check(
        &mut checks,
        base_url,
        "allowed public health check",
        "/healthz",
        200,
        &[],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "allowed match source is ready",
        "/ready",
        200,
        &[],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "denied anonymous records request",
        RECORDS_PATH,
        401,
        &[("Data-Purpose".to_string(), PURPOSE.to_string())],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "denied wrong local API key",
        RECORDS_PATH,
        401,
        &[
            bearer_header("registryctl-intentionally-wrong-local-key"),
            ("Data-Purpose".to_string(), PURPOSE.to_string()),
        ],
    );
    record_row_count_smoke_check(
        &mut checks,
        base_url,
        "allowed matching principal returns one record",
        RECORDS_PATH,
        &[
            bearer_header(&credentials.match_raw),
            ("Data-Purpose".to_string(), PURPOSE.to_string()),
        ],
        1,
    );
    record_row_count_smoke_check(
        &mut checks,
        base_url,
        "wrong principal safely returns no match",
        RECORDS_PATH,
        &[
            bearer_header(&credentials.no_match_raw),
            ("Data-Purpose".to_string(), PURPOSE.to_string()),
        ],
        0,
    );
    if let Some(notary) = &credentials.notary {
        record_notary_smoke_check(
            &mut checks,
            notary_base_url,
            "denied anonymous Notary evaluation",
            None,
            NotarySmokeExpectation {
                project_id: "pw_001",
                claim_id: "project-status-accepted",
                status: 401,
                value: None,
            },
        );
        record_notary_smoke_check(
            &mut checks,
            notary_base_url,
            "denied wrong Notary API key",
            Some("registryctl-intentionally-wrong-notary-key"),
            NotarySmokeExpectation {
                project_id: "pw_001",
                claim_id: "project-status-accepted",
                status: 401,
                value: None,
            },
        );
        record_notary_smoke_check(
            &mut checks,
            notary_base_url,
            "denied under-scoped Notary caller",
            Some(&notary.under_scoped_raw),
            NotarySmokeExpectation {
                project_id: "pw_001",
                claim_id: "project-status-accepted",
                status: 403,
                value: None,
            },
        );
        record_notary_smoke_check(
            &mut checks,
            notary_base_url,
            "matching evaluation returns the accepted predicate",
            Some(&notary.caller_raw),
            NotarySmokeExpectation {
                project_id: "pw_001",
                claim_id: "project-status-accepted",
                status: 200,
                value: Some(true),
            },
        );
        record_notary_smoke_check(
            &mut checks,
            notary_base_url,
            "second matching evaluation returns the non-accepted predicate",
            Some(&notary.caller_raw),
            NotarySmokeExpectation {
                project_id: "PW-002",
                claim_id: "project-status-accepted",
                status: 200,
                value: Some(false),
            },
        );
        record_notary_smoke_check(
            &mut checks,
            notary_base_url,
            "absent evaluation returns the bounded no-match predicate",
            Some(&notary.caller_raw),
            NotarySmokeExpectation {
                project_id: "pw_999",
                claim_id: "project-record-exists",
                status: 200,
                value: Some(false),
            },
        );
    }
    SmokeReport {
        schema_version: SmokeReportSchema::V1,
        base_url: base_url.to_string(),
        passed: checks.iter().all(|check| check.passed),
        checks,
    }
}

struct NotarySmokeExpectation<'a> {
    project_id: &'a str,
    claim_id: &'a str,
    status: u16,
    value: Option<bool>,
}

fn record_notary_smoke_check(
    checks: &mut Vec<SmokeCheck>,
    base_url: &str,
    name: &'static str,
    api_key: Option<&str>,
    expected: NotarySmokeExpectation<'_>,
) {
    const PATH: &str = "/v1/evaluations";
    let mut headers = vec![
        (
            "Data-Purpose".to_string(),
            "public-works-case-management".to_string(),
        ),
        ("Content-Type".to_string(), "application/json".to_string()),
        (
            "Accept".to_string(),
            "application/vnd.registry-notary.claim-result+json".to_string(),
        ),
    ];
    if let Some(api_key) = api_key {
        headers.push(("x-api-key".to_string(), api_key.to_string()));
    }
    let body = serde_json::json!({
        "target": {
            "type": "Project",
            "identifiers": [{"scheme": "project_id", "value": expected.project_id}],
        },
        "claims": [expected.claim_id],
        "format": "application/vnd.registry-notary.claim-result+json",
        "purpose": "public-works-case-management",
    })
    .to_string();
    match http_request("POST", &format!("{base_url}{PATH}"), &headers, &body) {
        Ok(response) => {
            let passed = response.status == expected.status
                && expected.value.is_none_or(|expected_value| {
                    validate_notary_smoke_response(
                        &response.body,
                        expected.claim_id,
                        expected_value,
                    )
                    .is_ok()
                });
            checks.push(SmokeCheck {
                name: name.to_string(),
                method: "POST".to_string(),
                path: PATH.to_string(),
                expected_status: expected.status,
                actual_status: Some(response.status),
                passed,
                error: (!passed).then(|| {
                    "Notary response did not match the expected bounded shape".to_string()
                }),
            });
        }
        Err(error) => checks.push(SmokeCheck {
            name: name.to_string(),
            method: "POST".to_string(),
            path: PATH.to_string(),
            expected_status: expected.status,
            actual_status: None,
            passed: false,
            error: Some(redact_error(&error.to_string())),
        }),
    }
}

fn validate_notary_smoke_response(
    contents: &str,
    claim_id: &str,
    expected_value: bool,
) -> Result<()> {
    let document: serde_json::Value =
        serde_json::from_str(contents).context("Notary response was not valid JSON")?;
    let results = document["results"]
        .as_array()
        .ok_or_else(|| anyhow!("Notary response results were absent"))?;
    if results.len() != 1 {
        bail!("Notary response did not contain the exact claim set");
    }
    let result = &results[0];
    if result["claim_id"].as_str() != Some(claim_id)
        || result["value"].as_bool() != Some(expected_value)
        || result["satisfied"].as_bool() != Some(expected_value)
        || result["disclosure"].as_str() != Some("predicate")
    {
        bail!("Notary response claim values did not match the expected bounded outcome");
    }
    Ok(())
}

#[allow(dead_code)]
fn run_smoke_checks(base_url: &str, secrets: &LocalEnv) -> SmokeReport {
    let mut checks = Vec::new();

    record_smoke_check(
        &mut checks,
        base_url,
        "healthz is public",
        "/healthz",
        200,
        &[],
    );
    record_smoke_check(&mut checks, base_url, "ready is public", "/ready", 200, &[]);
    record_smoke_check(
        &mut checks,
        base_url,
        "anonymous dataset request is denied",
        "/v1/datasets",
        401,
        &[],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "metadata key can list datasets",
        "/v1/datasets",
        200,
        &[bearer_header(secrets.value("METADATA_READER_RAW"))],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "metadata key cannot read rows",
        "/v1/datasets/benefits_casework/entities/person/records?household_id=hh-1001",
        403,
        &[
            bearer_header(secrets.value("METADATA_READER_RAW")),
            (
                "Data-Purpose".to_string(),
                "https://example.local/purpose/tutorial".to_string(),
            ),
        ],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "row read without Data-Purpose returns 400",
        "/v1/datasets/benefits_casework/entities/person/records?household_id=hh-1001",
        400,
        &[bearer_header(secrets.value("ROW_READER_RAW"))],
    );
    record_row_data_smoke_check(
        &mut checks,
        base_url,
        "row reader can read filtered records",
        "/v1/datasets/benefits_casework/entities/person/records?household_id=hh-1001",
        &[
            bearer_header(secrets.value("ROW_READER_RAW")),
            (
                "Data-Purpose".to_string(),
                "https://example.local/purpose/tutorial".to_string(),
            ),
        ],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "row reader cannot read restricted identity fields",
        "/v1/datasets/benefits_casework/entities/person_identity/records?id=per-2001",
        403,
        &[
            bearer_header(secrets.value("ROW_READER_RAW")),
            (
                "Data-Purpose".to_string(),
                TUTORIAL_IDENTITY_PURPOSE.to_string(),
            ),
        ],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "identity reader with unpermitted Data-Purpose returns 403",
        "/v1/datasets/benefits_casework/entities/person_identity/records?id=per-2001",
        403,
        &[
            bearer_header(secrets.value("IDENTITY_READER_RAW")),
            ("Data-Purpose".to_string(), TUTORIAL_PURPOSE.to_string()),
        ],
    );
    record_row_data_smoke_check(
        &mut checks,
        base_url,
        "identity reader can read one restricted identity record",
        "/v1/datasets/benefits_casework/entities/person_identity/records?id=per-2001",
        &[
            bearer_header(secrets.value("IDENTITY_READER_RAW")),
            (
                "Data-Purpose".to_string(),
                TUTORIAL_IDENTITY_PURPOSE.to_string(),
            ),
        ],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "anonymous caller can fetch runtime OpenAPI",
        "/openapi.json",
        200,
        &[],
    );

    SmokeReport {
        schema_version: SmokeReportSchema::V1,
        base_url: base_url.to_string(),
        passed: checks.iter().all(|check| check.passed),
        checks,
    }
}

fn record_row_count_smoke_check(
    checks: &mut Vec<SmokeCheck>,
    base_url: &str,
    name: &'static str,
    path: &'static str,
    headers: &[(String, String)],
    expected_rows: usize,
) {
    let url = format!("{base_url}{path}");
    match http_get(&url, headers) {
        Ok(response) => {
            let passed = response.status == 200
                && validate_exact_row_count_response(&response.body, expected_rows).is_ok();
            checks.push(SmokeCheck {
                name: name.to_string(),
                method: "GET".to_string(),
                path: path.to_string(),
                expected_status: 200,
                actual_status: Some(response.status),
                passed,
                error: (!passed).then(|| {
                    "record response did not match the expected exact row shape".to_string()
                }),
            });
        }
        Err(error) => checks.push(SmokeCheck {
            name: name.to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            expected_status: 200,
            actual_status: None,
            passed: false,
            error: Some(redact_error(&error.to_string())),
        }),
    }
}

fn validate_exact_row_count_response(contents: &str, expected_rows: usize) -> Result<()> {
    let document: serde_json::Value =
        serde_json::from_str(contents).context("record response was not valid JSON")?;
    let object = document
        .as_object()
        .ok_or_else(|| anyhow!("record response was not a JSON object"))?;
    let rows = object
        .get("data")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow!("record response data was not an array"))?;
    if rows.iter().any(|row| !row.is_object()) {
        bail!("record response data contained a non-object row");
    }
    if rows.len() != expected_rows {
        bail!("record response did not contain the expected exact row count");
    }
    Ok(())
}

fn parse_smoke_report(contents: &str) -> Result<SmokeReport> {
    serde_json::from_str(contents).context("failed to parse smoke result JSON")
}

fn record_smoke_check(
    checks: &mut Vec<SmokeCheck>,
    base_url: &str,
    name: &'static str,
    path: &'static str,
    expected_status: u16,
    headers: &[(String, String)],
) {
    let url = format!("{base_url}{path}");
    match http_get(&url, headers) {
        Ok(response) => checks.push(SmokeCheck {
            name: name.to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            expected_status,
            actual_status: Some(response.status),
            passed: response.status == expected_status,
            error: None,
        }),
        Err(err) => checks.push(SmokeCheck {
            name: name.to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            expected_status,
            actual_status: None,
            passed: false,
            error: Some(redact_error(&err.to_string())),
        }),
    }
}

#[allow(dead_code)]
fn record_row_data_smoke_check(
    checks: &mut Vec<SmokeCheck>,
    base_url: &str,
    name: &'static str,
    path: &'static str,
    headers: &[(String, String)],
) {
    let url = format!("{base_url}{path}");
    match http_get(&url, headers) {
        Ok(response) => {
            let has_rows = response.status == 200
                && serde_json::from_str::<serde_json::Value>(&response.body)
                    .ok()
                    .and_then(|value| value["data"].as_array().map(|data| !data.is_empty()))
                    .unwrap_or(false);
            checks.push(SmokeCheck {
                name: name.to_string(),
                method: "GET".to_string(),
                path: path.to_string(),
                expected_status: 200,
                actual_status: Some(response.status),
                passed: has_rows,
                error: (!has_rows)
                    .then(|| "row response did not include any sample records".to_string()),
            });
        }
        Err(err) => checks.push(SmokeCheck {
            name: name.to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            expected_status: 200,
            actual_status: None,
            passed: false,
            error: Some(redact_error(&err.to_string())),
        }),
    }
}

fn bearer_header(raw_key: &str) -> (String, String) {
    ("Authorization".to_string(), format!("Bearer {raw_key}"))
}

fn redact_error(error: &str) -> String {
    if error.len() > 240 {
        format!("{}...", &error[..240])
    } else {
        error.to_string()
    }
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    body: String,
}

fn http_get(url: &str, headers: &[(String, String)]) -> Result<HttpResponse> {
    http_request("GET", url, headers, "")
}

fn http_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &str,
) -> Result<HttpResponse> {
    let parsed = ParsedHttpUrl::parse(url)?;
    let addr = (parsed.host.as_str(), parsed.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("could not resolve {}", parsed.host))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .with_context(|| format!("failed to connect to {}", parsed.authority()))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    write!(
        stream,
        "{method} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        parsed.path, parsed.host
    )?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    if !body.is_empty() {
        write!(stream, "Content-Length: {}\r\n", body.len())?;
    }
    write!(stream, "\r\n")?;
    if !body.is_empty() {
        write!(stream, "{body}")?;
    }

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("invalid HTTP response from {}", parsed.authority()))?;
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    Ok(HttpResponse { status, body })
}

#[derive(Debug)]
struct ParsedHttpUrl {
    host: String,
    port: u16,
    path: String,
}

impl ParsedHttpUrl {
    fn parse(url: &str) -> Result<Self> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| anyhow!("only http:// local URLs are supported"))?;
        let (authority, path) = rest
            .split_once('/')
            .map(|(authority, path)| (authority, format!("/{path}")))
            .unwrap_or_else(|| (rest, "/".to_string()));
        let (host, port) = if let Some((host, port)) = authority.rsplit_once(':') {
            let parsed_port = port
                .parse::<u16>()
                .with_context(|| format!("invalid URL port in {url}"))?;
            (host.to_string(), parsed_port)
        } else {
            (authority.to_string(), 80)
        };
        Ok(Self { host, port, path })
    }

    fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use registry_config_report::REGISTRYCTL_VALIDATION_REPORT_SCHEMA_V1;
    use serde_json::Value as JsonValue;
    use serde_norway::Value;
    use tempfile::TempDir;

    use super::*;

    const TEST_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;
    const TEST_RELAY_IMAGE: &str = "ghcr.io/registrystack/registry-relay@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TEST_NOTARY_IMAGE: &str = "ghcr.io/registrystack/registry-notary@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const TEST_POSTGRESQL_IMAGE: &str = "docker.io/library/postgres@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn test_image_lock() -> RegistryctlImageLock {
        RegistryctlImageLock {
            schema_version: IMAGE_LOCK_SCHEMA_VERSION.to_string(),
            release_tag: format!("v{}", env!("CARGO_PKG_VERSION")),
            manifest_source_ref: "a".repeat(40),
            tag_target: "b".repeat(40),
            platform: LINUX_AMD64_PLATFORM.to_string(),
            images: RegistryctlLockedImages {
                registry_relay: TEST_RELAY_IMAGE.to_string(),
                registry_notary: TEST_NOTARY_IMAGE.to_string(),
                postgresql: TEST_POSTGRESQL_IMAGE.to_string(),
            },
        }
    }

    fn test_image_lock_json() -> serde_json::Value {
        serde_json::json!({
            "schema_version": IMAGE_LOCK_SCHEMA_VERSION,
            "release_tag": format!("v{}", env!("CARGO_PKG_VERSION")),
            "manifest_source_ref": "a".repeat(40),
            "tag_target": "b".repeat(40),
            "platform": LINUX_AMD64_PLATFORM,
            "images": {
                "registry-relay": TEST_RELAY_IMAGE,
                "registry-notary": TEST_NOTARY_IMAGE,
                "postgresql": TEST_POSTGRESQL_IMAGE,
            }
        })
    }

    fn write_test_image_lock(temp: &TempDir, value: &serde_json::Value) -> PathBuf {
        let executable = temp.path().join("registryctl");
        fs::write(&executable, b"test binary").unwrap();
        fs::write(
            temp.path().join(registryctl_image_lock_filename()),
            serde_json::to_vec(value).unwrap(),
        )
        .unwrap();
        executable
    }

    #[test]
    fn image_lock_loads_strict_versioned_file_beside_executable() {
        let temp = TempDir::new().unwrap();
        let executable = write_test_image_lock(&temp, &test_image_lock_json());

        let image_lock = load_registryctl_image_lock_beside(&executable).unwrap();

        assert_eq!(image_lock, test_image_lock());
    }

    #[test]
    fn image_lock_rejects_unknown_root_and_image_fields() {
        for (field_path, value) in [
            ("root", serde_json::json!(true)),
            ("images", serde_json::json!(true)),
        ] {
            let temp = TempDir::new().unwrap();
            let mut document = test_image_lock_json();
            if field_path == "root" {
                document["unexpected"] = value;
            } else {
                document["images"]["unexpected"] = value;
            }
            let executable = write_test_image_lock(&temp, &document);

            let error = load_registryctl_image_lock_beside(&executable).unwrap_err();

            assert!(
                format!("{error:#}").contains("unknown field"),
                "unexpected error: {error:#}"
            );
        }
    }

    #[test]
    fn image_lock_rejects_release_identity_and_platform_mismatches() {
        for (field, invalid, expected) in [
            ("release_tag", serde_json::json!("v9.9.9"), "release_tag"),
            (
                "manifest_source_ref",
                serde_json::json!("A".repeat(40)),
                "manifest_source_ref",
            ),
            (
                "tag_target",
                serde_json::json!("b".repeat(39)),
                "tag_target",
            ),
            ("platform", serde_json::json!("linux/arm64"), "platform"),
        ] {
            let temp = TempDir::new().unwrap();
            let mut document = test_image_lock_json();
            document[field] = invalid;
            let executable = write_test_image_lock(&temp, &document);

            let error = load_registryctl_image_lock_beside(&executable).unwrap_err();

            assert!(
                format!("{error:#}").contains(expected),
                "unexpected error: {error:#}"
            );
        }
    }

    #[test]
    fn image_lock_rejects_mutable_or_noncanonical_image_references() {
        for (field, invalid) in [
            (
                "registry-relay",
                "ghcr.io/registrystack/registry-relay:v0.8.4".to_string(),
            ),
            (
                "registry-notary",
                format!("ghcr.io/example/registry-notary@sha256:{}", "b".repeat(64)),
            ),
            (
                "postgresql",
                format!("docker.io/example/postgres@sha256:{}", "c".repeat(64)),
            ),
            (
                "registry-relay",
                format!(
                    "ghcr.io/registrystack/registry-relay@sha256:{}",
                    "A".repeat(64)
                ),
            ),
        ] {
            let temp = TempDir::new().unwrap();
            let mut document = test_image_lock_json();
            document["images"][field] = serde_json::json!(invalid);
            let executable = write_test_image_lock(&temp, &document);

            let error = load_registryctl_image_lock_beside(&executable).unwrap_err();

            assert!(
                format!("{error:#}").contains(&format!("images.{field}")),
                "unexpected error: {error:#}"
            );
        }
    }

    #[test]
    fn canonical_staging_image_allows_only_the_candidate_repository_at_locked_digest() {
        let image_lock = test_image_lock();
        let candidate = format!(
            "ghcr.io/registrystack/registry-relay-candidate@sha256:{}",
            "a".repeat(64)
        );
        assert_eq!(
            select_canonical_relay_image(&image_lock, Some(OsStr::new(&candidate))).unwrap(),
            candidate
        );
        for invalid in [
            format!(
                "ghcr.io/registrystack/registry-relay-candidate@sha256:{}",
                "b".repeat(64)
            ),
            "ghcr.io/registrystack/registry-relay-candidate:v0.13.0".to_string(),
            format!(
                "ghcr.io/example/registry-relay-candidate@sha256:{}",
                "a".repeat(64)
            ),
            TEST_RELAY_IMAGE.to_string(),
        ] {
            let error =
                select_canonical_relay_image(&image_lock, Some(OsStr::new(&invalid))).unwrap_err();
            assert!(
                format!("{error:#}").contains("staging"),
                "unexpected error for {invalid}: {error:#}"
            );
        }
        assert_eq!(
            select_canonical_relay_image(&image_lock, None).unwrap(),
            TEST_RELAY_IMAGE
        );
    }

    #[test]
    fn canonical_notary_staging_image_allows_only_the_candidate_repository_at_locked_digest() {
        let image_lock = test_image_lock();
        let candidate = format!(
            "ghcr.io/registrystack/registry-notary-candidate@sha256:{}",
            "b".repeat(64)
        );
        assert_eq!(
            select_canonical_notary_image(&image_lock, Some(OsStr::new(&candidate))).unwrap(),
            candidate
        );
        for invalid in [
            format!(
                "ghcr.io/registrystack/registry-notary-candidate@sha256:{}",
                "a".repeat(64)
            ),
            "ghcr.io/registrystack/registry-notary-candidate:v0.13.0".to_string(),
            format!(
                "ghcr.io/example/registry-notary-candidate@sha256:{}",
                "b".repeat(64)
            ),
            TEST_NOTARY_IMAGE.to_string(),
        ] {
            let error =
                select_canonical_notary_image(&image_lock, Some(OsStr::new(&invalid))).unwrap_err();
            assert!(
                format!("{error:#}").contains("staging"),
                "unexpected error for {invalid}: {error:#}"
            );
        }
        assert_eq!(
            select_canonical_notary_image(&image_lock, None).unwrap(),
            TEST_NOTARY_IMAGE
        );
    }

    #[test]
    fn image_lock_rejects_missing_nonregular_and_oversized_files() {
        let missing = TempDir::new().unwrap();
        let missing_executable = missing.path().join("registryctl");
        fs::write(&missing_executable, b"test binary").unwrap();
        let error = load_registryctl_image_lock_beside(&missing_executable).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("image lock is missing"));
        assert!(message.contains(IMAGE_LOCK_PATH_ENV));

        let directory = TempDir::new().unwrap();
        let executable = directory.path().join("registryctl");
        fs::write(&executable, b"test binary").unwrap();
        fs::create_dir(directory.path().join(registryctl_image_lock_filename())).unwrap();
        let error = load_registryctl_image_lock_beside(&executable).unwrap_err();
        assert!(format!("{error:#}").contains("must be a regular file"));

        let oversized = TempDir::new().unwrap();
        let executable = oversized.path().join("registryctl");
        fs::write(&executable, b"test binary").unwrap();
        fs::write(
            oversized.path().join(registryctl_image_lock_filename()),
            vec![b' '; IMAGE_LOCK_MAX_BYTES as usize + 1],
        )
        .unwrap();
        let error = load_registryctl_image_lock_beside(&executable).unwrap_err();
        assert!(format!("{error:#}").contains("exceeds the 16384-byte limit"));
    }

    #[cfg(unix)]
    #[test]
    fn image_lock_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let executable = temp.path().join("registryctl");
        let target = temp.path().join("lock-target.json");
        fs::write(&executable, b"test binary").unwrap();
        fs::write(
            &target,
            serde_json::to_vec(&test_image_lock_json()).unwrap(),
        )
        .unwrap();
        symlink(&target, temp.path().join(registryctl_image_lock_filename())).unwrap();

        let error = load_registryctl_image_lock_beside(&executable).unwrap_err();

        assert!(format!("{error:#}").contains("must be a regular file"));
    }

    #[test]
    fn config_bundle_sign_anchor_and_verify_round_trip() {
        let temp = TempDir::new().unwrap();
        let input_dir = temp.path().join("input");
        let bundle_dir = temp.path().join("bundle");
        fs::create_dir_all(input_dir.join("config")).unwrap();
        let config_bytes = b"server:\n  bind: 127.0.0.1:8080\n";
        fs::write(input_dir.join("config/notary.yaml"), config_bytes).unwrap();
        let config_hash = registry_platform_config::sha256_uri(config_bytes);
        let private_path = temp.path().join("private.jwk");
        fs::write(&private_path, TEST_PRIVATE_JWK).unwrap();
        let private = PrivateJwk::parse(TEST_PRIVATE_JWK).unwrap();
        let public = private.public();
        let public_path = temp.path().join("public.jwk");
        fs::write(&public_path, serde_json::to_vec_pretty(&public).unwrap()).unwrap();
        let anchor_path = temp.path().join("trust_anchor.json");

        let init = init_config_anchor(
            &anchor_path,
            "registry-notary".to_string(),
            "production".to_string(),
            "civil-registry".to_string(),
            "notary-011".to_string(),
        )
        .unwrap();
        assert_eq!(init.signer_count, 0);

        let sign = sign_config_bundle(BundleSignOptions {
            input: input_dir,
            key: private_path.display().to_string(),
            product: "registry-notary".to_string(),
            environment: "production".to_string(),
            stream_id: "civil-registry".to_string(),
            instance_id: None,
            sequence: 1,
            bundle_id: "rollout-1".to_string(),
            out: bundle_dir.clone(),
        })
        .unwrap();
        assert_eq!(sign.alg, "EdDSA");
        assert_eq!(sign.signature_count, 1);
        assert_eq!(sign.config_path, "config/notary.yaml");

        let add = add_config_anchor_key(&anchor_path, &public_path, true).unwrap();
        assert_eq!(add.signer_count, 1);
        assert_eq!(add.enabled_signer_count, 1);

        let inspect = inspect_config_bundle(&bundle_dir).unwrap();
        assert_eq!(inspect.signature_count, 1);
        assert_eq!(inspect.manifest.bundle_id, "rollout-1");

        let verified = verify_config_bundle_cli(&bundle_dir, &anchor_path).unwrap();
        assert_eq!(verified.config_hash, config_hash);
        assert_eq!(verified.signer_kids, vec![public.jkt().unwrap()]);
        assert_eq!(verified.config_path, bundle_dir.join("config/notary.yaml"));
    }

    #[test]
    fn config_artifact_reader_rejects_duplicate_members_and_oversize_input() {
        let temp = TempDir::new().unwrap();
        let duplicate_path = temp.path().join("duplicate.json");
        fs::write(&duplicate_path, br#"{"id":1,"\u0069d":2}"#).unwrap();

        let error = read_bounded_strict_json::<Value>(&duplicate_path, 1024).unwrap_err();
        assert!(format!("{error:#}").contains("duplicate JSON object member"));

        let oversized_path = temp.path().join("oversized.json");
        fs::write(&oversized_path, br#"{"value":"too-large"}"#).unwrap();
        let error = read_bounded_strict_json::<Value>(&oversized_path, 4).unwrap_err();
        assert!(format!("{error:#}").contains("exceeds the 4-byte limit"));

        let oversized_jwk_path = temp.path().join("oversized.jwk");
        fs::write(&oversized_jwk_path, vec![b' '; MAX_JWK_JSON_BYTES + 1]).unwrap();
        let error = read_private_jwk_text(oversized_jwk_path.to_str().unwrap()).unwrap_err();
        assert!(
            format!("{error:#}").contains(&format!("exceeds the {MAX_JWK_JSON_BYTES}-byte limit"))
        );
        let error = read_bounded_utf8_file(&oversized_jwk_path, MAX_JWK_JSON_BYTES).unwrap_err();
        assert!(
            format!("{error:#}").contains(&format!("exceeds the {MAX_JWK_JSON_BYTES}-byte limit"))
        );
    }

    #[test]
    fn config_anchor_remove_key_updates_anchor_without_private_material() {
        let temp = TempDir::new().unwrap();
        let anchor_path = temp.path().join("trust_anchor.json");
        let private = PrivateJwk::parse(TEST_PRIVATE_JWK).unwrap();
        let public = private.public();
        let public_path = temp.path().join("public.jwk");
        fs::write(&public_path, serde_json::to_vec_pretty(&public).unwrap()).unwrap();
        init_config_anchor(
            &anchor_path,
            "registry-notary".to_string(),
            "production".to_string(),
            "civil-registry".to_string(),
            "notary-011".to_string(),
        )
        .unwrap();
        add_config_anchor_key(&anchor_path, &public_path, true).unwrap();

        let report = remove_config_anchor_key(&anchor_path, &public.jkt().unwrap()).unwrap();

        assert_eq!(report.signer_count, 0);
        let anchor = fs::read_to_string(anchor_path).unwrap();
        assert!(!anchor.contains(r#""d":"#));
        assert!(!anchor.contains(r#""d": "#));
    }

    #[cfg(unix)]
    #[test]
    fn config_anchor_writes_verifier_safe_permissions_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let anchor_path = temp.path().join("trust_anchor.json");
        let private = PrivateJwk::parse(TEST_PRIVATE_JWK).unwrap();
        let public = private.public();
        let public_path = temp.path().join("public.jwk");
        fs::write(&public_path, serde_json::to_vec_pretty(&public).unwrap()).unwrap();

        init_config_anchor(
            &anchor_path,
            "registry-notary".to_string(),
            "production".to_string(),
            "civil-registry".to_string(),
            "notary-011".to_string(),
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&anchor_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let mut permissions = fs::metadata(&anchor_path).unwrap().permissions();
        permissions.set_mode(0o664);
        fs::set_permissions(&anchor_path, permissions).unwrap();

        add_config_anchor_key(&anchor_path, &public_path, true).unwrap();
        assert_eq!(
            fs::metadata(&anchor_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let mut permissions = fs::metadata(&anchor_path).unwrap().permissions();
        permissions.set_mode(0o664);
        fs::set_permissions(&anchor_path, permissions).unwrap();

        remove_config_anchor_key(&anchor_path, &public.jkt().unwrap()).unwrap();
        assert_eq!(
            fs::metadata(&anchor_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    fn assert_digest_pinned_image(image: &str, repository: &str) {
        assert!(image.starts_with(&format!("{repository}@sha256:")));
        assert!(!image.contains(":snapshot"));
        assert!(!image.contains(":latest"));
    }

    fn assert_no_local_demo_external_auth_deps(label: &str, contents: &str) {
        let normalized = contents.to_ascii_lowercase();
        let boundary_normalized = normalized
            .chars()
            .map(|value| {
                if value.is_alphanumeric() || value == '-' || value == '_' || value == ' ' {
                    value
                } else {
                    ' '
                }
            })
            .collect::<String>();
        for forbidden in [
            "assisted access",
            "assisted-access",
            "assisted_access",
            "e-signet",
            "oidc",
            "oauth",
            "openid",
            "sts-url",
            "sts url",
            "security token service",
            "security-token-service",
            "security_token_service",
            "transaction-token",
            "transaction_token",
            "transaction token",
        ] {
            assert!(
                !boundary_normalized.contains(forbidden),
                "{label} should not reference external auth dependency {forbidden:?}"
            );
        }

        for word in boundary_normalized.split_whitespace() {
            assert!(
                word != "esign" && word != "sts",
                "{label} should not reference external auth dependency {word:?}"
            );
        }
    }

    #[test]
    fn registryctl_manifest_has_no_external_auth_dependencies() {
        let manifest =
            fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
        assert_no_local_demo_external_auth_deps("registryctl Cargo.toml", &manifest);
        for forbidden_dependency in [
            "registry-platform-sts",
            "registry-assisted-access",
            "registry-platform-oidc",
        ] {
            assert!(
                !manifest.contains(forbidden_dependency),
                "registryctl must not depend on {forbidden_dependency}"
            );
        }
    }

    #[test]
    fn update_check_detects_newer_canonical_release_tags() {
        assert!(update_notice("0.1.0", "v0.1.1").is_some());
        assert!(update_notice("0.1.9", "v0.10.0").is_some());
        assert!(update_notice("0.1.0", "v0.1.0").is_none());
        assert!(update_notice("0.2.0", "v0.1.9").is_none());
        assert!(update_notice("not-a-version", "v0.2.0").is_none());
    }

    #[test]
    fn update_check_selects_the_highest_published_release_including_prereleases() {
        let releases = vec![
            GitHubRelease {
                tag_name: "v0.13.0".to_string(),
                draft: false,
                prerelease: true,
            },
            GitHubRelease {
                tag_name: "v0.14.0".to_string(),
                draft: true,
                prerelease: false,
            },
            GitHubRelease {
                tag_name: "not-a-release".to_string(),
                draft: false,
                prerelease: false,
            },
            GitHubRelease {
                tag_name: "v0.12.0".to_string(),
                draft: false,
                prerelease: false,
            },
        ];

        assert_eq!(
            select_latest_published_release(&releases).as_deref(),
            Some("v0.13.0")
        );
    }

    #[test]
    fn update_notice_uses_explicit_tag_ref_and_env_on_bash() {
        let notice = update_notice("0.1.0", "v0.2.0").unwrap();

        assert!(notice.contains("registryctl v0.2.0 is available"));
        assert!(notice.contains("You have v0.1.0"));
        assert_eq!(
            notice.lines().last(),
            Some(
                "  curl -fsSL https://github.com/registrystack/registry-stack/releases/download/v0.2.0/registryctl-v0.2.0-install.sh | REGISTRYCTL_VERSION=v0.2.0 bash"
            )
        );
        assert!(!notice.contains("raw.githubusercontent.com"));
        assert!(!notice.contains("/releases/latest/"));
        assert!(!notice.contains("REGISTRYCTL_VERSION=v0.2.0 curl"));
    }

    #[test]
    fn update_notice_states_installer_and_payload_trust_before_command() {
        let notice = update_notice("0.1.0", "v0.2.0").unwrap();
        let warning = notice.find("trusts GitHub and TLS").unwrap();
        let command = notice.find("Upgrade with:").unwrap();

        assert!(warning < command);
        assert!(notice.contains(
            "https://github.com/registrystack/registry-stack/blob/v0.2.0/release/VERIFY.md"
        ));
        assert!(notice.contains("signature and provenance verification"));
    }

    #[test]
    fn update_notice_rejects_shell_active_and_noncanonical_tags() {
        let hostile = "v999.0.0-$(touch${IFS}/tmp/registryctl-owned)";
        let temp = TempDir::new().unwrap();
        let cache_path = temp.path().join("registryctl/update-check.json");

        assert!(update_notice("0.1.0", hostile).is_none());
        assert!(VersionNumber::parse_release_tag(hostile).is_none());
        assert!(VersionNumber::parse_release_tag("999.0.0").is_none());
        assert!(VersionNumber::parse_release_tag("v01.0.0").is_none());
        assert!(write_update_check_cache(&cache_path, hostile).is_err());
        assert!(!cache_path.exists());

        fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
        let poisoned = UpdateCheckCache {
            checked_at: 1,
            latest_tag: hostile.to_string(),
        };
        fs::write(&cache_path, serde_json::to_string(&poisoned).unwrap()).unwrap();
        assert!(read_update_check_cache(&cache_path).is_err());
    }

    #[test]
    fn update_check_cache_round_trips_latest_tag() {
        let temp = TempDir::new().unwrap();
        let cache_path = temp.path().join("registryctl/update-check.json");

        write_update_check_cache(&cache_path, "v0.2.0").unwrap();

        let read = read_update_check_cache(&cache_path).unwrap().unwrap();
        assert_eq!(read.latest_tag, "v0.2.0");
        assert!(read.is_fresh);
    }

    #[test]
    fn update_check_reads_stale_cache_for_nonblocking_notice() {
        let temp = TempDir::new().unwrap();
        let cache_path = temp.path().join("registryctl/update-check.json");
        let cache = UpdateCheckCache {
            checked_at: 1,
            latest_tag: "v0.2.0".to_string(),
        };
        fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
        fs::write(&cache_path, serde_json::to_string(&cache).unwrap()).unwrap();

        let read = read_update_check_cache(&cache_path).unwrap().unwrap();

        assert_eq!(read.latest_tag, "v0.2.0");
        assert!(!read.is_fresh);
    }

    #[test]
    fn init_sample_creates_expected_project_tree() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");

        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();

        for path in [
            "registryctl.yaml",
            "compose.yaml",
            ".env",
            "README.md",
            ".gitignore",
            "relay/config.yaml",
            "data/benefits_casework.xlsx",
            "secrets/local.env",
            "output/.gitkeep",
            "state/relay/cache",
            "state/relay/config-state",
            "state/relay/audit",
            "bruno/registry-api/bruno.json",
            "bruno/registry-api/collection.bru",
            "bruno/registry-api/environments/local.bru",
            "bruno/registry-api/environments/local.example.bru",
            "bruno/registry-api/Relay/Health.bru",
        ] {
            assert!(project.join(path).exists(), "{path} should exist");
        }
        assert_private_state_dirs(
            &project,
            &[
                "state",
                "state/relay",
                "state/relay/cache",
                "state/relay/config-state",
                "state/relay/audit",
            ],
        );
        assert_private_state_dir(&project, "secrets");
        assert_private_file(&project, "secrets/local.env");
        assert_private_file(&project, "bruno/registry-api/environments/local.bru");
        assert_runtime_env_matches_project_owner(&project);
        assert!(!project.join("relay/metadata.yaml").exists());

        let config_text = fs::read_to_string(project.join("relay/config.yaml")).unwrap();
        assert!(config_text.contains("# This file is the Relay contract"));
        assert!(config_text.contains("# The raw bearer keys live in secrets/local.env."));
        assert!(config_text.contains("# Tables describe the source workbook."));
        assert!(config_text.contains("# Aggregates expose predeclared grouped statistics."));
        assert!(config_text.contains("# Entities are API projections."));
        let config: Value = serde_norway::from_str(&config_text).unwrap();
        let manifest: Value =
            serde_norway::from_str(&fs::read_to_string(project.join("registryctl.yaml")).unwrap())
                .unwrap();
        let compose = fs::read_to_string(project.join("compose.yaml")).unwrap();
        assert!(config.get("metadata").is_none());
        assert_eq!(config["deployment"]["profile"], "local");
        assert!(manifest["relay"].get("metadata").is_none());
        assert!(!compose.contains("metadata.yaml"));
        assert!(compose.contains(
            "user: \"${REGISTRY_STACK_RUNTIME_UID:-65532}:${REGISTRY_STACK_RUNTIME_GID:-65532}\""
        ));
        assert!(compose.contains("./relay:/etc/registry-relay:ro"));
        assert!(compose.contains("./state/relay/cache:/var/lib/registry-relay/cache"));
        assert!(compose.contains("./state/relay/config-state:/var/lib/registry-relay/config-state"));
        assert!(compose.contains("./state/relay/audit:/var/log/registry-relay"));
        assert_eq!(
            config["datasets"][0]["aggregates"][0]["access"]["aggregate_only_execution"],
            true
        );
        assert_eq!(
            config["datasets"][0]["aggregates"][0]["disclosure_control"]["min_group_size"],
            2
        );
        assert_eq!(
            config["datasets"][0]["aggregates"][1]["access"]["aggregate_only_execution"],
            true
        );
        assert_eq!(
            config["datasets"][0]["aggregates"][1]["disclosure_control"]["min_group_size"],
            2
        );

        let entities = config["datasets"][0]["entities"].as_sequence().unwrap();
        let entity = |name: &str| {
            entities
                .iter()
                .find(|entity| entity["name"] == name)
                .unwrap()
        };
        let person = entity("person");
        let person_fields = person["fields"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|field| field["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            person_fields,
            [
                "id",
                "household_id",
                "date_of_birth",
                "relationship_to_head",
                "registration_status"
            ]
        );
        assert_eq!(
            person["api"]["governed_policy"]["permitted_purposes"][0],
            TUTORIAL_PURPOSE
        );

        let person_identity = entity("person_identity");
        assert_eq!(
            person_identity["access"]["read_scope"],
            "benefits_casework:identity_release"
        );
        assert_eq!(person_identity["api"]["max_limit"], 1);
        assert_eq!(
            person_identity["api"]["governed_policy"]["permitted_purposes"][0],
            TUTORIAL_IDENTITY_PURPOSE
        );
        assert_eq!(
            entity("household_contact")["access"]["read_scope"],
            "benefits_casework:identity_release"
        );

        let readme = fs::read_to_string(project.join("README.md")).unwrap();
        assert!(readme.contains("registryctl doctor --profile local"));
        assert!(readme.contains("no host Relay binary is needed"));
        assert!(readme.contains("raw API keys and an audit hash secret"));
        assert!(readme.contains("redacts local secret"));
        assert!(readme.contains("Back up that file before upgrades"));
        assert!(readme.contains("Notary evaluation state is in memory"));
        assert!(readme.contains("may contain cached source rows"));
        assert!(!readme.contains("preserve its configured PostgreSQL database"));
        assert!(readme.contains("https://docs.registrystack.org/operate/backup-and-restore/"));
        assert!(readme
            .contains("https://docs.registrystack.org/operate/single-node-compose-behind-proxy/"));
    }

    #[test]
    fn generated_compose_ports_are_exact_ipv4_loopback_bindings() {
        let relay = compose_yaml(&test_image_lock()).unwrap();
        validate_generated_compose_ports(&relay).unwrap();
        let relay_document: Value = serde_norway::from_str(&relay).unwrap();
        assert_eq!(
            relay_document["services"]["registry-relay"]["ports"][0],
            "127.0.0.1:4242:8080"
        );
    }

    #[test]
    fn generated_compose_port_validation_rejects_planted_wide_bindings() {
        let relay = compose_yaml(&test_image_lock()).unwrap();
        let widened_relay = relay.replace("127.0.0.1:4242:8080", "0.0.0.0:4242:8080");
        assert!(validate_generated_compose_ports(&widened_relay).is_err());
    }

    #[test]
    fn bruno_files_for_relay_project_are_generated_and_secret_scoped() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();

        let env = fs::read_to_string(project.join("secrets/local.env")).unwrap();
        let local_bru =
            fs::read_to_string(project.join("bruno/registry-api/environments/local.bru")).unwrap();
        let example_bru =
            fs::read_to_string(project.join("bruno/registry-api/environments/local.example.bru"))
                .unwrap();
        let request =
            fs::read_to_string(project.join("bruno/registry-api/Relay/Read sample people.bru"))
                .unwrap();
        let aggregate_request = fs::read_to_string(
            project.join("bruno/registry-api/Relay/Run households by district aggregate.bru"),
        )
        .unwrap();
        let application_aggregate_request = fs::read_to_string(
            project.join("bruno/registry-api/Relay/Query applications aggregate.bru"),
        )
        .unwrap();
        let identity_request = fs::read_to_string(
            project.join("bruno/registry-api/Relay/Read restricted identity.bru"),
        )
        .unwrap();
        let openapi_request =
            fs::read_to_string(project.join("bruno/registry-api/Relay/OpenAPI.bru")).unwrap();

        assert!(local_bru.contains(&env_value(&env, "METADATA_READER_RAW")));
        assert!(local_bru.contains(&env_value(&env, "ROW_READER_RAW")));
        assert!(local_bru.contains(&env_value(&env, "AGGREGATE_READER_RAW")));
        assert!(local_bru.contains(&env_value(&env, "IDENTITY_READER_RAW")));
        assert!(example_bru.contains("replace-with-metadata_reader_raw"));
        assert!(example_bru.contains("replace-with-aggregate_reader_raw"));
        assert!(example_bru.contains("replace-with-identity_reader_raw"));
        assert!(!request.contains(&env_value(&env, "METADATA_READER_RAW")));
        assert!(!request.contains(&env_value(&env, "ROW_READER_RAW")));
        assert!(!aggregate_request.contains(&env_value(&env, "AGGREGATE_READER_RAW")));
        assert!(request.contains("{{relay_row_key}}"));
        assert!(aggregate_request.contains("{{relay_aggregate_key}}"));
        assert!(aggregate_request.contains("Data-Purpose"));
        assert!(application_aggregate_request.contains("Data-Purpose"));
        assert!(identity_request.contains("{{relay_identity_key}}"));
        assert!(identity_request.contains("{{identity_purpose}}"));
        assert!(!openapi_request.contains("Authorization"));
        assert!(!openapi_request.contains("{{relay_metadata_key}}"));
    }

    #[test]
    fn bruno_generate_is_idempotent_for_generated_files() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();

        let before =
            fs::read_to_string(project.join("bruno/registry-api/Relay/Health.bru")).unwrap();
        bruno_generate_project(&project, false).unwrap();
        let after =
            fs::read_to_string(project.join("bruno/registry-api/Relay/Health.bru")).unwrap();

        assert_eq!(before, after);
    }

    #[test]
    fn manifest_pins_image_and_records_base_url() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();

        let manifest: Value =
            serde_norway::from_str(&fs::read_to_string(project.join("registryctl.yaml")).unwrap())
                .unwrap();
        let compose = fs::read_to_string(project.join("compose.yaml")).unwrap();

        assert_digest_pinned_image(
            manifest["runtime"]["relay_image"].as_str().unwrap(),
            "ghcr.io/registrystack/registry-relay",
        );
        assert_eq!(manifest["runtime"]["relay_base_url"], RELAY_BASE_URL);
        assert!(manifest["relay"].get("metadata").is_none());
        assert!(compose.contains(&format!("image: {TEST_RELAY_IMAGE}")));
        assert!(!compose.contains("metadata.yaml"));
        assert!(!compose.contains("registry-relay:snapshot"));
        assert!(!compose.contains("registry-relay:latest"));
    }

    #[test]
    fn compose_platform_override_targets_amd64_for_arm64_relay_project() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();
        let project = Project::load(&project_dir).unwrap();

        assert_eq!(
            compose_platform_override(&project, None, Some("linux/arm64")),
            Some(LINUX_AMD64_PLATFORM)
        );
        assert_eq!(
            compose_platform_override(&project, None, Some("linux/arm64/v8")),
            Some(LINUX_AMD64_PLATFORM)
        );
        assert_eq!(
            compose_platform_override(&project, None, Some("linux/amd64")),
            None
        );
    }

    #[test]
    fn compose_platform_override_respects_operator_platform() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();
        let project = Project::load(&project_dir).unwrap();

        assert_eq!(
            compose_platform_override(&project, Some("linux/arm64"), Some("linux/arm64")),
            None
        );
    }

    #[test]
    fn relay_only_manifest_loads_without_notary_section() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();

        Project::load(&project).unwrap();

        let manifest: Value =
            serde_norway::from_str(&fs::read_to_string(project.join("registryctl.yaml")).unwrap())
                .unwrap();
        let products = manifest["project"]["products"]
            .as_sequence()
            .expect("project products should be a list");
        assert!(products
            .iter()
            .any(|product| product.as_str() == Some("registry-relay")));
    }

    fn write_project_yaml(dir: &Path, yaml: &str) {
        fs::write(dir.join("registryctl.yaml"), yaml).unwrap();
    }

    const MINIMAL_LOCAL_BLOCK: &str =
        "local:\n  secrets_env: secrets/local.env\n  output_dir: output\n";

    // `schema_version` and `project` are required fields with no `#[serde(default)]`, so any
    // fixture exercising `deny_unknown_fields` elsewhere in the document must still supply them
    // (and a complete `runtime` block) to keep the unknown-key/invalid-value error the only
    // possible parse failure.
    const MINIMAL_SCHEMA_AND_PROJECT_BLOCK: &str = "schema_version: registryctl/v1\nproject:\n  name: my-first-api\n  kind: spreadsheet-api\n  products:\n    - registry-relay\n";

    const MINIMAL_RUNTIME_BLOCK: &str =
        "runtime:\n  engine: docker_compose\n  compose_file: compose.yaml\n";

    #[test]
    fn unknown_top_level_key_fails_to_load_naming_the_key() {
        let temp = TempDir::new().unwrap();
        write_project_yaml(
            temp.path(),
            &format!(
                "{MINIMAL_SCHEMA_AND_PROJECT_BLOCK}unknown_product:\n  config: unknown/config.yaml\n{MINIMAL_RUNTIME_BLOCK}{MINIMAL_LOCAL_BLOCK}"
            ),
        );

        let error = Project::load(temp.path()).unwrap_err();

        assert!(
            format!("{error:#}").contains("unknown_product"),
            "error should name the offending key `unknown_product`: {error:#}"
        );
    }

    #[test]
    fn unknown_key_in_relay_section_fails_to_load() {
        let temp = TempDir::new().unwrap();
        write_project_yaml(
            temp.path(),
            &format!(
                "{MINIMAL_SCHEMA_AND_PROJECT_BLOCK}relay:\n  config: relay/config.yaml\n  bogus_relay_key: nope\n{MINIMAL_RUNTIME_BLOCK}{MINIMAL_LOCAL_BLOCK}"
            ),
        );

        let error = Project::load(temp.path()).unwrap_err();

        assert!(
            format!("{error:#}").contains("bogus_relay_key"),
            "error should name the offending key `bogus_relay_key`: {error:#}"
        );
    }

    #[test]
    fn unknown_key_in_runtime_section_fails_to_load() {
        let temp = TempDir::new().unwrap();
        write_project_yaml(
            temp.path(),
            &format!(
                "{MINIMAL_SCHEMA_AND_PROJECT_BLOCK}runtime:\n  engine: docker_compose\n  compose_file: compose.yaml\n  bogus_runtime_key: nope\n{MINIMAL_LOCAL_BLOCK}"
            ),
        );

        let error = Project::load(temp.path()).unwrap_err();

        assert!(
            format!("{error:#}").contains("bogus_runtime_key"),
            "error should name the offending key `bogus_runtime_key`: {error:#}"
        );
    }

    #[test]
    fn runtime_rejects_unimplemented_compose_providers() {
        let temp = TempDir::new().unwrap();
        write_project_yaml(
            temp.path(),
            &format!(
                "{MINIMAL_SCHEMA_AND_PROJECT_BLOCK}runtime:\n  engine: podman_compose\n  compose_file: compose.yaml\n{MINIMAL_LOCAL_BLOCK}"
            ),
        );

        let error = Project::load(temp.path()).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("podman_compose"), "{rendered}");
        assert!(rendered.contains("docker_compose"), "{rendered}");
    }

    #[test]
    fn runtime_rejects_arbitrary_compose_files() {
        let temp = TempDir::new().unwrap();
        write_project_yaml(
            temp.path(),
            &format!(
                "{MINIMAL_SCHEMA_AND_PROJECT_BLOCK}runtime:\n  engine: docker_compose\n  compose_file: ../alternate.yaml\n{MINIMAL_LOCAL_BLOCK}"
            ),
        );

        let error = Project::load(temp.path()).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("../alternate.yaml"), "{rendered}");
        assert!(rendered.contains("compose.yaml"), "{rendered}");
    }

    #[test]
    fn unknown_key_in_local_section_fails_to_load() {
        let temp = TempDir::new().unwrap();
        write_project_yaml(
            temp.path(),
            &format!(
                "{MINIMAL_SCHEMA_AND_PROJECT_BLOCK}runtime:\n  engine: docker_compose\n  compose_file: compose.yaml\nlocal:\n  secrets_env: secrets/local.env\n  output_dir: output\n  bogus_local_key: nope\n"
            ),
        );

        let error = Project::load(temp.path()).unwrap_err();

        assert!(
            format!("{error:#}").contains("bogus_local_key"),
            "error should name the offending key `bogus_local_key`: {error:#}"
        );
    }

    #[test]
    fn invalid_schema_version_fails_to_load_naming_the_value() {
        let temp = TempDir::new().unwrap();
        write_project_yaml(
            temp.path(),
            &format!(
                "schema_version: registryctl/v2\nproject:\n  name: my-first-api\n  kind: spreadsheet-api\n  products:\n    - registry-relay\n{MINIMAL_RUNTIME_BLOCK}{MINIMAL_LOCAL_BLOCK}"
            ),
        );

        let error = Project::load(temp.path()).unwrap_err();
        let rendered = format!("{error:#}");

        assert!(
            rendered.contains("registryctl/v2"),
            "error should name the offending value `registryctl/v2`: {rendered}"
        );
        assert!(
            rendered.contains("registryctl/v1"),
            "error should name the expected value `registryctl/v1`: {rendered}"
        );
    }

    #[test]
    fn missing_schema_version_fails_to_load() {
        let temp = TempDir::new().unwrap();
        write_project_yaml(
            temp.path(),
            &format!(
                "project:\n  name: my-first-api\n  kind: spreadsheet-api\n  products:\n    - registry-relay\n{MINIMAL_RUNTIME_BLOCK}{MINIMAL_LOCAL_BLOCK}"
            ),
        );

        let error = Project::load(temp.path()).unwrap_err();
        let rendered = format!("{error:#}");

        assert!(
            rendered.contains("schema_version"),
            "error should name the missing field `schema_version`: {rendered}"
        );
    }

    #[test]
    fn relay_open_always_reports_docs_url_for_headless_fallback() {
        // On macOS `open <url>` returns success even over SSH with no display,
        // so a conditional fallback never fires. The URL must always be surfaced.
        let lines = relay_open_lines("http://127.0.0.1:4242/docs");
        assert!(
            lines
                .iter()
                .any(|line| line.contains("http://127.0.0.1:4242/docs")),
            "relay open must always print the docs URL for headless environments; got {lines:?}"
        );
    }

    #[test]
    fn generated_gitignore_excludes_local_secrets_and_output() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();

        let gitignore = fs::read_to_string(project.join(".gitignore")).unwrap();
        assert!(gitignore.lines().any(|line| line == ".env"));
        assert!(gitignore.lines().any(|line| line == "secrets/"));
        assert!(gitignore.lines().any(|line| line == "output/"));
        assert!(gitignore.lines().any(|line| line == "state/"));
    }

    #[test]
    fn generated_credentials_reference_fingerprints_without_commitments() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();

        let env = fs::read_to_string(project.join("secrets/local.env")).unwrap();
        let config = fs::read_to_string(project.join("relay/config.yaml")).unwrap();
        let config_yaml: Value = serde_norway::from_str(&config).unwrap();
        assert_eq!(config_yaml["server"]["openapi_requires_auth"], false);
        assert!(!config.contains("commitment:"));

        for (id, env_name) in [
            ("metadata_reader", "METADATA_READER_HASH"),
            ("row_reader", "ROW_READER_HASH"),
            ("aggregate_reader", "AGGREGATE_READER_HASH"),
            ("identity_reader", "IDENTITY_READER_HASH"),
        ] {
            let fingerprint = env_value(&env, env_name);
            assert!(
                fingerprint.starts_with("sha256:"),
                "generated env should contain fingerprint for {id}"
            );
            assert!(
                config.contains(&format!("name: {env_name}")),
                "config should reference fingerprint env for {id}"
            );
        }
    }

    #[test]
    fn generated_fingerprint_preflight_passes_for_clean_project() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();

        let project = Project::load(&project_dir).unwrap();
        validate_project_fingerprints(&project_dir, &project).unwrap();
    }

    #[test]
    fn generated_fingerprint_preflight_fails_when_hash_changes() {
        for (env_name, id) in [
            ("METADATA_READER_HASH", "metadata_reader"),
            ("ROW_READER_HASH", "row_reader"),
            ("AGGREGATE_READER_HASH", "aggregate_reader"),
            ("IDENTITY_READER_HASH", "identity_reader"),
        ] {
            let temp = TempDir::new().unwrap();
            let project_dir = temp.path().join("my-first-api");
            init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();

            let env_path = project_dir.join("secrets/local.env");
            let mut env = fs::read_to_string(&env_path).unwrap();
            let original = env_value(&env, env_name);
            env = env.replace(
                &original,
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            );
            fs::write(&env_path, env).unwrap();

            let project = Project::load(&project_dir).unwrap();
            let error = validate_project_fingerprints(&project_dir, &project).unwrap_err();
            assert!(error.to_string().contains(&format!(
                "local raw key and fingerprint do not match for {id}"
            )));
        }
    }

    #[test]
    fn generated_fingerprint_preflight_fails_when_hash_is_missing() {
        for env_name in [
            "METADATA_READER_HASH",
            "ROW_READER_HASH",
            "AGGREGATE_READER_HASH",
            "IDENTITY_READER_HASH",
        ] {
            let temp = TempDir::new().unwrap();
            let project_dir = temp.path().join("my-first-api");
            init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();

            let env_path = project_dir.join("secrets/local.env");
            let env = fs::read_to_string(&env_path).unwrap();
            let filtered: String = env
                .lines()
                .filter(|line| !line.starts_with(&format!("{env_name}=")))
                .map(|line| format!("{line}\n"))
                .collect();
            fs::write(&env_path, filtered).unwrap();

            let project = Project::load(&project_dir).unwrap();
            let error = validate_project_fingerprints(&project_dir, &project).unwrap_err();
            assert!(error
                .to_string()
                .contains(&format!("missing required local env value {env_name}")));
        }
    }

    #[test]
    fn generated_public_files_do_not_contain_raw_keys_or_fingerprints() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();

        let env = fs::read_to_string(project.join("secrets/local.env")).unwrap();
        let secrets: BTreeSet<_> = env
            .lines()
            .filter_map(|line| line.split_once('='))
            .filter(|(name, _)| name.ends_with("_RAW") || name.ends_with("_HASH"))
            .map(|(_, value)| value.to_string())
            .collect();

        for path in [
            "registryctl.yaml",
            "compose.yaml",
            "README.md",
            "relay/config.yaml",
        ] {
            let contents = fs::read_to_string(project.join(path)).unwrap();
            for secret in &secrets {
                assert!(
                    !contents.contains(secret),
                    "{path} should not contain generated secret/fingerprint"
                );
            }
        }
    }

    #[test]
    fn planted_credential_sentinel_stays_private_and_is_redacted() {
        const SENTINEL: &str = "registryctl-credential-sentinel-do-not-leak";

        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();
        let env_path = project.join("secrets/local.env");
        let env = fs::read_to_string(&env_path).unwrap();
        let planted = env
            .lines()
            .map(|line| {
                if line.starts_with("METADATA_READER_RAW=") {
                    format!("METADATA_READER_RAW={SENTINEL}")
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        write_private_text(&env_path, &planted).unwrap();
        bruno_generate_project(&project, true).unwrap();

        assert!(fs::read_to_string(&env_path).unwrap().contains(SENTINEL));
        assert!(
            fs::read_to_string(project.join("bruno/registry-api/environments/local.bru"))
                .unwrap()
                .contains(SENTINEL)
        );
        for path in [
            "registryctl.yaml",
            "compose.yaml",
            "README.md",
            "relay/config.yaml",
            "bruno/registry-api/environments/local.example.bru",
            "bruno/registry-api/.registryctl-generated",
        ] {
            let contents = fs::read_to_string(project.join(path)).unwrap();
            assert!(!contents.contains(SENTINEL), "{path} leaked the sentinel");
        }

        let secrets = LocalEnv::load(&env_path).unwrap();
        let redactor = SecretRedactor::new(&secrets);
        assert_eq!(
            redactor.redact_output(format!("failure: {SENTINEL}").as_bytes()),
            Some("failure: [REDACTED]".to_string())
        );
        let smoke =
            serde_json::to_string(&run_smoke_checks("http://127.0.0.1:1", &secrets)).unwrap();
        assert!(!smoke.contains(SENTINEL));
    }

    #[cfg(unix)]
    #[test]
    fn private_bruno_credential_modes_survive_regeneration_and_force() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();
        let bruno_path = project.join("bruno/registry-api/environments/local.bru");

        fs::set_permissions(&bruno_path, fs::Permissions::from_mode(0o644)).unwrap();
        bruno_generate_project(&project, false).unwrap();
        assert_private_file(&project, "bruno/registry-api/environments/local.bru");

        fs::set_permissions(&bruno_path, fs::Permissions::from_mode(0o666)).unwrap();
        bruno_generate_project(&project, true).unwrap();
        assert_private_file(&project, "bruno/registry-api/environments/local.bru");
    }

    #[cfg(unix)]
    #[test]
    fn forced_bruno_generation_rejects_private_output_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();
        let local_bru = project.join("bruno/registry-api/environments/local.bru");
        let external = temp.path().join("external-local.bru");
        fs::write(&external, "external sentinel\n").unwrap();
        fs::remove_file(&local_bru).unwrap();
        symlink(&external, &local_bru).unwrap();

        let error = bruno_generate_project(&project, true).unwrap_err();
        assert!(format!("{error:#}").contains("must not contain a symlink"));
        assert_eq!(
            fs::read_to_string(&external).unwrap(),
            "external sentinel\n"
        );
    }

    #[test]
    fn generated_workbook_is_xlsx_with_benefits_sample_sheets() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();

        let workbook = fs::read(project.join("data/benefits_casework.xlsx")).unwrap();
        assert!(workbook.starts_with(b"PK"));
        let lossy = String::from_utf8_lossy(&workbook);
        assert!(lossy.contains("Households"));
        assert!(lossy.contains("Persons"));
        assert!(lossy.contains("Applications"));
        assert!(lossy.contains("hh-1001"));
        assert!(lossy.contains("app-3001"));
        assert!(lossy.contains("date_of_birth"));
        assert!(lossy.contains("given_name"));
        assert!(lossy.contains("national_id"));
        assert!(lossy.contains("address_line"));
        assert!(!lossy.contains("age_band"));
        assert!(!lossy.contains("eligibility_status"));
        assert!(!lossy.contains("is_primary_applicant"));
        assert!(!lossy.contains("consent_reference"));
    }

    #[test]
    fn compose_command_arguments_are_stable() {
        assert_eq!(
            compose_command_args(Path::new("compose.yaml"), &["up", "-d"]),
            ["compose", "-f", "compose.yaml", "up", "-d"]
        );
    }

    #[test]
    fn compose_runner_surfaces_nonzero_exit() {
        let temp = TempDir::new().unwrap();

        run_compose_command_with_platform(
            temp.path(),
            "true",
            Path::new("compose.yaml"),
            &["ps"],
            None,
        )
        .unwrap();
        let error = run_compose_command_with_platform(
            temp.path(),
            "false",
            Path::new("compose.yaml"),
            &["ps"],
            None,
        )
        .unwrap_err();

        assert!(error.to_string().contains("false compose exited"));
    }

    #[test]
    fn restart_project_requires_a_canonical_project() {
        let temp = TempDir::new().unwrap();

        let error = restart_project(temp.path()).unwrap_err();

        assert!(error.to_string().contains("registry-stack.yaml"));
    }

    #[test]
    fn readiness_wait_fails_after_bounded_timeout() {
        let error =
            wait_for_ready("Relay", "http://127.0.0.1:1", Duration::from_millis(1)).unwrap_err();

        assert!(error
            .to_string()
            .contains("Relay did not become healthy and ready before timeout"));
    }

    #[test]
    fn parses_local_http_urls_for_smoke_checks() {
        let parsed = ParsedHttpUrl::parse("http://127.0.0.1:4242/v1/datasets?x=y").unwrap();
        assert_eq!(parsed.host, "127.0.0.1");
        assert_eq!(parsed.port, 4242);
        assert_eq!(parsed.path, "/v1/datasets?x=y");

        let default_port = ParsedHttpUrl::parse("http://localhost/healthz").unwrap();
        assert_eq!(default_port.host, "localhost");
        assert_eq!(default_port.port, 80);
        assert_eq!(default_port.path, "/healthz");
    }

    #[test]
    fn smoke_report_json_does_not_include_local_keys() {
        let secrets = LocalEnv {
            values: BTreeMap::from([
                (
                    "METADATA_READER_RAW".to_string(),
                    "metadata-secret".to_string(),
                ),
                ("ROW_READER_RAW".to_string(), "row-secret".to_string()),
                (
                    "IDENTITY_READER_RAW".to_string(),
                    "identity-secret".to_string(),
                ),
            ]),
        };
        let report = run_smoke_checks("http://127.0.0.1:1", &secrets);
        let json = serde_json::to_string(&report).unwrap();
        let parsed = parse_smoke_report(&json).unwrap();

        assert!(!json.contains("metadata-secret"));
        assert!(!json.contains("row-secret"));
        assert!(!json.contains("identity-secret"));
        assert!(!report.passed);
        assert_eq!(parsed.schema_version, SmokeReportSchema::V1);
        assert_eq!(parsed.checks.len(), 11);
    }

    #[test]
    fn exact_row_count_smoke_rejects_duplicate_match_rows() {
        let response = serde_json::json!({
            "data": [
                {"project_id": "project-1"},
                {"project_id": "project-1"}
            ]
        });

        assert!(validate_exact_row_count_response(&response.to_string(), 1).is_err());
    }

    #[test]
    fn exact_row_count_smoke_rejects_unexpected_nonempty_no_match() {
        let response = serde_json::json!({
            "data": [{"project_id": "unexpected"}]
        });

        assert!(validate_exact_row_count_response(&response.to_string(), 0).is_err());
    }

    #[test]
    fn exact_row_count_smoke_accepts_one_object_match_and_empty_no_match() {
        let match_response = serde_json::json!({
            "data": [{
                "project_id": "project-1",
                "district_code": "D-01",
                "sector": "transport",
                "status": "active"
            }]
        });
        let no_match_response = serde_json::json!({"data": []});

        validate_exact_row_count_response(&match_response.to_string(), 1).unwrap();
        validate_exact_row_count_response(&no_match_response.to_string(), 0).unwrap();
    }

    #[test]
    fn exact_row_count_smoke_rejects_malformed_and_non_object_data() {
        for response in ["not JSON", "[]", r#"{"data": {}}"#, r#"{"data": [42]}"#] {
            assert!(
                validate_exact_row_count_response(response, 1).is_err(),
                "unexpectedly accepted {response}"
            );
        }
    }

    #[test]
    fn exact_row_count_smoke_allows_disclosure_field_changes() {
        let response = serde_json::json!({
            "data": [{
                "project_id": "project-1",
                "district_code": "D-01",
                "newly_disclosed_field": "reviewed"
            }]
        });

        validate_exact_row_count_response(&response.to_string(), 1).unwrap();
    }

    #[test]
    fn smoke_report_rejects_another_schema_version() {
        let secrets = LocalEnv {
            values: BTreeMap::new(),
        };
        let report = run_smoke_checks("http://127.0.0.1:1", &secrets);
        let mut document = serde_json::to_value(report).unwrap();
        document["schema_version"] = serde_json::json!("registryctl.smoke.v2");

        assert!(parse_smoke_report(&document.to_string()).is_err());
    }

    #[test]
    fn smoke_report_json_matches_committed_schema() {
        let secrets = LocalEnv {
            values: BTreeMap::new(),
        };
        let report = run_smoke_checks("http://127.0.0.1:1", &secrets);
        let document = serde_json::to_value(report).unwrap();
        let schema: JsonValue = serde_json::from_str(SMOKE_REPORT_SCHEMA_V1).unwrap();
        let compiled = jsonschema::JSONSchema::compile(&schema).expect("schema compiles");
        let validation_errors = match compiled.validate(&document) {
            Ok(()) => Vec::new(),
            Err(errors) => errors.map(|error| error.to_string()).collect::<Vec<_>>(),
        };

        assert!(
            validation_errors.is_empty(),
            "registryctl smoke report must satisfy its schema: {validation_errors:?}"
        );
    }

    #[test]
    fn smoke_project_retires_legacy_direct_projects_without_writing() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();

        let error = smoke_project(&project_dir).unwrap_err();
        assert!(error.to_string().contains("legacy pre-1.0 direct projects"));
        assert!(!project_dir.join("output/smoke-results.json").exists());
    }

    #[test]
    fn doctor_invokes_digest_pinned_compose_relay_for_relay_project() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();
        let fake_bin = temp.path().join("bin");
        fs::create_dir_all(&fake_bin).unwrap();
        write_fake_product(
            &fake_bin.join("docker"),
            &format!(
                "printf '%s\\n' \"$@\" > {}\nprintf '%s\\n' {}\nexit 0\n",
                shell_single_quoted(&temp.path().join("docker.args").display().to_string()),
                shell_single_quoted(&fake_product_report("registry-relay", "ok", vec![]))
            ),
        );

        let report = run_doctor_report_with_path(&project_dir, None, Some(&fake_bin)).unwrap();

        assert_eq!(report.status, ReportStatus::Ok);
        assert_eq!(report.products.len(), 1);
        assert_eq!(report.products[0].product, "registry-relay");
        assert_eq!(report.products[0].status, ReportStatus::Ok);
        let human = render_doctor_report(&report);
        assert!(human.starts_with("Registry Stack doctor: ok\n"), "{human}");
        assert!(human.contains("Profile: project"), "{human}");
        assert!(
            human.contains("registry-relay: ok (0 errors, 0 warnings)"),
            "{human}"
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["project"]["profile"], "project");
        let args = fs::read_to_string(temp.path().join("docker.args")).unwrap();
        assert_eq!(
            args,
            "compose\n-f\ncompose.yaml\nrun\n--rm\n--no-deps\n-T\nregistry-relay\ndoctor\n--config\n/etc/registry-relay/config.yaml\n--format\njson\n"
        );
        assert!(!project_dir.join("output/doctor/relay.config.yaml").exists());
        let compose = fs::read_to_string(project_dir.join("compose.yaml")).unwrap();
        assert!(compose.contains(test_image_lock().relay_image()));
    }

    #[test]
    fn doctor_invokes_relay_product_with_profile_override() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();
        let fake_bin = temp.path().join("bin");
        fs::create_dir_all(&fake_bin).unwrap();
        write_fake_product(
            &fake_bin.join("docker"),
            &format!(
                "printf '%s\\n' \"$@\" > {}\nprintf '%s\\n' {}\nexit 0\n",
                shell_single_quoted(&temp.path().join("docker.args").display().to_string()),
                shell_single_quoted(&fake_product_report("registry-relay", "ok", vec![]))
            ),
        );

        let report = run_doctor_report_with_path(
            &project_dir,
            Some(DeploymentProfile::Local),
            Some(&fake_bin),
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::Ok);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["project"]["profile"], "local");
        let args = fs::read_to_string(temp.path().join("docker.args")).unwrap();
        assert_eq!(
            args,
            "compose\n-f\ncompose.yaml\nrun\n--rm\n--no-deps\n-T\nregistry-relay\ndoctor\n--config\n/etc/registry-relay/config.yaml\n--format\njson\n--profile\nlocal\n"
        );
    }

    #[test]
    fn doctor_reports_missing_product_binary_without_panic() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();
        let empty_path = temp.path().join("empty-path");
        fs::create_dir_all(&empty_path).unwrap();

        let report = run_doctor_report_with_path(&project_dir, None, Some(&empty_path)).unwrap();

        assert_eq!(report.status, ReportStatus::Error);
        assert_eq!(report.products[0].status, ReportStatus::NotRun);
        assert!(report.products[0].report.diagnostics[0]
            .message
            .contains("Docker Compose v2"));
    }

    #[test]
    fn doctor_reports_nonzero_product_exit_and_redacts_output() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();
        let env = fs::read_to_string(project_dir.join("secrets/local.env")).unwrap();
        let secrets = env
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(_, value)| value.to_string())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        let fake_bin = temp.path().join("bin");
        fs::create_dir_all(&fake_bin).unwrap();
        let secret_prints = secrets
            .iter()
            .map(|secret| {
                format!(
                    "printf 'stdout has {}\\n'\nprintf 'stderr has {}\\n' >&2\n",
                    shell_single_quoted(secret),
                    shell_single_quoted(secret)
                )
            })
            .collect::<String>();
        write_fake_product(
            &fake_bin.join("docker"),
            &format!("{secret_prints}exit 17\n"),
        );

        let report = run_doctor_report_with_path(&project_dir, None, Some(&fake_bin)).unwrap();
        let json = serde_json::to_string(&report).unwrap();

        assert_eq!(report.status, ReportStatus::Error);
        assert_eq!(report.products[0].status, ReportStatus::Error);
        assert_eq!(
            report.products[0].report.diagnostics[0].code,
            "registryctl.product_doctor.report_missing_after_failure"
        );
        let error = ensure_doctor_report_ok(&report).unwrap_err();
        assert!(error
            .to_string()
            .contains("one or more product doctor checks failed"));
        for secret in &secrets {
            assert!(!json.contains(secret));
        }
    }

    #[test]
    fn secret_redactor_deduplicates_before_length_ordering() {
        let secrets = LocalEnv {
            values: BTreeMap::from([
                ("A".to_string(), "secret1".to_string()),
                ("B".to_string(), "another".to_string()),
                ("C".to_string(), "secret1".to_string()),
                ("D".to_string(), "longer-secret".to_string()),
            ]),
        };

        let redactor = SecretRedactor::new(&secrets);

        assert_eq!(
            redactor.secrets,
            vec![
                "longer-secret".to_string(),
                "another".to_string(),
                "secret1".to_string(),
            ]
        );
    }

    #[test]
    fn doctor_extracts_structured_product_report_and_findings_after_redaction() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();
        let env = fs::read_to_string(project_dir.join("secrets/local.env")).unwrap();
        let secret = env
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(_, value)| value)
            .find(|value| !value.is_empty())
            .unwrap();
        let product_json = serde_json::json!({
            "schema_version": "registry.config.diagnostic_report.v1",
            "product": "registry-relay",
            "config_schema_version": "registry.relay.config.v1",
            "source": {"kind": "generated_file", "path": "relay/config.yaml"},
            "status": "error",
            "summary": {"error_count": 1, "warning_count": 0},
            "diagnostics": [
                {
                    "code": "relay.config.unsigned",
                    "severity": "error",
                    "message": format!("do not leak {secret}")
                }
            ],
            "context_constraints": [],
            "generated_at": "2026-06-20T00:00:00Z"
        })
        .to_string();
        let fake_bin = temp.path().join("bin");
        fs::create_dir_all(&fake_bin).unwrap();
        write_fake_product(
            &fake_bin.join("docker"),
            &format!(
                "printf '%s\\n' {}\nexit 1\n",
                shell_single_quoted(&product_json)
            ),
        );

        let report = run_doctor_report_with_path(&project_dir, None, Some(&fake_bin)).unwrap();
        let json = serde_json::to_value(&report).unwrap();

        assert_eq!(report.status, ReportStatus::Error);
        assert_eq!(json["products"][0]["product"], "registry-relay");
        assert_eq!(
            json["products"][0]["report"]["diagnostics"][0]["code"],
            "relay.config.unsigned"
        );
        let rendered = serde_json::to_string(&json).unwrap();
        assert!(!rendered.contains(secret));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn doctor_carries_audit_shipping_section_through_typed_aggregation() {
        // registryctl deserializes each product's doctor JSON into
        // ConfigDiagnosticReport and re-serializes it into the aggregated
        // report. If the struct doesn't model audit_shipping, this section is
        // silently dropped even though the product emitted it.
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();
        let product_json = serde_json::json!({
            "schema_version": "registry.config.diagnostic_report.v1",
            "product": "registry-relay",
            "config_schema_version": "registry.relay.config.v1",
            "source": {"kind": "generated_file", "path": "relay/config.yaml"},
            "status": "ok",
            "summary": {"error_count": 0, "warning_count": 0},
            "diagnostics": [],
            "context_constraints": [],
            "audit_shipping": {
                "sink_type": "file",
                "shipping_target_configured": true,
                "shipping_target": "declared_external",
                "shipping_health": "stale",
                "shipping_observed_at": "2026-06-19T23:00:00Z"
            },
            "generated_at": "2026-06-20T00:00:00Z"
        })
        .to_string();
        let fake_bin = temp.path().join("bin");
        fs::create_dir_all(&fake_bin).unwrap();
        write_fake_product(
            &fake_bin.join("docker"),
            &format!(
                "printf '%s\\n' {}\nexit 0\n",
                shell_single_quoted(&product_json)
            ),
        );

        let report = run_doctor_report_with_path(&project_dir, None, Some(&fake_bin)).unwrap();
        let json = serde_json::to_value(&report).unwrap();

        let shipping = &json["products"][0]["report"]["audit_shipping"];
        assert_eq!(shipping["sink_type"], "file");
        assert_eq!(shipping["shipping_target_configured"], true);
        assert_eq!(shipping["shipping_target"], "declared_external");
        assert_eq!(shipping["shipping_health"], "stale");
        assert_eq!(shipping["shipping_observed_at"], "2026-06-19T23:00:00Z");
    }

    #[test]
    fn doctor_report_json_has_registryctl_schema() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();
        let fake_bin = temp.path().join("bin");
        fs::create_dir_all(&fake_bin).unwrap();
        write_fake_product(
            &fake_bin.join("docker"),
            &format!(
                "printf '%s\\n' {}\nexit 0\n",
                shell_single_quoted(&fake_product_report("registry-relay", "ok", vec![]))
            ),
        );

        let report = run_doctor_report_with_path(&project_dir, None, Some(&fake_bin)).unwrap();
        let json = serde_json::to_value(&report).unwrap();

        assert_eq!(
            json["schema_version"],
            REGISTRYCTL_VALIDATION_REPORT_SCHEMA_VERSION_V1
        );
        assert_eq!(json["status"], "ok");
        assert_eq!(json["project"]["profile"], "project");
        assert_eq!(json["products"][0]["status"], "ok");
        let schema: JsonValue =
            serde_json::from_str(REGISTRYCTL_VALIDATION_REPORT_SCHEMA_V1).unwrap();
        let compiled = jsonschema::JSONSchema::compile(&schema).expect("schema compiles");
        let validation_errors = match compiled.validate(&json) {
            Ok(()) => Vec::new(),
            Err(errors) => errors.map(|error| error.to_string()).collect::<Vec<_>>(),
        };
        assert!(
            validation_errors.is_empty(),
            "registryctl doctor report must satisfy its schema: {validation_errors:?}"
        );
    }

    #[test]
    fn doctor_human_values_cannot_inject_terminal_lines() {
        assert_eq!(
            human_line_value("line\nreturn\r tab\t escape\u{1b}"),
            "line\\nreturn\\r tab\\t escape\\u001b"
        );
    }

    fn write_fake_product(path: &Path, body: &str) {
        fs::write(path, format!("#!/bin/sh\n{body}")).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o755);
        }
        fs::set_permissions(path, permissions).unwrap();
    }

    fn assert_private_state_dirs(project: &Path, paths: &[&str]) {
        for path in paths {
            assert_private_state_dir(project, path);
        }
    }

    #[cfg(unix)]
    fn assert_private_state_dir(project: &Path, path: &str) {
        use std::os::unix::fs::PermissionsExt;

        let actual_mode = fs::metadata(project.join(path))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(actual_mode, 0o700, "{path} should be private");
    }

    #[cfg(not(unix))]
    fn assert_private_state_dir(_project: &Path, _path: &str) {}

    #[cfg(unix)]
    fn assert_private_file(project: &Path, path: &str) {
        use std::os::unix::fs::PermissionsExt;

        let actual_mode = fs::metadata(project.join(path))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(actual_mode, 0o600, "{path} should be private");
    }

    #[cfg(not(unix))]
    fn assert_private_file(_project: &Path, _path: &str) {}

    #[cfg(unix)]
    #[test]
    fn runtime_identity_uses_default_nonroot_for_root_owner() {
        let identity = runtime_identity_for_owner(0, 0);

        assert_eq!(identity.uid.to_string(), DEFAULT_NONROOT_CONTAINER_ID);
        assert_eq!(identity.gid.to_string(), DEFAULT_NONROOT_CONTAINER_ID);

        let identity = runtime_identity_for_owner(1000, 0);
        assert_eq!(identity.uid, 1000);
        assert_eq!(identity.gid.to_string(), DEFAULT_NONROOT_CONTAINER_ID);
    }

    fn assert_runtime_env_matches_project_owner(project: &Path) {
        let env = fs::read_to_string(project.join(".env")).unwrap();
        let uid = env_value(&env, REGISTRY_STACK_RUNTIME_UID_ENV);
        let gid = env_value(&env, REGISTRY_STACK_RUNTIME_GID_ENV);

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let metadata = fs::metadata(project).unwrap();
            let identity = runtime_identity_for_owner(metadata.uid(), metadata.gid());
            assert_eq!(uid, identity.uid.to_string());
            assert_eq!(gid, identity.gid.to_string());
        }

        #[cfg(not(unix))]
        {
            assert_eq!(uid, DEFAULT_NONROOT_CONTAINER_ID);
            assert_eq!(gid, DEFAULT_NONROOT_CONTAINER_ID);
        }
    }

    fn init_canonical_spreadsheet(project: &Path) {
        init_registry_project(&ProjectInitOptions {
            starter: ProjectStarter::Spreadsheet,
            directory: project.to_path_buf(),
        })
        .unwrap();
    }

    fn combined_runtime_images() -> CanonicalRuntimeImages {
        CanonicalRuntimeImages {
            relay: TEST_RELAY_IMAGE.to_string(),
            notary: Some(TEST_NOTARY_IMAGE.to_string()),
            postgresql: Some(TEST_POSTGRESQL_IMAGE.to_string()),
        }
    }

    fn prepare_combined_runtime(project: &Path) -> CanonicalRuntime {
        init_canonical_spreadsheet(project);
        add_notary_to_canonical_project(project).unwrap();
        // These unit tests exercise generated runtime topology and private-file
        // closure. Fixture evaluation is covered through the real registryctl
        // binary because only that binary owns the internal CEL worker mode.
        let project_file = project.join(CANONICAL_PROJECT_FILE);
        let project_contents = fs::read_to_string(&project_file).unwrap();
        fs::write(
            &project_file,
            project_contents
                .replace(
                    "      project-record-exists: { cel: project.matched, disclosure: predicate }\n",
                    "      project-status: { output: project.status, disclosure: value }\n",
                )
                .replace(
                    "      project-status-accepted: { cel: 'project.matched && project.status == \"active\"', disclosure: predicate }\n",
                    "",
                ),
        )
        .unwrap();
        for fixture in ["match.yaml", "planned.yaml", "no-match.yaml"] {
            let status = match fixture {
                "match.yaml" => "active",
                "planned.yaml" => "planned",
                "no-match.yaml" => "null",
                _ => unreachable!(),
            };
            let path = project
                .join("integrations/project-record-snapshot/fixtures")
                .join(fixture);
            let contents = fs::read_to_string(&path).unwrap();
            let without_cel_expectations = contents
                .lines()
                .filter(|line| {
                    !line.contains("project-record-exists:")
                        && !line.contains("project-status-accepted:")
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            fs::write(
                &path,
                without_cel_expectations.replacen(
                    "  claims:\n",
                    &format!("  claims:\n    project-status: {status}\n"),
                    1,
                ),
            )
            .unwrap();
        }
        prepare_canonical_runtime_with_images(project, &combined_runtime_images()).unwrap()
    }

    #[test]
    fn add_notary_is_idempotent_and_records_project_subject_type() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("spreadsheet-project");
        init_canonical_spreadsheet(&project);

        let first = add_notary_to_canonical_project(&project).unwrap();
        let second = add_notary_to_canonical_project(&project).unwrap();

        assert_eq!(first.status, "updated");
        assert_eq!(second.status, "unchanged");
        assert_eq!(first.files, second.files);
        assert!(fs::read_to_string(project.join(CANONICAL_PROJECT_FILE))
            .unwrap()
            .contains(
                "  public-works-verification:\n    kind: evidence\n    version: 1\n    subject_type: project\n"
            ));
        assert_eq!(
            canonical_spreadsheet_binding(&project).unwrap().topology,
            CanonicalRuntimeTopology::CombinedNotary
        );
    }

    #[test]
    fn combined_runtime_has_exact_private_topology_and_distinct_credentials() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("spreadsheet-project");
        let runtime = prepare_combined_runtime(&project);
        let compose = fs::read_to_string(&runtime.compose_file).unwrap();
        let document: JsonValue = serde_norway::from_str(&compose).unwrap();
        let services = document["services"].as_object().unwrap();

        assert_eq!(services.len(), 6);
        assert_eq!(
            services["registry-relay"]["ports"],
            serde_json::json!([CANONICAL_RELAY_HOST_PORT])
        );
        assert_eq!(
            services["notary-network"]["ports"],
            serde_json::json!([CANONICAL_NOTARY_HOST_PORT])
        );
        assert!(services["postgresql"]["ports"].is_null());
        assert!(services["registry-notary"]["ports"].is_null());
        assert!(services["registry-relay-consultation"]["ports"].is_null());
        assert_eq!(
            services["registry-relay-consultation"]["network_mode"],
            "service:notary-network"
        );
        assert_eq!(
            services["registry-notary"]["network_mode"],
            "service:notary-network"
        );
        assert_eq!(
            services["registry-relay-bootstrap"]["network_mode"],
            "service:notary-network"
        );
        assert_eq!(
            services["postgresql"]["network_mode"],
            "service:notary-network"
        );
        assert_eq!(document["networks"]["notary-internal"]["internal"], true);
        assert_eq!(
            services["notary-network"]["networks"],
            serde_json::json!(["notary-internal", "notary-host"])
        );
        assert!(services["postgresql"]["command"][3]
            .as_str()
            .unwrap()
            .contains("listen_addresses=127.0.0.1"));
        assert_eq!(
            services["registry-relay"]["networks"],
            serde_json::json!(["public"])
        );
        assert_eq!(
            services["registry-relay-consultation"]["volumes"][0],
            "../../build/local/private/relay:/etc/registry-relay:ro"
        );
        assert_eq!(
            services["registry-relay-consultation"]["command"][1],
            CANONICAL_CONSULTATION_RELAY_CONFIG_MOUNT
        );
        assert_eq!(services["registry-notary"]["image"], TEST_NOTARY_IMAGE);
        assert_eq!(services["postgresql"]["image"], TEST_POSTGRESQL_IMAGE);
        assert_eq!(services["notary-network"]["image"], TEST_POSTGRESQL_IMAGE);
        assert_eq!(
            services["notary-network"]["healthcheck"]["test"],
            serde_json::json!([
                "CMD",
                "pg_isready",
                "-h",
                "127.0.0.1",
                "-U",
                CANONICAL_RUNTIME_POSTGRES_USER,
                "-d",
                "postgres"
            ])
        );
        let notary_config: JsonValue = serde_norway::from_str(
            &fs::read_to_string(project.join(CANONICAL_RUNTIME_NOTARY_CONFIG)).unwrap(),
        )
        .unwrap();
        assert_eq!(notary_config["cel"]["worker_count"], 1);
        assert_eq!(
            notary_config["cel"]["worker_memory_bytes"],
            1024 * 1024 * 1024_u64
        );
        let (runtime_uid, runtime_gid) = compose_runtime_identity(&project).unwrap();
        let runtime_user = format!("{runtime_uid}:{runtime_gid}");
        for name in [
            "registry-relay",
            "registry-relay-consultation",
            "registry-relay-bootstrap",
            "registry-notary",
        ] {
            assert_eq!(services[name]["user"], runtime_user);
        }
        for name in [
            "registry-relay",
            "registry-relay-consultation",
            "registry-relay-bootstrap",
            "registry-notary",
            "postgresql",
            "notary-network",
        ] {
            assert_eq!(services[name]["read_only"], true);
            assert_eq!(services[name]["cap_drop"], serde_json::json!(["ALL"]));
            assert_eq!(
                services[name]["security_opt"],
                serde_json::json!(["no-new-privileges:true"])
            );
            if name != "registry-relay-bootstrap" {
                assert!(services[name]["healthcheck"].is_object());
            }
        }

        let credentials = strict_canonical_runtime_credentials(
            &project,
            CanonicalRuntimeTopology::CombinedNotary,
        )
        .unwrap();
        let notary = credentials.notary.as_ref().unwrap();
        validate_distinct_runtime_credentials(&credentials).unwrap();
        assert_ne!(
            notary.workload_private_jwk,
            notary.notary_signing_private_jwk
        );
        assert_eq!(
            notary.workload_public_jwk,
            public_jwk_from_private(&notary.workload_private_jwk).unwrap()
        );
        assert!(
            !fs::read_to_string(project.join(CANONICAL_RUNTIME_NOTARY_ENV))
                .unwrap()
                .contains(&notary.workload_private_jwk)
        );
        let init = fs::read_to_string(project.join(CANONICAL_RUNTIME_DB_INIT)).unwrap();
        assert!(!init.contains(&notary.relay_database_password));
        assert!(init.contains(CANONICAL_RUNTIME_RELAY_DB_PASSWORD_ENV));

        let token = fs::read_to_string(project.join(CANONICAL_RUNTIME_WORKLOAD_TOKEN)).unwrap();
        validate_workload_jwt(&token, &notary.workload_private_jwk).unwrap();
        let claims: JsonValue = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(token.trim().split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(claims["iss"], CANONICAL_RUNTIME_WORKLOAD_ISSUER);
        assert_eq!(claims["aud"], CANONICAL_RUNTIME_WORKLOAD_AUDIENCE);
        assert_eq!(claims["client_id"], CANONICAL_RUNTIME_WORKLOAD_CLIENT);
        assert_eq!(claims["azp"], CANONICAL_RUNTIME_WORKLOAD_CLIENT);
        assert_eq!(claims["scope"], CANONICAL_RUNTIME_WORKLOAD_SCOPE);
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
            CANONICAL_RUNTIME_WORKLOAD_TTL_SECONDS
        );

        let compose_file = runtime.compose_file.strip_prefix(&project).unwrap();
        assert_eq!(
            compose_command_args(
                compose_file,
                &["up", "-d", "--wait", "--wait-timeout", "60"]
            ),
            vec![
                "compose",
                "-f",
                CANONICAL_RUNTIME_COMPOSE,
                "up",
                "-d",
                "--wait",
                "--wait-timeout",
                "60",
            ]
        );
        assert_eq!(
            compose_command_args(compose_file, &["down"]),
            vec!["compose", "-f", CANONICAL_RUNTIME_COMPOSE, "down"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn combined_runtime_enforces_modes_symlinks_manifest_closure_and_tamper_detection() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let temp = TempDir::new().unwrap();
        let project = temp.path().join("spreadsheet-project");
        prepare_combined_runtime(&project);
        let manifest: CanonicalRuntimeManifest =
            serde_json::from_slice(&fs::read(project.join(CANONICAL_RUNTIME_MANIFEST)).unwrap())
                .unwrap();
        assert_eq!(manifest.topology, CanonicalRuntimeTopology::CombinedNotary);
        assert_eq!(
            manifest.notary.as_ref().unwrap().notary_image,
            TEST_NOTARY_IMAGE
        );
        assert_eq!(
            manifest.notary.as_ref().unwrap().postgresql_image,
            TEST_POSTGRESQL_IMAGE
        );
        validate_runtime_file_closure(&project, CanonicalRuntimeTopology::CombinedNotary).unwrap();
        for relative in [
            CANONICAL_RUNTIME_ROOT,
            CANONICAL_RUNTIME_SECRETS,
            ".registry-stack/runtime/local/private",
            ".registry-stack/runtime/local/private/db",
            ".registry-stack/runtime/local/private/notary",
            ".registry-stack/runtime/local/private/notary/config",
            ".registry-stack/runtime/local/private/relay",
            ".registry-stack/runtime/local/private/relay/config",
            ".registry-stack/runtime/local/private/relay/config/artifacts",
            ".registry-stack/runtime/local/private/workload",
        ] {
            assert_eq!(
                fs::metadata(project.join(relative))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700,
                "{relative}"
            );
        }
        for relative in [
            CANONICAL_RUNTIME_ENV,
            CANONICAL_RUNTIME_RELAY_ENV,
            CANONICAL_RUNTIME_CONSULTATION_RELAY_ENV,
            CANONICAL_RUNTIME_RELAY_BOOTSTRAP_ENV,
            CANONICAL_RUNTIME_NOTARY_ENV,
            CANONICAL_RUNTIME_POSTGRES_ENV,
            CANONICAL_RUNTIME_WORKLOAD_TOKEN,
            CANONICAL_RUNTIME_WORKLOAD_PRIVATE_JWK,
            CANONICAL_RUNTIME_WORKLOAD_JWKS,
        ] {
            assert_eq!(
                fs::metadata(project.join(relative))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600,
                "{relative}"
            );
        }
        for relative in [
            CANONICAL_RUNTIME_DB_INIT,
            CANONICAL_RUNTIME_NOTARY_CONFIG,
            CANONICAL_RUNTIME_CONSULTATION_RELAY_CONFIG,
            CANONICAL_RUNTIME_POSTGRES_CA,
        ] {
            assert_eq!(
                fs::metadata(project.join(relative))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o644,
                "{relative}"
            );
        }

        let jwks = project.join(CANONICAL_RUNTIME_WORKLOAD_JWKS);
        let original = fs::read_to_string(&jwks).unwrap();
        write_private_text(&jwks, &(original.clone() + "\n")).unwrap();
        let error = load_canonical_runtime(&project, CanonicalRuntimeValidation::Full).unwrap_err();
        assert!(
            format!("{error:#}").contains("credential contract")
                || format!("{error:#}").contains("integrity")
        );
        write_private_text(&jwks, &original).unwrap();

        let unexpected = project
            .join(CANONICAL_RUNTIME_ROOT)
            .join("private/unexpected");
        write_private_text(&unexpected, "planted\n").unwrap();
        let error = load_canonical_runtime(&project, CanonicalRuntimeValidation::Full).unwrap_err();
        assert!(format!("{error:#}").contains("closure"));
        fs::remove_file(&unexpected).unwrap();

        let notary_env = project.join(CANONICAL_RUNTIME_NOTARY_ENV);
        let external = temp.path().join("external.env");
        fs::write(&external, fs::read(&notary_env).unwrap()).unwrap();
        fs::remove_file(&notary_env).unwrap();
        symlink(&external, &notary_env).unwrap();
        let error = load_canonical_runtime(&project, CanonicalRuntimeValidation::Full).unwrap_err();
        assert!(format!("{error:#}").contains("symlink"));
    }

    #[test]
    fn combined_smoke_plan_is_value_free_and_covers_denials_and_three_outcomes() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("spreadsheet-project");
        prepare_combined_runtime(&project);
        let credentials = strict_canonical_runtime_credentials(
            &project,
            CanonicalRuntimeTopology::CombinedNotary,
        )
        .unwrap();

        let report =
            run_canonical_smoke_checks("http://127.0.0.1:1", "http://127.0.0.1:2", &credentials);
        let notary_checks = report
            .checks
            .iter()
            .filter(|check| check.method == "POST")
            .collect::<Vec<_>>();
        assert_eq!(notary_checks.len(), 6);
        assert_eq!(
            notary_checks
                .iter()
                .map(|check| check.expected_status)
                .collect::<Vec<_>>(),
            vec![401, 401, 403, 200, 200, 200]
        );
        assert!(notary_checks
            .iter()
            .all(|check| check.path == "/v1/evaluations"));
        let json = serde_json::to_string(&report).unwrap();
        for value in [
            "pw_001",
            "PW-002",
            "pw_999",
            credentials.notary.as_ref().unwrap().caller_raw.as_str(),
            credentials
                .notary
                .as_ref()
                .unwrap()
                .under_scoped_raw
                .as_str(),
        ] {
            assert!(!json.contains(value));
        }
    }

    #[test]
    fn notary_smoke_accepts_one_exact_predicate_result_and_rejects_mixed_disclosure_shapes() {
        let accepted = serde_json::json!({
            "results": [{
                "claim_id": "project-status-accepted",
                "value": true,
                "satisfied": true,
                "disclosure": "predicate",
            }],
        })
        .to_string();
        validate_notary_smoke_response(&accepted, "project-status-accepted", true).unwrap();

        let mixed = serde_json::json!({
            "results": [
                {
                    "claim_id": "project-status-accepted",
                    "value": true,
                    "satisfied": true,
                    "disclosure": "predicate",
                },
                {
                    "claim_id": "project-status",
                    "value": "active",
                    "satisfied": true,
                    "disclosure": "value",
                },
            ],
        })
        .to_string();
        assert!(
            validate_notary_smoke_response(&mixed, "project-status-accepted", true)
                .unwrap_err()
                .to_string()
                .contains("exact claim set")
        );
    }

    #[cfg(unix)]
    #[test]
    fn add_notary_transaction_rolls_back_new_files_and_restores_existing_modes() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = TempDir::new().unwrap();
        let project = temp.path().join("spreadsheet-project");
        init_canonical_spreadsheet(&project);
        let project_file = project.join(CANONICAL_PROJECT_FILE);
        let environment_file = project.join(CANONICAL_LOCAL_ENVIRONMENT_FILE);
        let project_before = fs::read_to_string(&project_file).unwrap();
        let environment_before = fs::read_to_string(&environment_file).unwrap();
        let project_mode = fs::metadata(&project_file).unwrap().permissions().mode() & 0o777;
        let environment_mode = fs::metadata(&environment_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        ADD_NOTARY_FAIL_AFTER_PUBLISH_COUNT.with(|count| count.set(3));
        let error = add_notary_to_canonical_project(&project).unwrap_err();
        ADD_NOTARY_FAIL_AFTER_PUBLISH_COUNT.with(|count| count.set(0));
        assert!(
            format!("{error:#}").contains("rolled back"),
            "unexpected error: {error:#}"
        );
        assert_eq!(fs::read_to_string(&project_file).unwrap(), project_before);
        assert_eq!(
            fs::read_to_string(&environment_file).unwrap(),
            environment_before
        );
        assert_eq!(
            fs::metadata(&project_file).unwrap().permissions().mode() & 0o777,
            project_mode
        );
        assert_eq!(
            fs::metadata(&environment_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            environment_mode
        );
        assert!(!project
            .join("integrations/project-record-snapshot")
            .exists());
    }

    #[test]
    fn canonical_runtime_is_closed_private_and_secret_free_outside_credentials() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("spreadsheet-project");
        init_canonical_spreadsheet(&project);

        let runtime = prepare_canonical_runtime_with_image(&project, TEST_RELAY_IMAGE).unwrap();
        let binding = canonical_spreadsheet_binding(&project).unwrap();
        let compose = fs::read_to_string(&runtime.compose_file).unwrap();
        validate_canonical_compose(
            &compose,
            &CanonicalRuntimeImages {
                relay: TEST_RELAY_IMAGE.to_string(),
                notary: None,
                postgresql: None,
            },
            &binding,
        )
        .unwrap();
        validate_compiled_local_relay_auth(&runtime.relay_config, &binding).unwrap();

        let credentials = strict_runtime_credentials(
            &project.join(CANONICAL_RUNTIME_RELAY_ENV),
            &runtime.secrets_env,
        )
        .unwrap();
        for secret in [
            &credentials.audit_secret,
            &credentials.match_raw,
            &credentials.match_hash,
            &credentials.no_match_raw,
            &credentials.no_match_hash,
        ] {
            for relative in [
                CANONICAL_RUNTIME_COMPOSE,
                CANONICAL_RUNTIME_MANIFEST,
                CANONICAL_RELAY_CONFIG,
                CANONICAL_ARTIFACT_MANIFEST,
            ] {
                assert!(
                    !fs::read_to_string(project.join(relative))
                        .unwrap()
                        .contains(secret),
                    "{relative} leaked a generated credential"
                );
            }
        }
        assert!(
            !fs::read_to_string(project.join(CANONICAL_RUNTIME_RELAY_ENV))
                .unwrap()
                .contains(&credentials.match_raw)
        );
        assert!(
            !fs::read_to_string(project.join(CANONICAL_RUNTIME_RELAY_ENV))
                .unwrap()
                .contains(&credentials.no_match_raw)
        );
        let document: JsonValue = serde_norway::from_str(&compose).unwrap();
        assert_eq!(
            document["services"]["registry-relay"]["ports"],
            serde_json::json!([CANONICAL_RELAY_HOST_PORT])
        );
        assert_eq!(
            document["services"]["registry-relay"]["volumes"],
            serde_json::json!([
                "../../build/local/private/relay/config/relay.yaml:/etc/registry-relay/config.yaml:ro",
                "../../../data/public_works_projects.xlsx:/var/lib/registry/public_works_projects.xlsx:ro"
            ])
        );
        assert_eq!(
            document["services"]["registry-relay"]["env_file"],
            serde_json::json!(["secrets/relay.env"])
        );
        let compose_file = runtime.compose_file.strip_prefix(&project).unwrap();
        assert_eq!(
            compose_command_args(compose_file, &["up", "-d"]),
            vec!["compose", "-f", CANONICAL_RUNTIME_COMPOSE, "up", "-d",]
        );
        let doctor = product_doctor_invocations(&project, &runtime, None, None).unwrap();
        assert_eq!(doctor.len(), 1);
        assert_eq!(
            doctor[0].args,
            vec![
                "compose",
                "-f",
                CANONICAL_RUNTIME_COMPOSE,
                "run",
                "--rm",
                "--no-deps",
                "-T",
                "registry-relay",
                "doctor",
                "--config",
                CANONICAL_RELAY_CONFIG_MOUNT,
                "--format",
                "json",
            ]
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for relative in [CANONICAL_RUNTIME_ROOT, CANONICAL_RUNTIME_SECRETS] {
                assert_eq!(
                    fs::metadata(project.join(relative))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o700
                );
            }
            for relative in [
                CANONICAL_RUNTIME_COMPOSE,
                CANONICAL_RUNTIME_MANIFEST,
                CANONICAL_RUNTIME_ENV,
                CANONICAL_RUNTIME_RELAY_ENV,
            ] {
                assert_eq!(
                    fs::metadata(project.join(relative))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn canonical_runtime_rejects_a_permissive_credential_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = TempDir::new().unwrap();
        let project = temp.path().join("spreadsheet-project");
        init_canonical_spreadsheet(&project);
        prepare_canonical_runtime_with_image(&project, TEST_RELAY_IMAGE).unwrap();
        let credential_path = project.join(CANONICAL_RUNTIME_ENV);
        let credentials = fs::read_to_string(&credential_path).unwrap();
        let mut permissions = fs::metadata(&credential_path).unwrap().permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&credential_path, permissions).unwrap();

        let error = load_canonical_runtime(&project, CanonicalRuntimeValidation::Full).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("Unix mode 0600"), "{rendered}");
        for (_, value) in credentials.lines().filter_map(|line| line.split_once('=')) {
            assert!(!rendered.contains(value), "{rendered}");
        }
    }

    #[test]
    fn canonical_runtime_rejects_generated_compose_and_config_tampering() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("spreadsheet-project");
        init_canonical_spreadsheet(&project);
        prepare_canonical_runtime_with_image(&project, TEST_RELAY_IMAGE).unwrap();

        let compose_path = project.join(CANONICAL_RUNTIME_COMPOSE);
        let compose = fs::read_to_string(&compose_path).unwrap();
        write_private_text(
            &compose_path,
            &compose.replace(CANONICAL_RELAY_HOST_PORT, "0.0.0.0:4242:8080"),
        )
        .unwrap();
        let error = load_canonical_runtime(&project, CanonicalRuntimeValidation::Full).unwrap_err();
        assert!(format!("{error:#}").contains("Compose integrity"));

        prepare_canonical_runtime_with_image(&project, TEST_RELAY_IMAGE).unwrap_err();
        write_private_text(&compose_path, &compose).unwrap();
        let config_path = project.join(CANONICAL_RELAY_CONFIG);
        let config = fs::read_to_string(&config_path).unwrap();
        write_private_text(&config_path, &(config + "\n# planted tamper\n")).unwrap();
        let error = load_canonical_runtime(&project, CanonicalRuntimeValidation::Full).unwrap_err();
        assert!(format!("{error:#}").contains("Relay config integrity"));
    }

    #[test]
    fn canonical_runtime_rejects_missing_source_without_value_echo() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("spreadsheet-project");
        init_canonical_spreadsheet(&project);
        fs::remove_file(project.join("data/public_works_projects.xlsx")).unwrap();

        let error = prepare_canonical_runtime_with_image(&project, TEST_RELAY_IMAGE).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("project workbook is missing"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("public_works_projects.xlsx"),
            "{rendered}"
        );
        assert!(!project.join(CANONICAL_RUNTIME_ROOT).exists());
    }

    #[test]
    fn canonical_runtime_full_validation_rejects_workbook_content_drift_without_value_echo() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("spreadsheet-project");
        init_canonical_spreadsheet(&project);
        prepare_canonical_runtime_with_image(&project, TEST_RELAY_IMAGE).unwrap();
        let workbook = project.join("data/public_works_projects.xlsx");
        let mut bytes = fs::read(&workbook).unwrap();
        bytes.push(0);
        fs::write(&workbook, bytes).unwrap();

        let error = load_canonical_runtime(&project, CanonicalRuntimeValidation::Full).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("operator-owned source data changed"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("public_works_projects.xlsx"),
            "{rendered}"
        );
        assert!(!rendered.contains("PW-001"), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn canonical_runtime_rejects_source_and_generated_path_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let project = temp.path().join("spreadsheet-project");
        init_canonical_spreadsheet(&project);
        let workbook = project.join("data/public_works_projects.xlsx");
        let external = temp.path().join("external.xlsx");
        let bytes = fs::read(&workbook).unwrap();
        fs::write(&external, &bytes).unwrap();
        fs::remove_file(&workbook).unwrap();
        symlink(&external, &workbook).unwrap();

        let error = prepare_canonical_runtime_with_image(&project, TEST_RELAY_IMAGE).unwrap_err();
        assert!(format!("{error:#}").contains("symlink"));
        assert_eq!(fs::read(&external).unwrap(), bytes);
        assert!(!project.join(CANONICAL_RUNTIME_ROOT).exists());
    }

    #[test]
    fn canonical_runtime_records_and_validates_candidate_transport() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("spreadsheet-project");
        init_canonical_spreadsheet(&project);
        let candidate = format!(
            "ghcr.io/registrystack/registry-relay-candidate@sha256:{}",
            "a".repeat(64)
        );

        let runtime = prepare_canonical_runtime_with_image(&project, &candidate).unwrap();
        let manifest: CanonicalRuntimeManifest =
            serde_json::from_slice(&fs::read(project.join(CANONICAL_RUNTIME_MANIFEST)).unwrap())
                .unwrap();
        assert_eq!(manifest.relay_image, candidate);
        assert_eq!(
            manifest.workbook_classification,
            ArtifactInputClassification::OperatorOwnedSourceData
        );
        let compose = fs::read_to_string(runtime.compose_file).unwrap();
        assert!(compose.contains(&candidate));
        load_canonical_runtime(&project, CanonicalRuntimeValidation::Full).unwrap();
    }

    fn fake_product_report(product: &str, status: &str, diagnostics: Vec<JsonValue>) -> String {
        let error_count = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic["severity"] == "error")
            .count();
        let warning_count = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic["severity"] == "warning")
            .count();
        serde_json::json!({
            "schema_version": "registry.config.diagnostic_report.v1",
            "product": product,
            "config_schema_version": product_config_schema_version(product),
            "source": {"kind": "generated_file", "path": format!("{product}.yaml")},
            "status": status,
            "summary": {"error_count": error_count, "warning_count": warning_count},
            "diagnostics": diagnostics,
            "context_constraints": [],
            "generated_at": "2026-06-20T00:00:00Z"
        })
        .to_string()
    }

    fn shell_single_quoted(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    fn env_value(env: &str, name: &str) -> String {
        env.lines()
            .filter_map(|line| line.split_once('='))
            .find_map(|(key, value)| (key == name).then(|| value.to_string()))
            .unwrap_or_else(|| panic!("{name} should be present"))
    }
}
