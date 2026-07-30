use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use clap::ValueEnum;
use registry_platform_config::{
    sha256_uri, verify_config_bundle, ConfigBundleFile, ConfigBundleManifest,
    ConfigBundleSignature, ConfigBundleSignatureEnvelope, ConfigTrustAnchor,
    ConfigTrustAnchorSigner, ProductAcceptanceIdentityV1, ProductAcceptanceLaneV1,
    ProductAcceptanceProductV1, ProductTrustDomainV1, MAX_BUNDLE_FILE_BYTES,
    MAX_CONFIG_BUNDLE_SEQUENCE, MAX_MANIFEST_BYTES, MAX_SIGNATURE_ENVELOPE_BYTES,
    MAX_TRUST_ANCHOR_BYTES,
};
use registry_platform_crypto::{
    canonicalize_json, parse_json_strict, sign as sign_payload, PrivateJwk, PublicJwk,
    SigningAlgorithm, MAX_JWK_JSON_BYTES,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::Zeroizing;

mod trust;

pub use trust::{
    create_trust_anchor, rotate_trust_anchor, sign_product_bundle, ProductBundleSignOptions,
    ProductBundleSignReportV1, SigningInputMarkerV1, TrustAnchorCreateOptions,
    TrustAnchorCreateReportV1, TrustAnchorRotateOptions, TrustAnchorRotateReportV1,
    SIGNING_INPUT_MARKER_FILE, SIGNING_INPUT_SCHEMA_ID, SIGNING_INPUT_SCHEMA_VERSION,
};

mod approved_set;

pub use approved_set::{
    assemble_approved_set, load_approved_baseline_set, ApprovedAnchorTransitionLinkV1,
    ApprovedBaselineLanesV1, ApprovedBaselineSetV1, ApprovedLaneEntryV1, ApprovedLaneLocatorsV1,
    ApprovedLaneV1, ApprovedSetAssembleOptions, ApprovedSetAssemblyReportV1,
    CrossLaneInterfaceDigestsV1, PortableArtifactLocator, ReviewedBuildUpdateV1,
    ReviewedLaneBindingV1, APPROVED_BASELINE_SET_SCHEMA_ID, APPROVED_BASELINE_SET_SCHEMA_VERSION,
};

mod deployment;

pub use deployment::{
    generate_deployment_package, verify_generated_deployment, DeploymentGenerateRequestV1,
    DeploymentOwnershipReportV1, DeploymentPackageRenderReportV1, DeploymentVerifyRequestV1,
};

mod dev_runtime;

pub use dev_runtime::prepare_dev_runtime_plan;
pub use dev_runtime::{
    diagnose_dev_runtime, load_bound_dev_runtime_plan, DevFailureCategory, DevLogsReport,
    DevRuntimeController, DevRuntimeError, DevRuntimePlan, DevRuntimeResult, DevSmokeReportV1,
    DevSmokeScenarioResult, DevSmokeStatus, DevStartupReport, DevStatusReport,
    DockerComposeBackend, DEV_SMOKE_REPORT_SCHEMA_V1,
};

mod dev_credentials;

mod release_lock;

pub use release_lock::{
    verify_installed_release_lock, verify_release_lock_for_package, LockedEmbeddedStarterV1,
    LockedManagedImagesV1, LockedOciImageV1, LockedOciPlatformV1, LockedProductRecipeV1,
    LockedRegistryctlArtifactV1, LockedReleaseIdentityV1, LockedRuntimeRecipesV1, OciPlatformV1,
    RegistryReleaseLockV1, RegistryctlPlatformV1, SupportedContractsV1, VerifiedManagedImagesV1,
    VerifiedProductRuntimeV1, VerifiedReleaseLockV1, VerifiedRuntimeMappingV1,
    RELEASE_LOCK_SCHEMA_ID, RELEASE_LOCK_SCHEMA_VERSION,
};

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
    PromotionBaselineMigration, PromotionBlockingReason, PromotionBoundaryAssessment,
    PromotionChange, PromotionChangeEffect, PromotionChangeInput, PromotionChangeKind,
    PromotionCompatibilityAssessment, PromotionCompatibilityComponent, PromotionCompatibilityInput,
    PromotionCompatibilityState, PromotionDeploymentEvaluation, PromotionDisposition,
    PromotionDocument, PromotionEvidenceGrade, PromotionEvidenceLimitation, PromotionFieldAddress,
    PromotionFieldClassification, PromotionFieldOwnership, PromotionFieldPath,
    PromotionRequiredActions, PromotionReviewClass, RedactionReason, ReferenceCoverageSummary,
    ReferenceSourceContract, RequiredFixtureCoverageRequirement, RequiredProductAction,
    Requiredness, ReviewCompareOptions, ReviewComparisonReportV1, ReviewedBuildRecordV1,
    ReviewedCeilingAssessment, ReviewedCeilingInput, ReviewedProjectBuildOptions,
    ReviewedProjectBuildReportV1, ReviewedRevisionComparison, RuntimeActivationEvaluation,
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
    PROJECT_SEMANTIC_IMPACT_SCHEMA_VERSION_V1, REVIEWED_BUILD_RECORD_FILE,
};
pub use project_authoring::{
    build_reviewed_project, compare_registry_project_environments_semantically,
    compare_registry_project_to_embedded_starter_semantically,
    compare_registry_projects_semantically, compare_reviewed_project,
    ProjectEnvironmentSemanticComparisonOptions, ProjectSemanticComparisonChange,
    ProjectSemanticComparisonOptions, ProjectSemanticComparisonReportV1,
    ProjectSemanticComparisonSchemaVersion, ProjectStarterSemanticComparisonOptions,
    SemanticComparisonAffectedSubject, SemanticComparisonAffectedSubjectKind,
    SemanticComparisonAssurance, SemanticComparisonChangeSource, SemanticComparisonConsumer,
    SemanticComparisonDimension, SemanticComparisonDirection, SemanticComparisonEquivalence,
    SemanticComparisonEvidenceGrade, SemanticComparisonEvidenceLimitation,
    SemanticComparisonExternalApproval, SemanticComparisonFieldAddress,
    SemanticComparisonGeneratedArtifact, SemanticComparisonKind, SemanticComparisonPrecision,
    SemanticComparisonRequiredAction, SemanticComparisonRequirements,
    SemanticComparisonReviewClass, SemanticComparisonReviewPlan, SemanticComparisonReviewPlanState,
    SemanticComparisonSchemaFamily, PROJECT_SEMANTIC_COMPARISON_SCHEMA_VERSION_V1,
};

const CONFIG_BUNDLE_SIGNATURE_SCHEMA: &str = "registry.platform.config_bundle_signatures.v1";
const CONFIG_TRUST_ANCHOR_SCHEMA: &str = "registry.platform.config_trust_anchor.v1";
const INIT_REPORT_SCHEMA_VERSION: &str = "registryctl.init.v1";
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InitProjectKind {
    RegistryProject,
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
}

#[derive(Clone, Debug, Serialize)]
pub struct InitArtifacts {
    pub project_file: PathBuf,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub enum DeploymentProfile {
    Local,
    HostedLab,
    Production,
    EvidenceGrade,
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
    let identity = verified.manifest.acceptance_identity.clone();
    Ok(BundleVerifyReport {
        schema_version: "registryctl.config_bundle.verify.v1".to_string(),
        product: product_acceptance_product_name(identity.product).to_string(),
        environment: identity.environment,
        stream_id: identity.stream,
        instance_id: Some(identity.instance),
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
    let instance = options
        .instance_id
        .clone()
        .unwrap_or_else(|| options.stream_id.clone());
    let acceptance_identity = legacy_product_acceptance_identity(
        &options.product,
        &options.environment,
        &options.stream_id,
        &instance,
    )?;
    let manifest = ConfigBundleManifest {
        schema: "registry.platform.config_bundle.v1".to_string(),
        acceptance_identity,
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
    let acceptance_identity =
        legacy_product_acceptance_identity(&product, &environment, &stream_id, &instance_id)?;
    let anchor = ConfigTrustAnchor {
        schema: CONFIG_TRUST_ANCHOR_SCHEMA.to_string(),
        acceptance_identity,
        version: 1,
        threshold: 1,
        enabled_signers: Vec::new(),
    };
    write_trust_anchor_file(anchor_path, &anchor)?;
    Ok(anchor_report(anchor_path, &anchor))
}

pub fn add_config_anchor_key(
    anchor_path: &Path,
    jwk_path: &Path,
    enabled: bool,
) -> Result<AnchorReport> {
    if !enabled {
        bail!("disabled trust-anchor keys are unsupported; omit the key instead");
    }
    let mut anchor = read_anchor_unvalidated(anchor_path)?;
    let jwk_text = read_bounded_utf8_file(jwk_path, MAX_JWK_JSON_BYTES)?;
    let jwk = PublicJwk::parse(&jwk_text)
        .with_context(|| format!("failed to parse public JWK {}", jwk_path.display()))?;
    let kid = jwk
        .jkt()
        .context("failed to compute JWK thumbprint for anchor key")?;
    if anchor
        .enabled_signers
        .iter()
        .any(|signer| signer.kid == kid)
    {
        bail!("trust anchor already contains signer {kid}");
    }
    anchor
        .enabled_signers
        .push(ConfigTrustAnchorSigner { kid, jwk });
    anchor
        .enabled_signers
        .sort_by(|left, right| left.kid.cmp(&right.kid));
    anchor
        .validate()
        .with_context(|| format!("invalid trust anchor {}", anchor_path.display()))?;
    write_trust_anchor_file(anchor_path, &anchor)?;
    Ok(anchor_report(anchor_path, &anchor))
}

pub fn remove_config_anchor_key(anchor_path: &Path, kid: &str) -> Result<AnchorReport> {
    let mut anchor = read_anchor_unvalidated(anchor_path)?;
    let before = anchor.enabled_signers.len();
    anchor.enabled_signers.retain(|signer| signer.kid != kid);
    if anchor.enabled_signers.len() == before {
        bail!("trust anchor does not contain signer {kid}");
    }
    if !anchor.enabled_signers.is_empty() {
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
    anchor
        .acceptance_identity
        .validate()
        .context("trust anchor acceptance identity is invalid")?;
    if anchor.version == 0 {
        bail!("trust anchor version must be non-zero");
    }
    if anchor.threshold == 0 {
        bail!("trust anchor threshold must be non-zero");
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
        product: product_acceptance_product_name(anchor.acceptance_identity.product).to_string(),
        environment: anchor.acceptance_identity.environment.clone(),
        stream_id: anchor.acceptance_identity.stream.clone(),
        instance_id: anchor.acceptance_identity.instance.clone(),
        signer_count: anchor.enabled_signers.len(),
        enabled_signer_count: anchor.enabled_signers.len(),
    }
}

fn legacy_product_acceptance_identity(
    product: &str,
    environment: &str,
    stream: &str,
    instance: &str,
) -> Result<ProductAcceptanceIdentityV1> {
    let (product, lane) = match product {
        "registry-relay" => {
            let lane = if stream.contains("consultation") || instance.contains("consultation") {
                ProductAcceptanceLaneV1::RelayConsultation
            } else {
                ProductAcceptanceLaneV1::RelayPublic
            };
            (ProductAcceptanceProductV1::RegistryRelay, lane)
        }
        "registry-notary" => (
            ProductAcceptanceProductV1::RegistryNotary,
            ProductAcceptanceLaneV1::Notary,
        ),
        _ => bail!("unsupported config bundle product"),
    };
    let identity = ProductAcceptanceIdentityV1 {
        trust_domain: ProductTrustDomainV1::Governed,
        project: stream.to_string(),
        environment: environment.to_string(),
        lane,
        product,
        stream: stream.to_string(),
        instance: instance.to_string(),
    };
    identity
        .validate()
        .context("legacy config acceptance identity is invalid")?;
    Ok(identity)
}

fn product_acceptance_product_name(product: ProductAcceptanceProductV1) -> &'static str {
    match product {
        ProductAcceptanceProductV1::RegistryRelay => "registry-relay",
        ProductAcceptanceProductV1::RegistryNotary => "registry-notary",
    }
}

fn signing_algorithm_label(algorithm: SigningAlgorithm) -> &'static str {
    match algorithm {
        SigningAlgorithm::EdDsa => "EdDSA",
        SigningAlgorithm::Es256 => "ES256",
        SigningAlgorithm::Rs256 => "RS256",
    }
}
