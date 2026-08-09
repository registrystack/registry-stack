//! Complete authenticated Evidence evaluation and fail-closed release pipeline.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::Path,
    str,
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::{SubsecRound as _, Utc};
use registry_platform_audit::{AuditError, AuditProfile};
use registry_platform_crypto::{
    LocalJwkSigner, PrivateJwk, SigningProvider, TransitSigner, TransitSignerConfig,
};
use serde_json::{Map as JsonMap, Value};
use thiserror::Error;

use crate::{
    audit::{
        AuditAuthority, AuditDecision, AuditPhase, AuditSubject,
        AuthorityKind as AuditAuthorityKind, EvidenceAuditError, EvidenceAuditEvent,
        EvidenceAuditLog, EvidenceAuthorizationRefusalAuditEvent, ResponseProtection,
    },
    auth::Authenticator,
    bundle::{Bundle, DeploymentInputs},
    config::{
        subject_binding_permits_response_format, AcquisitionConfig, AssuranceProfile,
        AuthorityKind, ConceptForm, RequirementKind, ResponseFormat, RuntimeConfig,
        RuntimeSignerConfig, SelectorField, SelectorInput, StageRole, SubjectBindingMode,
        SubjectCardinality, ValueOrigin, MAXIMUM_HOLDER_BOUND_BATCH_SIZE,
    },
    contracts::definitions_contract_accepts,
    kernel::{EvidenceConstruction, EvidenceScope, KernelError, OfflineKernel, ValueProjection},
    model::{
        request_nonce_is_canonical, EvidenceDefinition, EvidenceDefinitionConcept,
        EvidenceDefinitionSelector, EvidenceDefinitionSubject, EvidenceDefinitions,
        EvidenceRequest, EvidenceSelectorField, FlattenedJws, JwksDocument, LookupResult,
        RequestedSelector, RequestedSubject, SdJwtVcBatchEnvelope, SdJwtVcBatchEnvelopeType,
        SelectorValue, SubjectBinding, UnsignedEnvelopeType, UnsignedEnvelopeWarning,
        UnsignedEvidenceEnvelope, UnsignedIntegrityProtection,
    },
    problem::ProblemCode,
    rate_limit::{EvidenceRateLimiter, RateLimitConfig, RateLimitError},
    sdjwt_vc,
    secrets::{ProtectedSecret, SecretProvider, SecretResolver},
    selector::{
        match_entitlement, resolve_selectors, validate_entitlement_context,
        validate_subject_binding_key, AuthorizationError, MatchedEntitlement,
        ResolvedAuthorization, ResolvedSelectorValue, ResolvedSubjectScope,
    },
    signing::EvidenceSigner,
    source::{statement_inputs, ResolvedSourceSelector, SourceError, SourceExecutor},
    EVIDENCE_DEFINITIONS_SCHEMA_V1, EVIDENCE_JWS_MEDIA_TYPE, EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE,
    EVIDENCE_SD_JWT_VC_MEDIA_TYPE, EVIDENCE_UNSIGNED_ENVELOPE_SCHEMA_V1,
    EVIDENCE_UNSIGNED_MEDIA_TYPE, MAX_SD_JWT_VC_BATCH_RESPONSE_BYTES, SD_JWT_VC_BATCH_SCHEMA_V1,
};
use zeroize::Zeroizing;

const MAX_OPERATION_BYTES: usize = 128;

#[derive(Debug, Error)]
pub enum RuntimeInitializationError {
    #[error("the immutable Evidence bundle could not be loaded")]
    Bundle,
    #[error("the Evidence secret resolver could not initialize")]
    Secrets,
    #[error("the Evidence audit boundary could not initialize: {0}")]
    Audit(AuditInitializationFault),
    #[error("the Evidence signing boundary could not initialize")]
    Signing,
    #[error("an Evidence source plan could not initialize")]
    Source,
    #[error("the Evidence rate limiter could not initialize")]
    RateLimit,
}

/// Why the audit boundary refused to initialize.
///
/// A mode an operator fixes with `chmod`, a chain that no longer verifies, and
/// a second writer already holding the sink lock are three unrelated faults
/// with three unrelated remedies. They are reported separately because from
/// outside the process they are indistinguishable, and the wrong guess sends an
/// operator hunting for tampering in what is a permission bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditInitializationFault {
    /// `auditStorage` bounds or the audit key version are out of range.
    Configuration,
    /// The audit hash secret is missing, unreadable, or too weak.
    Secret,
    /// The audit file or lock is not owner-only and singly linked, or its
    /// directory is not controlled by the service owner.
    Storage,
    /// Another writer already holds the sink's single-writer lock.
    Locked,
    /// A chain is present but its records do not verify against the head.
    Chain,
}

impl AuditInitializationFault {
    /// The value-free cause, for the operator message this fault appears in.
    /// It names the fault and never the audit path, which the operator already
    /// has in the runtime file.
    pub fn cause(self) -> &'static str {
        match self {
            Self::Configuration => "the audit storage configuration is out of range",
            Self::Secret => "the audit hash secret is unusable",
            Self::Storage => {
                "the audit file or lock is not owner-only, or its directory is unavailable or not owner-controlled"
            }
            Self::Locked => "another writer already holds the audit sink lock",
            Self::Chain => "the existing audit chain did not verify",
        }
    }
}

impl fmt::Display for AuditInitializationFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.cause())
    }
}

impl From<&EvidenceAuditError> for AuditInitializationFault {
    fn from(error: &EvidenceAuditError) -> Self {
        match error {
            EvidenceAuditError::Configuration => Self::Configuration,
            EvidenceAuditError::InvalidEvent | EvidenceAuditError::SegmentMissing { .. } => {
                Self::Chain
            }
            EvidenceAuditError::Audit(audit) => match audit {
                AuditError::Io(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                    Self::Chain
                }
                AuditError::Io(_) => Self::Storage,
                AuditError::SinkLocked { .. } => Self::Locked,
                AuditError::EmptyEnvVarName
                | AuditError::EnvVarUnavailable { .. }
                | AuditError::EnvVarNotUnicode { .. }
                | AuditError::EmptySecret { .. }
                | AuditError::WeakSecret { .. } => Self::Secret,
                // Everything else the sink can report at startup is a statement
                // about chain state: a record that does not parse, a hash that
                // does not match, or a head that cannot be read.
                _ => Self::Chain,
            },
        }
    }
}

/// Deployment secret material, resolved and validated exactly as service
/// startup validates it.
pub struct ValidatedSecretMaterial {
    pub audit_secret: ProtectedSecret,
    pub subject_binding_secret: ProtectedSecret,
    pub signer: EvidenceSigner,
    pub jwks: JwksDocument,
}

/// Secret-derived material needed to prepare an independent verification
/// context. Unlike complete startup validation, this boundary never resolves
/// the audit key or opens audit storage.
pub struct ValidatedVerificationMaterial {
    pub subject_binding_secret: ProtectedSecret,
    pub signer: EvidenceSigner,
    pub jwks: JwksDocument,
}

/// Resolve and validate the audit, subject-binding, and signing secret
/// material a bundle names, with no side effects: nothing is written and no
/// audit chain is opened. Startup builds its runtime state from the returned
/// material, and `check` runs the same validation so a deployment whose
/// mounted secrets the server would refuse fails check instead of first
/// start. Source credentials are deliberately not resolved here: readiness
/// owns them.
pub async fn validate_secret_material(
    bundle: &Bundle,
    runtime: &RuntimeConfig,
    secrets: &SecretResolver,
) -> Result<ValidatedSecretMaterial, RuntimeInitializationError> {
    let audit_secret = secrets
        .resolve(bundle.config.audit.hash_secret_ref.as_str())
        .map_err(|_| RuntimeInitializationError::Audit(AuditInitializationFault::Secret))?;
    AuditProfile::production_from_secret_bytes(Zeroizing::new(
        audit_secret.expose_secret().to_vec(),
    ))
    .map_err(|_| RuntimeInitializationError::Audit(AuditInitializationFault::Secret))?;

    let verification = validate_verification_material(bundle, &runtime.signer, secrets).await?;
    if audit_secret.expose_secret() == verification.subject_binding_secret.expose_secret() {
        return Err(RuntimeInitializationError::Secrets);
    }

    Ok(ValidatedSecretMaterial {
        audit_secret,
        subject_binding_secret: verification.subject_binding_secret,
        signer: verification.signer,
        jwks: verification.jwks,
    })
}

/// Resolve and validate only the binding and signing material required to
/// create a pre-response verification context. This deliberately excludes
/// source credentials and the audit boundary.
pub async fn validate_verification_material(
    bundle: &Bundle,
    signer_config: &RuntimeSignerConfig,
    secrets: &SecretResolver,
) -> Result<ValidatedVerificationMaterial, RuntimeInitializationError> {
    let subject_binding_secret = secrets
        .resolve(bundle.config.subject_binding.secret_ref.as_str())
        .map_err(|_| RuntimeInitializationError::Secrets)?;
    validate_subject_binding_key(
        subject_binding_secret.expose_secret(),
        bundle.config.subject_binding.key_version,
        &bundle.config.service.trust_domain,
    )
    .map_err(|_| RuntimeInitializationError::Secrets)?;

    let provider: Arc<dyn SigningProvider> = match signer_config {
        RuntimeSignerConfig::LocalJwk { private_key_ref } => {
            let signing_secret = secrets
                .resolve(private_key_ref.as_str())
                .map_err(|_| RuntimeInitializationError::Signing)?;
            let signing_json = str::from_utf8(signing_secret.expose_secret())
                .map_err(|_| RuntimeInitializationError::Signing)?;
            let private_jwk =
                PrivateJwk::parse(signing_json).map_err(|_| RuntimeInitializationError::Signing)?;
            Arc::new(
                LocalJwkSigner::new(private_jwk)
                    .map_err(|_| RuntimeInitializationError::Signing)?,
            )
        }
        RuntimeSignerConfig::Transit {
            unix_socket_path,
            mount,
            key_name,
            key_version,
            timeout_milliseconds,
        } => {
            let config = TransitSignerConfig::new(
                unix_socket_path,
                mount,
                key_name,
                *key_version,
                bundle.active_public_jwk.clone(),
                Duration::from_millis(*timeout_milliseconds),
            )
            .map_err(|_| RuntimeInitializationError::Signing)?;
            Arc::new(
                TransitSigner::initialize(config)
                    .await
                    .map_err(|_| RuntimeInitializationError::Signing)?,
            )
        }
    };
    let signer = EvidenceSigner::initialize_governed(provider, &bundle.active_public_jwk)
        .await
        .map_err(|_| RuntimeInitializationError::Signing)?;
    let jwks = crate::signing::jwks_document_with_revocations(
        signer.public_jwk(),
        bundle.published_public_jwks.values().cloned(),
        bundle.config.signing.revoked_key_ids.clone(),
    )
    .map_err(|_| RuntimeInitializationError::Signing)?;

    Ok(ValidatedVerificationMaterial {
        subject_binding_secret,
        signer,
        jwks,
    })
}

/// One safe failure classification for the public HTTP boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFailure {
    problem: ProblemCode,
    category: &'static str,
}

impl RuntimeFailure {
    pub fn problem(self) -> ProblemCode {
        self.problem
    }

    pub fn category(self) -> &'static str {
        self.category
    }
}

impl std::fmt::Debug for RuntimeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeFailure")
            .field("problem", &self.problem)
            .field("category", &self.category)
            .finish()
    }
}

impl std::fmt::Display for RuntimeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the Evidence operation did not complete")
    }
}

impl std::error::Error for RuntimeFailure {}

/// One released response: the exact final immutable bytes that were serialized
/// before the durable disclosure-release audit event, plus their exact media
/// type. The HTTP boundary returns these bytes unchanged.
pub struct ReleasedEvidence {
    format: ResponseFormat,
    media_type: &'static str,
    bytes: Vec<u8>,
}

impl ReleasedEvidence {
    pub fn format(&self) -> ResponseFormat {
        self.format
    }

    pub fn media_type(&self) -> &'static str {
        self.media_type
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl std::fmt::Debug for ReleasedEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReleasedEvidence")
            .field("format", &self.format)
            .field("media_type", &self.media_type)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// All runtime state is derived from one captured immutable bundle revision.
pub struct EvidenceRuntime {
    kernel: OfflineKernel,
    runtime_config: RuntimeConfig,
    runtime_revision: String,
    authenticator: Authenticator,
    sources: BTreeMap<String, SourceExecutor>,
    audit: Arc<EvidenceAuditLog>,
    signer: EvidenceSigner,
    jwks: JwksDocument,
    subject_binding_secret: ProtectedSecret,
    rate_limiter: Arc<EvidenceRateLimiter>,
}

impl std::fmt::Debug for EvidenceRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceRuntime")
            .field("bundle_revision", &self.kernel.bundle().revision())
            .field("source_count", &self.sources.len())
            .field("signing_key_id", &self.signer.key_id())
            .finish_non_exhaustive()
    }
}

impl EvidenceRuntime {
    /// Capture and initialize the complete Version 1 deployment at one revision.
    pub async fn initialize(runtime_path: &Path) -> Result<Self, RuntimeInitializationError> {
        Self::initialize_internal(runtime_path, None).await
    }

    #[cfg(test)]
    pub(crate) async fn initialize_with_authenticator(
        runtime_path: &Path,
        authenticator: Authenticator,
    ) -> Result<Self, RuntimeInitializationError> {
        Self::initialize_internal(runtime_path, Some(authenticator)).await
    }

    async fn initialize_internal(
        runtime_path: &Path,
        authenticator_override: Option<Authenticator>,
    ) -> Result<Self, RuntimeInitializationError> {
        let deployment =
            DeploymentInputs::load(runtime_path).map_err(|_| RuntimeInitializationError::Bundle)?;
        let runtime_document = deployment.runtime;
        let runtime_config = runtime_document.config.clone();
        let runtime_revision = runtime_document.revision().to_owned();
        let bundle = Arc::new(deployment.bundle);
        let kernel = OfflineKernel::compile(Arc::clone(&bundle))
            .map_err(|_| RuntimeInitializationError::Bundle)?;

        let secrets = Arc::new(
            SecretResolver::new(
                [SecretProvider::File],
                &runtime_config.secret_providers.file.root,
            )
            .map_err(|_| RuntimeInitializationError::Secrets)?,
        );

        let material = validate_secret_material(&bundle, &runtime_config, &secrets).await?;
        let audit = EvidenceAuditLog::initialize(
            &runtime_config.audit_storage.path,
            runtime_config.audit_storage.maximum_file_bytes,
            material.audit_secret.expose_secret().to_vec(),
            bundle.config.audit.hash_key_version,
        )
        .await
        .map_err(|error| RuntimeInitializationError::Audit((&error).into()))?;

        let mut sources = BTreeMap::new();
        for (source_id, source) in bundle.config.sources.iter() {
            let allowed_selector_sets = bundle.config.source_selector_sets(source_id);
            // A serving deployment has a runtime document, so a statement
            // source is compiled against the file it will actually read. The
            // statement's strong check runs here, at startup, rather than on
            // the first request that needs it.
            let statement =
                statement_inputs(source, &bundle, Some(&runtime_document.source_extracts))
                    .map_err(|_| RuntimeInitializationError::Source)?;
            let executor = SourceExecutor::new_with_selector_sets_and_tls(
                source,
                &allowed_selector_sets,
                &runtime_config.outbound_tls,
                &runtime_document.ca_bundles,
                statement,
                Arc::clone(&secrets),
            )
            .map_err(|_| RuntimeInitializationError::Source)?;
            sources.insert(source_id.to_owned(), executor);
        }

        let configured_limits = &bundle.config.rate_limits;
        let rate_limiter = EvidenceRateLimiter::new(RateLimitConfig {
            requests_per_principal_per_minute: u32::try_from(
                configured_limits.requests_per_principal_per_minute,
            )
            .map_err(|_| RuntimeInitializationError::RateLimit)?,
            burst_per_principal: u32::try_from(configured_limits.burst_per_principal)
                .map_err(|_| RuntimeInitializationError::RateLimit)?,
            failed_selector_attempts_per_principal_authority_per_minute: u32::try_from(
                configured_limits.failed_selector_attempts_per_principal_authority_per_minute,
            )
            .map_err(|_| RuntimeInitializationError::RateLimit)?,
        })
        .map_err(|_| RuntimeInitializationError::RateLimit)?;
        let rate_limiter = Arc::new(rate_limiter);

        Ok(Self {
            kernel,
            runtime_config,
            runtime_revision,
            authenticator: authenticator_override.unwrap_or_else(|| {
                Authenticator::from_config(
                    &bundle.config.authentication,
                    bundle.config.assurance_profile,
                )
            }),
            sources,
            audit: Arc::new(audit),
            signer: material.signer,
            jwks: material.jwks,
            subject_binding_secret: material.subject_binding_secret,
            rate_limiter,
        })
    }

    pub fn bundle(&self) -> &Bundle {
        self.kernel.bundle()
    }

    pub fn runtime_config(&self) -> &RuntimeConfig {
        &self.runtime_config
    }

    pub fn runtime_revision(&self) -> &str {
        &self.runtime_revision
    }

    pub fn jwks(&self) -> &JwksDocument {
        &self.jwks
    }

    /// The rate limiter whose tracked-key count backs the
    /// `evidence_rate_limiter_tracked_keys` gauge on the metrics listener.
    ///
    /// Returned as a shared handle, independent of this runtime's own
    /// lifetime, so the metrics listener can hold it and sample it fresh on
    /// every scrape.
    pub(crate) fn rate_limiter(&self) -> Arc<EvidenceRateLimiter> {
        Arc::clone(&self.rate_limiter)
    }

    /// The audit chain, for the capacity gauge.
    ///
    /// Shared for the same reason as the rate limiter: the metrics listener
    /// samples the chain's on-disk footprint at scrape time rather than
    /// caching a value taken at startup.
    pub(crate) fn audit(&self) -> Arc<EvidenceAuditLog> {
        Arc::clone(&self.audit)
    }

    #[cfg(test)]
    pub(crate) fn replace_signer_for_test(&mut self, signer: EvidenceSigner) {
        self.signer = signer;
    }

    /// Readiness proves all locally required material and source credentials.
    /// It never performs an evidence-data request.
    ///
    /// It also asks the access-token issuer for its key set, but only so an
    /// issuer that has gone quiet is named in the log while requests still
    /// work. The answer does not decide readiness: the verifier keeps serving
    /// a key set it cannot recheck for a bounded while, and an issuer outage
    /// that pulled every replica out of rotation at once would be a cascading
    /// failure, not a diagnosis.
    pub async fn ready(&self) -> bool {
        self.authenticator.probe_key_source().await;
        if validate_subject_binding_key(
            self.subject_binding_secret.expose_secret(),
            self.bundle().config.subject_binding.key_version,
            &self.bundle().config.service.trust_domain,
        )
        .is_err()
            || !self.signer.ensure_ready().await
            || !self.audit.ready().await
        {
            return false;
        }
        for source in self.sources.values() {
            if source.credentials_ready().await.is_err() {
                return false;
            }
        }
        true
    }

    /// Attempt the access-token issuer's key set once, so a `jwksUri` this
    /// deployment cannot use is named at startup rather than discovered one
    /// rejected request at a time. It reports; it does not refuse to start.
    pub async fn announce_key_source(&self) {
        self.authenticator.announce_key_source().await;
    }

    /// The sources whose mounted extract is already older than they allow.
    ///
    /// Startup names these for the same reason it names an unusable `jwksUri`,
    /// and with the same standing: it reports, it does not refuse to start, and
    /// it does not decide readiness. Age is an evaluation-time question, asked
    /// against the instant each evaluation carries, so this is a startup
    /// snapshot rather than a second authority over it. An extract that goes
    /// stale later, or one republished under the running process, is answered
    /// by that per-evaluation check and by the `source-extract-stale` audit
    /// category, never by this.
    pub fn stale_extract_sources(&self) -> Vec<&str> {
        let instant = Utc::now();
        self.sources
            .iter()
            .filter(|(_, source)| source.extract_is_stale(instant))
            .map(|(source_id, _)| source_id.as_str())
            .collect()
    }

    /// List only the complete request shapes that the authenticated caller can
    /// currently invoke. Discovery performs no source access, credential
    /// resolution, signing, or evidence-data audit.
    pub async fn discover(
        &self,
        access_token: &str,
    ) -> Result<EvidenceDefinitions, RuntimeFailure> {
        let context = self
            .authenticator
            .authenticate(access_token)
            .await
            .map_err(|_| failure(ProblemCode::AuthenticationFailed, "authentication"))?;
        let rate_scope = rate_limit_scope(&self.bundle().config.service.trust_domain);
        let request_limit_key = self
            .audit
            .pseudonym("request-rate", &rate_scope, context.principal().as_bytes())
            .map_err(|_| failure(ProblemCode::ServiceUnavailable, "audit-pseudonym"))?;
        self.rate_limiter
            .check_request(&request_limit_key)
            .await
            .map_err(map_request_limit)?;

        let mut candidates = BTreeSet::new();
        for (_, authority) in self.bundle().config.authority_profiles.iter() {
            for grant in &authority.grants {
                let mut subjects = grant
                    .subjects
                    .iter()
                    .map(|subject| (subject.role.clone(), subject.selector_profile.clone()))
                    .collect::<Vec<_>>();
                subjects.sort();
                candidates.insert((grant.requirement.clone(), grant.purpose.clone(), subjects));
            }
        }

        let mut definitions = Vec::new();
        for (requirement, purpose, subjects) in candidates {
            // Discovery only probes the authorization boundary; this internal
            // request shape is never evaluated or released, so it carries the
            // fixed non-random placeholder nonce.
            let request = EvidenceRequest {
                request_nonce: crate::model::OFFLINE_EVALUATION_REQUEST_NONCE.to_owned(),
                requirement,
                purpose,
                subjects: subjects
                    .into_iter()
                    .map(|(role, profile)| RequestedSubject {
                        role,
                        selector: RequestedSelector {
                            profile,
                            values: None,
                        },
                    })
                    .collect(),
                holder_keys: Vec::new(),
            };
            let Ok(matched) = match_entitlement(self.bundle(), &request, &context) else {
                continue;
            };
            if validate_entitlement_context(self.bundle(), &context, &matched).is_err() {
                continue;
            }
            definitions.push(self.discovery_definition(&request, &matched)?);
        }
        let response = EvidenceDefinitions {
            schema: EVIDENCE_DEFINITIONS_SCHEMA_V1.to_owned(),
            assurance_profile: self.bundle().config.assurance_profile,
            issued_by: self.bundle().config.issuer.id.clone(),
            provided_by: self.bundle().config.service.provider_id.clone(),
            definitions,
        };
        let contract_value = serde_json::to_value(&response)
            .map_err(|_| failure(ProblemCode::ServiceUnavailable, "discovery-contract"))?;
        if !definitions_contract_accepts(&contract_value)
            .map_err(|_| failure(ProblemCode::ServiceUnavailable, "discovery-contract"))?
        {
            return Err(failure(
                ProblemCode::ServiceUnavailable,
                "discovery-contract",
            ));
        }
        Ok(response)
    }

    fn discovery_definition(
        &self,
        request: &EvidenceRequest,
        matched: &MatchedEntitlement,
    ) -> Result<EvidenceDefinition, RuntimeFailure> {
        let requirement = self
            .kernel
            .requirement(&request.requirement)
            .ok_or_else(|| failure(ProblemCode::ServiceUnavailable, "discovery-requirement"))?;
        let subjects = requirement
            .subject_roles
            .iter()
            .map(|role| {
                let granted = matched
                    .subjects()
                    .iter()
                    .find(|subject| subject.role == role.role)
                    .ok_or_else(|| failure(ProblemCode::ServiceUnavailable, "discovery-subject"))?;
                let profile = self
                    .bundle()
                    .config
                    .selector_profiles
                    .get(&granted.selector_profile)
                    .ok_or_else(|| {
                        failure(ProblemCode::ServiceUnavailable, "discovery-selector")
                    })?;
                let fields = profile
                    .fields
                    .iter()
                    .map(|(name, field)| self.discovery_selector_field(name, field))
                    .collect::<Result<Vec<_>, RuntimeFailure>>()?;
                Ok(EvidenceDefinitionSubject {
                    role: role.role.clone(),
                    cardinality: subject_cardinality_name(role.cardinality).to_owned(),
                    selector: EvidenceDefinitionSelector {
                        profile: granted.selector_profile.clone(),
                        value_origin: value_origin_name(granted.value_origin).to_owned(),
                        fields,
                    },
                })
            })
            .collect::<Result<Vec<_>, RuntimeFailure>>()?;
        let concepts = requirement
            .concepts
            .iter()
            .map(|concept| EvidenceDefinitionConcept {
                id: concept.id.clone(),
                form: concept_form_name(concept.form).to_owned(),
            })
            .collect();

        let configuration_revision = self
            .bundle()
            .configuration_revision(&requirement.id)
            .ok_or_else(|| failure(ProblemCode::ServiceUnavailable, "discovery-requirement"))?
            .to_owned();

        // The vocabulary carries no default: absence means audience-scoped, so
        // only the holder-bound mode is ever stated here.
        let subject_binding_mode = match requirement.subject_binding_mode() {
            SubjectBindingMode::AudienceScoped => None,
            SubjectBindingMode::HolderBound => Some(SubjectBindingMode::HolderBound),
        };

        Ok(EvidenceDefinition {
            requirement: requirement.id.clone(),
            configuration_revision,
            kind: requirement_kind_name(requirement.kind).to_owned(),
            subject_binding_mode,
            evidence_type: requirement.evidence_type.clone(),
            purpose: request.purpose.clone(),
            reference_frameworks: requirement.reference_frameworks.clone(),
            subjects,
            concepts,
        })
    }

    fn discovery_selector_field(
        &self,
        name: &str,
        field: &SelectorField,
    ) -> Result<EvidenceSelectorField, RuntimeFailure> {
        Ok(match field {
            SelectorField::String {
                minimum_bytes,
                maximum_bytes,
            } => EvidenceSelectorField::String {
                name: name.to_owned(),
                minimum_bytes: *minimum_bytes,
                maximum_bytes: *maximum_bytes,
            },
            SelectorField::Date => EvidenceSelectorField::Date {
                name: name.to_owned(),
            },
            SelectorField::Integer { minimum, maximum } => EvidenceSelectorField::Integer {
                name: name.to_owned(),
                minimum: *minimum,
                maximum: *maximum,
            },
            SelectorField::Boolean => EvidenceSelectorField::Boolean {
                name: name.to_owned(),
            },
            SelectorField::ControlledCode {
                codelist,
                codelist_version,
                maximum_bytes,
            } => {
                let list = self.bundle().codelist(codelist).ok_or_else(|| {
                    failure(ProblemCode::ServiceUnavailable, "discovery-codelist")
                })?;
                EvidenceSelectorField::ControlledCode {
                    name: name.to_owned(),
                    scheme: list.id().to_owned(),
                    version: codelist_version.clone(),
                    maximum_bytes: *maximum_bytes,
                }
            }
        })
    }

    /// Run the fixed authenticated signed-default path and return the JWS.
    ///
    /// This convenience wrapper deserializes the exact released bytes; the
    /// HTTP boundary uses [`EvidenceRuntime::evaluate_with_format`] so the
    /// bytes serialized before release audit are the bytes returned.
    pub async fn evaluate(
        &self,
        operation: &str,
        access_token: &str,
        request: &EvidenceRequest,
    ) -> Result<FlattenedJws, RuntimeFailure> {
        let released = self
            .evaluate_at(
                operation,
                access_token,
                request,
                ResponseFormat::SignedJws,
                None,
            )
            .await?;
        serde_json::from_slice(released.bytes())
            .map_err(|_| failure(ProblemCode::ServiceUnavailable, "release-serialization"))
    }

    /// Run the fixed authenticated path for one explicitly resolved response
    /// format through serialization and durable release audit.
    pub async fn evaluate_with_format(
        &self,
        operation: &str,
        access_token: &str,
        request: &EvidenceRequest,
        format: ResponseFormat,
    ) -> Result<ReleasedEvidence, RuntimeFailure> {
        self.evaluate_at(operation, access_token, request, format, None)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn evaluate_at_for_test(
        &self,
        operation: &str,
        access_token: &str,
        request: &EvidenceRequest,
        format: ResponseFormat,
        evaluation_time: chrono::DateTime<Utc>,
    ) -> Result<ReleasedEvidence, RuntimeFailure> {
        self.evaluate_at(
            operation,
            access_token,
            request,
            format,
            Some(evaluation_time),
        )
        .await
    }

    async fn evaluate_at(
        &self,
        operation: &str,
        access_token: &str,
        request: &EvidenceRequest,
        format: ResponseFormat,
        evaluation_time: Option<chrono::DateTime<Utc>>,
    ) -> Result<ReleasedEvidence, RuntimeFailure> {
        if operation.len() < 16
            || operation.len() > MAX_OPERATION_BYTES
            || operation.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(failure(ProblemCode::ServiceUnavailable, "operation-id"));
        }
        // The nonce is validated before authentication and never used again
        // until evidence construction echoes it.
        if !request_nonce_is_canonical(&request.request_nonce) {
            return Err(failure(ProblemCode::MalformedRequest, "request-nonce"));
        }
        // An unacceptable or repeated holder key fails before any credential
        // acquisition or source access. Keys are distinct by RFC 7638
        // thumbprint, so the same coordinates under a second key identifier or
        // a declared algorithm are one key wearing two names, and admitting
        // them would silently collapse a batch to fewer holders than the
        // caller asked for. Under a holder-bound requirement a thumbprint
        // scopes the subject binding of its own credential, which is what
        // carries it into authorization and selector resolution. Neither the
        // keys nor their thumbprints reach Rhai, sources, or audit.
        if request.holder_keys.len() > usize::from(MAXIMUM_HOLDER_BOUND_BATCH_SIZE) {
            return Err(failure(ProblemCode::MalformedRequest, "holder-keys"));
        }
        let mut presented_thumbprints = Vec::with_capacity(request.holder_keys.len());
        for key in &request.holder_keys {
            if !key.is_acceptable() {
                return Err(failure(ProblemCode::MalformedRequest, "holder-keys"));
            }
            let thumbprint = sdjwt_vc::holder_thumbprint(key)
                .map_err(|_| failure(ProblemCode::MalformedRequest, "holder-keys"))?;
            if presented_thumbprints.contains(&thumbprint) {
                return Err(failure(ProblemCode::MalformedRequest, "holder-keys"));
            }
            presented_thumbprints.push(thumbprint);
        }
        let started = Instant::now();
        // One evaluation reads one clock, once, here. Every later question that
        // needs the wall clock is answered from this instant: what a statement
        // source sees as the current time, whether an extract is too old to
        // answer from, and the instant the assertion says it was observed at.
        // Reading the clock again anywhere below would let those three disagree
        // by however long acquisition took.
        //
        // Truncated to the second here rather than where each answer is
        // rendered, because the assertion reports whole seconds and a statement
        // comparing the bound instant against stored text has to see the same
        // characters. Truncating once, at the single read, is what keeps the
        // three answers one instant rather than three roundings of it.
        let observed_at = evaluation_time.unwrap_or_else(Utc::now).trunc_subsecs(0);
        let context = self
            .authenticator
            .authenticate(access_token)
            .await
            .map_err(|_| failure(ProblemCode::AuthenticationFailed, "authentication"))?;
        let rate_scope = rate_limit_scope(&self.bundle().config.service.trust_domain);
        let request_limit_key = self
            .audit
            .pseudonym("request-rate", &rate_scope, context.principal().as_bytes())
            .map_err(|_| failure(ProblemCode::ServiceUnavailable, "audit-pseudonym"))?;
        // A batch release costs what the single-credential requests it replaces
        // would have cost, so one request for many keys buys no rate advantage
        // over many requests for one key each.
        let request_cost = u32::try_from(request.holder_keys.len().max(1))
            .map_err(|_| failure(ProblemCode::MalformedRequest, "holder-keys"))?;
        self.rate_limiter
            .check_request_cost(&request_limit_key, request_cost)
            .await
            .map_err(map_request_limit)?;

        // The configured binding mode of the named requirement, read from the
        // immutable bundle. An unknown requirement resolves to the mode every
        // requirement already had, and authorization below is what answers it.
        let binding_mode = self
            .bundle()
            .config
            .requirements
            .iter()
            .find(|requirement| requirement.id == request.requirement)
            .map_or(SubjectBindingMode::AudienceScoped, |requirement| {
                requirement.subject_binding_mode()
            });
        // A refusal is scoped to the relying party that asked, in both binding
        // modes. It can be written before any requirement has been matched, so
        // no declared mode is in scope when one is recorded, and an
        // audience-free refusal pseudonym would be a durable cross-audience
        // name for one denied principal: every relying party that refused it
        // would hold the same identifier.
        let refusal_scope = authorization_refusal_audit_scope(
            &self.bundle().config.service.trust_domain,
            &request.purpose,
            context.evidence_audience(),
        );
        let refusal_requester_pseudonym = self
            .audit
            .pseudonym("requester", &refusal_scope, context.principal().as_bytes())
            .map_err(|_| failure(ProblemCode::ServiceUnavailable, "audit-pseudonym"))?;
        let refusal_actor_pseudonym = context
            .actor()
            .map(|actor| {
                self.audit
                    .pseudonym("actor", &refusal_scope, actor.as_bytes())
            })
            .transpose()
            .map_err(|_| failure(ProblemCode::ServiceUnavailable, "audit-pseudonym"))?;

        let matched = match match_entitlement(self.bundle(), request, &context) {
            Ok(matched) => matched,
            Err(AuthorizationError::Unauthorized | AuthorizationError::AmbiguousAuthority) => {
                self.append_authorization_refusal(
                    operation,
                    refusal_requester_pseudonym,
                    refusal_actor_pseudonym,
                    started,
                )
                .await?;
                return Err(failure(ProblemCode::NotAuthorized, "authorization"));
            }
            Err(error) => return Err(map_authority(error)),
        };
        // The immutable bundle and the one complete matched grant must both
        // permit the requested format, that same grant must permit the
        // requirement's binding mode, and the mode must permit the format. API
        // selection creates no permission, and the one denial does not reveal
        // which of the four layers withheld it.
        if !self.bundle().config.response_formats.contains(&format)
            || !matched.permits_response_format(format)
            || !matched.permits_subject_binding(binding_mode)
            || !subject_binding_permits_response_format(binding_mode, format)
        {
            self.append_authorization_refusal(
                operation,
                refusal_requester_pseudonym,
                refusal_actor_pseudonym,
                started,
            )
            .await?;
            return Err(failure(ProblemCode::NotAuthorized, "response-format"));
        }
        // Only the batch container carries more than one credential, so every
        // other media type answers at most one presented key, in either binding
        // mode. Audience-scoped issuance still takes its key as optional, and
        // that key only reaches the confirmation claim, but a request naming
        // several keys asks for several credentials: serving the first and
        // dropping the rest would answer for one holder a question asked for
        // many, without saying so.
        //
        // A holder-bound requirement additionally derives every subject binding
        // under a presented key, so a request carrying none cannot be served,
        // and the batch it does serve stays under the ceiling the immutable
        // bundle declares.
        //
        // The checks sit after authorization and after the format gate on
        // purpose: answered earlier they would turn the endpoint into an
        // unauthenticated oracle for which requirements exist, which binding
        // mode each one carries, and how large a batch the deployment serves.
        let presented = request.holder_keys.len();
        if format != ResponseFormat::SdJwtVcBatch && presented > 1 {
            return Err(failure(ProblemCode::MalformedRequest, "holder-keys"));
        }
        if binding_mode == SubjectBindingMode::HolderBound
            && (presented == 0
                || presented > usize::from(self.bundle().config.holder_bound_batch_ceiling()))
        {
            return Err(failure(ProblemCode::MalformedRequest, "holder-keys"));
        }
        let selector_limit_input = canonical_pair(
            context.principal().as_bytes(),
            matched.authority_profile().as_bytes(),
        )
        .ok_or_else(|| failure(ProblemCode::ServiceUnavailable, "selector-rate-key"))?;
        let selector_limit_key = self
            .audit
            .pseudonym("selector-failure-rate", &rate_scope, &selector_limit_input)
            .map_err(|_| failure(ProblemCode::ServiceUnavailable, "audit-pseudonym"))?;
        self.rate_limiter
            .check_selector_failure_budget(&selector_limit_key)
            .await
            .map_err(map_selector_limit)?;
        let resolved = match resolve_selectors(self.bundle(), request, &context, &matched) {
            Ok(resolved) => resolved,
            Err(AuthorizationError::Unauthorized | AuthorizationError::AmbiguousAuthority) => {
                self.append_authorization_refusal(
                    operation,
                    refusal_requester_pseudonym,
                    refusal_actor_pseudonym,
                    started,
                )
                .await?;
                return Err(failure(ProblemCode::NotAuthorized, "authorization"));
            }
            Err(error) => {
                if error == AuthorizationError::Selector {
                    self.rate_limiter
                        .record_selector_failure(&selector_limit_key)
                        .await
                        .map_err(map_selector_limit)?;
                }
                return Err(map_authority(error));
            }
        };

        // A holder-bound operation is scoped to no relying party, so the audit
        // pseudonyms of what it releases cannot be derived under one. Its scope
        // names the trust domain and the purpose only, and never the holder
        // key. Under the audience-scoped mode this derivation repeats the
        // refusal one exactly, because a pseudonym is a keyed function of its
        // label, its scope, and its input.
        let issuance_scope = match binding_mode {
            SubjectBindingMode::AudienceScoped => audit_scope(
                &self.bundle().config.service.trust_domain,
                &request.purpose,
                context.evidence_audience(),
            ),
            SubjectBindingMode::HolderBound => audit_scope_holder_bound(
                &self.bundle().config.service.trust_domain,
                &request.purpose,
            ),
        };
        let requester_pseudonym = self
            .audit
            .pseudonym("requester", &issuance_scope, context.principal().as_bytes())
            .map_err(|_| failure(ProblemCode::ServiceUnavailable, "audit-pseudonym"))?;
        let actor_pseudonym = context
            .actor()
            .map(|actor| {
                self.audit
                    .pseudonym("actor", &issuance_scope, actor.as_bytes())
            })
            .transpose()
            .map_err(|_| failure(ProblemCode::ServiceUnavailable, "audit-pseudonym"))?;
        let material = self.audit_material(
            &issuance_scope,
            requester_pseudonym,
            actor_pseudonym,
            &resolved,
            format,
        )?;
        let requirement = self
            .kernel
            .requirement(&request.requirement)
            .ok_or_else(|| failure(ProblemCode::ServiceUnavailable, "requirement"))?;
        let acquisition = requirement.acquisition.clone();
        let empty_facts = BTreeMap::new();
        // The stages an acquisition executed, for the release event of the
        // forms that make more calls than the two scalars below can name. The
        // one and two stage forms leave it unset, because their scalars already
        // name every source they reached.
        let mut executed_stages: Option<(Vec<String>, Vec<String>)> = None;
        let (facts, source_id, adapter_id) = match acquisition {
            AcquisitionConfig::Single { source } => {
                let stage = self
                    .execute_source_stage(
                        &material,
                        operation,
                        &source,
                        &resolved,
                        &empty_facts,
                        None,
                        started,
                        observed_at,
                    )
                    .await?;
                match stage.lookup {
                    LookupResult::Match(facts) => (facts, stage.source_id, stage.adapter_id),
                    LookupResult::NoMatch => {
                        self.append_failure(
                            &material,
                            operation,
                            AuditDecision::NoMatch,
                            "no-match",
                            &stage.source_id,
                            &stage.adapter_id,
                            started,
                        )
                        .await?;
                        return Err(evidence_unavailable_failure());
                    }
                    LookupResult::Ambiguous => {
                        self.append_failure(
                            &material,
                            operation,
                            AuditDecision::Ambiguous,
                            "ambiguous",
                            &stage.source_id,
                            &stage.adapter_id,
                            started,
                        )
                        .await?;
                        return Err(evidence_unavailable_failure());
                    }
                }
            }
            AcquisitionConfig::SearchThenFetch { search, fetch } => {
                let search_stage = self
                    .execute_source_stage(
                        &material,
                        operation,
                        &search,
                        &resolved,
                        &empty_facts,
                        None,
                        started,
                        observed_at,
                    )
                    .await?;
                let search_facts = match search_stage.lookup {
                    LookupResult::Match(facts) => facts,
                    LookupResult::NoMatch => {
                        self.append_failure(
                            &material,
                            operation,
                            AuditDecision::NoMatch,
                            "no-match",
                            &search_stage.source_id,
                            &search_stage.adapter_id,
                            started,
                        )
                        .await?;
                        return Err(evidence_unavailable_failure());
                    }
                    LookupResult::Ambiguous => {
                        self.append_failure(
                            &material,
                            operation,
                            AuditDecision::Ambiguous,
                            "ambiguous",
                            &search_stage.source_id,
                            &search_stage.adapter_id,
                            started,
                        )
                        .await?;
                        return Err(evidence_unavailable_failure());
                    }
                };
                let fetch_stage = self
                    .execute_source_stage(
                        &material,
                        operation,
                        &fetch,
                        &resolved,
                        &search_facts,
                        None,
                        started,
                        observed_at,
                    )
                    .await?;
                match fetch_stage.lookup {
                    LookupResult::Match(facts) => {
                        (facts, fetch_stage.source_id, fetch_stage.adapter_id)
                    }
                    LookupResult::NoMatch | LookupResult::Ambiguous => {
                        // A unique search match that cannot be fetched through
                        // the fixed second source is a dependency inconsistency,
                        // not evidence that the subject is unresolved.
                        self.append_failure(
                            &material,
                            operation,
                            AuditDecision::DependencyFailure,
                            "fetch-result",
                            &fetch_stage.source_id,
                            &fetch_stage.adapter_id,
                            started,
                        )
                        .await?;
                        return Err(failure(ProblemCode::DependencyUnavailable, "fetch-result"));
                    }
                }
            }
            AcquisitionConfig::SearchThenFetchSet { .. } => {
                // The order this executes and the order adopter tooling prints
                // are read from one derivation, so neither can describe an
                // acquisition the other would not perform.
                let plan = requirement.acquisition.plan();
                // The declared budget covers the whole acquisition, so it is
                // fixed once, here, rather than per call. Every source keeps
                // its own request timeout as well: whichever ceiling is
                // reached first refuses, under its own category.
                let deadline = plan
                    .budget_milliseconds
                    .map(|budget| Instant::now() + Duration::from_millis(budget));
                let mut search_facts = BTreeMap::new();
                let mut merged: BTreeMap<String, Value> = BTreeMap::new();
                let mut source_ids: Vec<String> = Vec::new();
                let mut adapter_ids: Vec<String> = Vec::new();
                let mut last_stage: Option<(String, String)> = None;
                for stage in &plan.stages {
                    if let Some((source_id, adapter_id)) = last_stage.as_ref() {
                        if acquisition_budget_exhausted(deadline, Instant::now()) {
                            // A budget exhausted between stages names the last
                            // source this process actually reached. Naming the
                            // stage that was about to run would assert an
                            // access attempt against a source nothing ever
                            // contacted, which is an audit-integrity defect
                            // rather than a more precise diagnostic.
                            self.append_failure(
                                &material,
                                operation,
                                AuditDecision::DependencyFailure,
                                "acquisition-budget",
                                source_id,
                                adapter_id,
                                started,
                            )
                            .await?;
                            return Err(failure(
                                ProblemCode::DependencyUnavailable,
                                "acquisition-budget",
                            ));
                        }
                    }
                    // Each member reads only the search facts it declared, so
                    // a resolved reference reaches exactly the requests that
                    // named it and no others.
                    let stage_facts = stage.inputs.project(&search_facts);
                    let SourceStageOutcome {
                        lookup,
                        source_id,
                        adapter_id,
                    } = self
                        .execute_source_stage(
                            &material,
                            operation,
                            &stage.source,
                            &resolved,
                            &stage_facts,
                            deadline,
                            started,
                            observed_at,
                        )
                        .await?;
                    source_ids.push(source_id.clone());
                    adapter_ids.push(adapter_id.clone());
                    last_stage = Some((source_id.clone(), adapter_id.clone()));
                    match (stage.role, lookup) {
                        (StageRole::Search, LookupResult::Match(facts)) => {
                            search_facts.clone_from(&facts);
                            merged = facts;
                        }
                        (StageRole::Member, LookupResult::Match(facts)) => {
                            // The bundle proved every stage of this set
                            // declares disjoint fact names, so extending the
                            // union cannot overwrite an earlier stage's fact.
                            merged.extend(facts);
                        }
                        (StageRole::Search, LookupResult::NoMatch) => {
                            self.append_failure(
                                &material,
                                operation,
                                AuditDecision::NoMatch,
                                "no-match",
                                &source_id,
                                &adapter_id,
                                started,
                            )
                            .await?;
                            return Err(evidence_unavailable_failure());
                        }
                        (StageRole::Search, LookupResult::Ambiguous) => {
                            self.append_failure(
                                &material,
                                operation,
                                AuditDecision::Ambiguous,
                                "ambiguous",
                                &source_id,
                                &adapter_id,
                                started,
                            )
                            .await?;
                            return Err(evidence_unavailable_failure());
                        }
                        (StageRole::Member, LookupResult::NoMatch | LookupResult::Ambiguous) => {
                            // A unique search match a declared member cannot
                            // resolve is a dependency inconsistency, not
                            // evidence that the subject is unresolved. The
                            // acquisition stops here, so no later member's
                            // source is contacted at all.
                            self.append_failure(
                                &material,
                                operation,
                                AuditDecision::DependencyFailure,
                                "fetch-result",
                                &source_id,
                                &adapter_id,
                                started,
                            )
                            .await?;
                            return Err(failure(
                                ProblemCode::DependencyUnavailable,
                                "fetch-result",
                            ));
                        }
                    }
                }
                let (source_id, adapter_id) = last_stage
                    .ok_or_else(|| failure(ProblemCode::ServiceUnavailable, "source-plan"))?;
                // Each stage's extraction was bounded on its own, and the count
                // of declared facts is bounded when the bundle loads, but the
                // serialized size of the union is bounded by neither. The
                // derivation applies that bound to its own input, so reading it
                // here keeps the outcome a named acquisition refusal instead of
                // an unnamed script failure. Serializing the map is exactly
                // what the derivation serializes: both are sorted JSON objects
                // over the same entries.
                let merged_bytes = match serde_json::to_vec(&merged) {
                    Ok(bytes) => bytes.len(),
                    Err(_) => usize::MAX,
                };
                if merged_bytes > crate::rhai_runtime::MAXIMUM_RESULT_BYTES {
                    self.append_failure(
                        &material,
                        operation,
                        AuditDecision::EvaluationFailure,
                        "acquisition-fact-size",
                        &source_id,
                        &adapter_id,
                        started,
                    )
                    .await?;
                    return Err(failure(
                        ProblemCode::ServiceUnavailable,
                        "acquisition-fact-size",
                    ));
                }
                executed_stages = Some((source_ids, adapter_ids));
                (merged, source_id, adapter_id)
            }
        };
        let derivation_selectors =
            selector_input_value(&resolved, &requirement.derivation.selector_inputs)?;
        let values = match self.kernel.derive_and_validate_with_selectors(
            &request.requirement,
            &facts,
            &derivation_selectors,
            observed_at,
            ValueProjection {
                scope: evidence_scope(&resolved.subject_scope, &request.request_nonce),
                binding_key: self.subject_binding_secret.expose_secret(),
                binding_key_version: self.bundle().config.subject_binding.key_version,
            },
        ) {
            Ok(values) => values,
            Err(error) => {
                let category = kernel_failure_category(&error);
                let problem = kernel_failure_problem(&error);
                let decision = match error {
                    KernelError::Extraction | KernelError::DerivationInput => {
                        AuditDecision::FactMissing
                    }
                    KernelError::SourceProtocol => AuditDecision::DependencyFailure,
                    _ => AuditDecision::EvaluationFailure,
                };
                self.append_failure(
                    &material,
                    operation,
                    decision,
                    category,
                    &source_id,
                    &adapter_id,
                    started,
                )
                .await?;
                return Err(failure(problem, category));
            }
        };

        // One authorization decision, one acquisition, and one derivation feed
        // every released member. A holder-bound release constructs one member
        // per presented key, each scoped to that key alone, so no member can
        // carry another member's subject binding. Every other release is a
        // single member under the resolution's own scope.
        let member_scopes = match binding_mode {
            SubjectBindingMode::HolderBound => presented_thumbprints
                .into_iter()
                .map(ResolvedSubjectScope::HolderKeyThumbprint)
                .collect::<Vec<_>>(),
            SubjectBindingMode::AudienceScoped => vec![resolved.subject_scope.clone()],
        };
        // `issued_at` is read after the source round-trip, so a backward wall-clock
        // adjustment between it and `observed_at` could otherwise make `issued_at`
        // precede `observed_at` and fail evidence construction. Clamp the wall-clock
        // read so issuance never predates observation; an injected evaluation time
        // keeps both stamps equal.
        let issued_at = evaluation_time.unwrap_or_else(|| Utc::now().max(observed_at));
        let mut evidence_ids = Vec::with_capacity(member_scopes.len());
        let mut members = Vec::with_capacity(member_scopes.len());
        for member_scope in &member_scopes {
            let subjects = match self.subject_bindings(&resolved, member_scope) {
                Ok(subjects) => subjects,
                Err(error) => {
                    self.append_failure(
                        &material,
                        operation,
                        AuditDecision::EvaluationFailure,
                        "subject-binding",
                        &source_id,
                        &adapter_id,
                        started,
                    )
                    .await?;
                    return Err(error);
                }
            };
            let evidence_id = format!("urn:ulid:{}", ulid::Ulid::new());
            let evidence = match self.kernel.construct_evidence(
                &request.requirement,
                values.clone(),
                EvidenceConstruction {
                    evidence_id: &evidence_id,
                    purpose: &request.purpose,
                    scope: evidence_scope(member_scope, &request.request_nonce),
                    issued_at,
                    observed_at,
                    subjects,
                },
            ) {
                Ok(evidence) => evidence,
                Err(_) => {
                    self.append_failure(
                        &material,
                        operation,
                        AuditDecision::EvaluationFailure,
                        "evidence-construction",
                        &source_id,
                        &adapter_id,
                        started,
                    )
                    .await?;
                    return Err(failure(
                        ProblemCode::ServiceUnavailable,
                        "evidence-construction",
                    ));
                }
            };
            evidence_ids.push(evidence_id);
            members.push(evidence);
        }
        // Only the batch container transports more than one member. Reaching
        // here with any other count means the cardinality gate above did not
        // hold, so release nothing rather than serve a member the caller's
        // chosen serialization cannot describe.
        if members.is_empty()
            || (format != ResponseFormat::SdJwtVcBatch && members.len() != 1)
            || members.len() > usize::from(MAXIMUM_HOLDER_BOUND_BATCH_SIZE)
        {
            self.append_failure(
                &material,
                operation,
                AuditDecision::EvaluationFailure,
                "release-cardinality",
                &source_id,
                &adapter_id,
                started,
            )
            .await?;
            return Err(failure(
                ProblemCode::ServiceUnavailable,
                "release-cardinality",
            ));
        }
        // Every member of one release carries the same derivation, so the
        // disclosed concept list is a property of the release and not of a
        // member.
        let disclosed_concepts = members[0]
            .supported_values
            .iter()
            .map(|value| value.provides_value_for.clone())
            .collect::<Vec<_>>();

        // Serialize the final immutable response bytes before the durable
        // disclosure-release audit; the released bytes are exactly these. A
        // signed-path failure never downgrades to unsigned output.
        let (bytes, media_type, signing_key_id) = match format {
            ResponseFormat::SignedJws => {
                let signed = match self.signer.sign_json(&members[0]).await {
                    Ok(signed) => signed,
                    Err(_) => {
                        self.append_failure(
                            &material,
                            operation,
                            AuditDecision::SigningFailure,
                            "signing",
                            &source_id,
                            &adapter_id,
                            started,
                        )
                        .await?;
                        return Err(failure(ProblemCode::ServiceUnavailable, "signing"));
                    }
                };
                let bytes = serde_json::to_vec(&signed)
                    .map_err(|_| failure(ProblemCode::ServiceUnavailable, "release-serialization"));
                let bytes = match bytes {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        // Serialization of the already-signed artifact failed;
                        // record it with the same decision as the unsigned path
                        // so the audit taxonomy for release-serialization is one
                        // class regardless of format.
                        self.append_failure(
                            &material,
                            operation,
                            AuditDecision::EvaluationFailure,
                            "release-serialization",
                            &source_id,
                            &adapter_id,
                            started,
                        )
                        .await?;
                        return Err(error);
                    }
                };
                (
                    bytes,
                    EVIDENCE_JWS_MEDIA_TYPE,
                    Some(self.signer.key_id().to_owned()),
                )
            }
            ResponseFormat::SdJwtVc => {
                // The projection re-encodes the constructed payload and
                // re-derives nothing.
                let structured_projections = self.structured_projections(&request.requirement)?;
                let input = match sdjwt_vc::issuance_input(
                    &members[0],
                    request.holder_keys.first(),
                    &structured_projections,
                ) {
                    Ok(input) => input,
                    Err(_) => {
                        self.append_failure(
                            &material,
                            operation,
                            AuditDecision::EvaluationFailure,
                            "sd-jwt-vc-mapping",
                            &source_id,
                            &adapter_id,
                            started,
                        )
                        .await?;
                        return Err(failure(
                            ProblemCode::ServiceUnavailable,
                            "sd-jwt-vc-mapping",
                        ));
                    }
                };
                // A signing failure is a safe 503. It never falls back to the
                // signed-JWS or unsigned format.
                let serialized = match self.signer.sign_sd_jwt_vc(input).await {
                    Ok(serialized) => serialized,
                    Err(_) => {
                        self.append_failure(
                            &material,
                            operation,
                            AuditDecision::SigningFailure,
                            "signing",
                            &source_id,
                            &adapter_id,
                            started,
                        )
                        .await?;
                        return Err(failure(ProblemCode::ServiceUnavailable, "signing"));
                    }
                };
                (
                    serialized.into_bytes(),
                    EVIDENCE_SD_JWT_VC_MEDIA_TYPE,
                    Some(self.signer.key_id().to_owned()),
                )
            }
            ResponseFormat::SdJwtVcBatch => {
                let structured_projections = self.structured_projections(&request.requirement)?;
                // Each member maps and signs on its own, so each carries its own
                // confirmation, its own identifier, and independent disclosure
                // salts. A failure on any member releases nothing: the container
                // is assembled in full before the durable release, and there is
                // no partial batch and no per-member fallback.
                let mut credentials = Vec::with_capacity(members.len());
                for (member, holder_key) in members.iter().zip(request.holder_keys.iter()) {
                    let input = match sdjwt_vc::issuance_input(
                        member,
                        Some(holder_key),
                        &structured_projections,
                    ) {
                        Ok(input) => input,
                        Err(_) => {
                            self.append_failure(
                                &material,
                                operation,
                                AuditDecision::EvaluationFailure,
                                "sd-jwt-vc-mapping",
                                &source_id,
                                &adapter_id,
                                started,
                            )
                            .await?;
                            return Err(failure(
                                ProblemCode::ServiceUnavailable,
                                "sd-jwt-vc-mapping",
                            ));
                        }
                    };
                    match self.signer.sign_sd_jwt_vc(input).await {
                        Ok(serialized) => credentials.push(serialized),
                        Err(_) => {
                            self.append_failure(
                                &material,
                                operation,
                                AuditDecision::SigningFailure,
                                "signing",
                                &source_id,
                                &adapter_id,
                                started,
                            )
                            .await?;
                            return Err(failure(ProblemCode::ServiceUnavailable, "signing"));
                        }
                    }
                }
                let envelope = SdJwtVcBatchEnvelope {
                    schema: SD_JWT_VC_BATCH_SCHEMA_V1.to_owned(),
                    envelope_type: SdJwtVcBatchEnvelopeType::SdJwtVcBatchEnvelope,
                    credentials,
                };
                // A batch multiplies one assertion by its member count, so the
                // response carries its own size bound. An oversized release is
                // refused rather than truncated.
                let bytes = serde_json::to_vec(&envelope)
                    .ok()
                    .filter(|bytes| bytes.len() <= MAX_SD_JWT_VC_BATCH_RESPONSE_BYTES);
                let Some(bytes) = bytes else {
                    self.append_failure(
                        &material,
                        operation,
                        AuditDecision::EvaluationFailure,
                        "release-serialization",
                        &source_id,
                        &adapter_id,
                        started,
                    )
                    .await?;
                    return Err(failure(
                        ProblemCode::ServiceUnavailable,
                        "release-serialization",
                    ));
                };
                (
                    bytes,
                    EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE,
                    Some(self.signer.key_id().to_owned()),
                )
            }
            ResponseFormat::UnsignedJson => {
                // Unsigned output is never a recovery or fallback path for a
                // failed signer. Signed requests still attempt the provider,
                // which lets a recovered Transit dependency return to Ready.
                if !self.signer.ready() {
                    self.append_failure(
                        &material,
                        operation,
                        AuditDecision::SigningFailure,
                        "signing",
                        &source_id,
                        &adapter_id,
                        started,
                    )
                    .await?;
                    return Err(failure(ProblemCode::ServiceUnavailable, "signing"));
                }
                let envelope = UnsignedEvidenceEnvelope {
                    schema: EVIDENCE_UNSIGNED_ENVELOPE_SCHEMA_V1.to_owned(),
                    envelope_type: UnsignedEnvelopeType::UnsignedEvidenceEnvelope,
                    integrity_protection: UnsignedIntegrityProtection::None,
                    warning: UnsignedEnvelopeWarning::NotCryptographicallyVerifiable,
                    evidence: members.swap_remove(0),
                };
                let bytes = serde_json::to_vec(&envelope)
                    .map_err(|_| failure(ProblemCode::ServiceUnavailable, "release-serialization"));
                let bytes = match bytes {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        self.append_failure(
                            &material,
                            operation,
                            AuditDecision::EvaluationFailure,
                            "release-serialization",
                            &source_id,
                            &adapter_id,
                            started,
                        )
                        .await?;
                        return Err(error);
                    }
                };
                (bytes, EVIDENCE_UNSIGNED_MEDIA_TYPE, None)
            }
        };

        let mut release = material.event(
            operation,
            AuditPhase::DisclosureRelease,
            AuditDecision::Released,
            elapsed_millis(started),
        );
        release.source_id = Some(source_id);
        release.adapter_id = Some(adapter_id);
        if let Some((source_ids, adapter_ids)) = executed_stages {
            release.source_ids = Some(source_ids);
            release.adapter_ids = Some(adapter_ids);
        }
        release.disclosed_concepts = Some(disclosed_concepts);
        // Exactly one terminal release event names the complete released set.
        // A release of one assertion keeps the singular member every release
        // already carried, so a reader never counts one release twice. Per
        // member events are not emitted: a failed append after an earlier one
        // would leave a durable record describing a credential that was never
        // released.
        if evidence_ids.len() == 1 {
            release.evidence_id = evidence_ids.pop();
        } else {
            release.evidence_ids = Some(evidence_ids);
        }
        release.signing_key_id = signing_key_id;
        self.audit
            .append(release)
            .await
            .map_err(|_| failure(ProblemCode::ServiceUnavailable, "release-audit"))?;
        Ok(ReleasedEvidence {
            format,
            media_type,
            bytes,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_source_stage(
        &self,
        material: &AuditMaterial,
        operation: &str,
        source_id: &str,
        resolved: &ResolvedAuthorization,
        prior_facts: &BTreeMap<String, Value>,
        deadline: Option<Instant>,
        started: Instant,
        observed_at: chrono::DateTime<Utc>,
    ) -> Result<SourceStageOutcome, RuntimeFailure> {
        let (source_id, adapter_id) = self.source_identity(source_id)?;
        // Every actual evidence-data call has its own durable access event,
        // written before preparation can acquire credentials or start I/O.
        let mut access_event = material.event(
            operation,
            AuditPhase::AccessAttempt,
            AuditDecision::Authorized,
            elapsed_millis(started),
        );
        access_event.source_id = Some(source_id.clone());
        access_event.adapter_id = Some(adapter_id.clone());
        self.audit
            .append(access_event)
            .await
            .map_err(|_| failure(ProblemCode::ServiceUnavailable, "access-audit"))?;

        let executor = self
            .sources
            .get(&source_id)
            .ok_or_else(|| failure(ProblemCode::ServiceUnavailable, "source-plan"))?;
        let source = self
            .bundle()
            .config
            .sources
            .get(&source_id)
            .ok_or_else(|| failure(ProblemCode::ServiceUnavailable, "source-plan"))?;
        let preparation_selector_value =
            source_selector_input_value(resolved, source.selector_inputs())?;
        let selectors = source_selectors(resolved, source.selector_inputs())?;
        let request =
            match self
                .kernel
                .prepare_source(&source_id, &preparation_selector_value, prior_facts)
            {
                Ok(prepared) => prepared,
                Err(error) => {
                    let category = kernel_failure_category(&error);
                    self.append_failure(
                        material,
                        operation,
                        AuditDecision::EvaluationFailure,
                        category,
                        &source_id,
                        &adapter_id,
                        started,
                    )
                    .await?;
                    return Err(failure(kernel_failure_problem(&error), category));
                }
            };
        // Only the source round-trip is bounded by the acquisition deadline.
        // `SourceExecutor::execute_with_prior_facts` mutates nothing before the
        // awaited send, so abandoning it abandons an in-flight request and
        // nothing else.
        //
        // No audit append is ever wrapped. The segmented JSONL sink poisons
        // itself on a durable-write error, not on cancellation: cancelling a
        // task inside its flush, after the buffered lines were taken, silently
        // drops already-hashed lines with no poison at all, leaving a chain
        // that no longer matches its tail hash while the service keeps serving.
        // That silent audit-integrity break is worse than a refusal, and it is
        // why the timeout never crosses an append.
        let execution =
            executor.execute_with_prior_facts(&selectors, prior_facts, &request, observed_at);
        let executed = match deadline {
            Some(deadline) => {
                // A ceiling already spent by the durable append above, or by
                // preparation, is answered before the source future is polled
                // at all; see `stage_time_budget`.
                let bounded = match stage_time_budget(deadline, Instant::now()) {
                    Some(remaining) => tokio::time::timeout(remaining, execution).await.ok(),
                    None => None,
                };
                match bounded {
                    Some(executed) => executed,
                    None => {
                        self.append_failure(
                            material,
                            operation,
                            AuditDecision::DependencyFailure,
                            "acquisition-budget",
                            &source_id,
                            &adapter_id,
                            started,
                        )
                        .await?;
                        return Err(failure(
                            ProblemCode::DependencyUnavailable,
                            "acquisition-budget",
                        ));
                    }
                }
            }
            None => execution.await,
        };
        let source_response = match executed {
            Ok(response) => response,
            Err(error) => {
                let category = source_failure_category(&error);
                self.append_failure(
                    material,
                    operation,
                    AuditDecision::DependencyFailure,
                    category,
                    &source_id,
                    &adapter_id,
                    started,
                )
                .await?;
                return Err(failure(source_failure_problem(&error), category));
            }
        };
        let lookup = match self
            .kernel
            .extract_source(&source_id, &source_response, prior_facts)
        {
            Ok(lookup) => lookup,
            Err(error) => {
                let category = kernel_failure_category(&error);
                let problem = kernel_failure_problem(&error);
                let decision = match error {
                    KernelError::Extraction | KernelError::DerivationInput => {
                        AuditDecision::FactMissing
                    }
                    KernelError::SourceProtocol => AuditDecision::DependencyFailure,
                    _ => AuditDecision::EvaluationFailure,
                };
                self.append_failure(
                    material,
                    operation,
                    decision,
                    category,
                    &source_id,
                    &adapter_id,
                    started,
                )
                .await?;
                return Err(failure(problem, category));
            }
        };

        Ok(SourceStageOutcome {
            lookup,
            source_id,
            adapter_id,
        })
    }

    fn source_identity(&self, source_id: &str) -> Result<(String, String), RuntimeFailure> {
        let source = self
            .bundle()
            .config
            .sources
            .get(source_id)
            .ok_or_else(|| failure(ProblemCode::ServiceUnavailable, "source-plan"))?;
        let adapter_id = Path::new(source.extract_script().as_str())
            .file_stem()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty() && name.len() <= 128)
            .ok_or_else(|| failure(ProblemCode::ServiceUnavailable, "adapter-id"))?;
        Ok((source_id.to_owned(), adapter_id.to_owned()))
    }

    fn audit_material(
        &self,
        scope: &str,
        requester_pseudonym: String,
        actor_pseudonym: Option<String>,
        resolved: &ResolvedAuthorization,
        format: ResponseFormat,
    ) -> Result<AuditMaterial, RuntimeFailure> {
        let grant_pseudonym = resolved
            .grant_id
            .as_deref()
            .map(|grant| self.audit.pseudonym("grant", scope, grant.as_bytes()))
            .transpose()
            .map_err(|_| failure(ProblemCode::ServiceUnavailable, "audit-pseudonym"))?;
        let subjects = resolved
            .subjects
            .iter()
            .map(|subject| {
                let protected = subject
                    .audit_pseudonym_input(&resolved.subject_scope, &resolved.purpose)
                    .map_err(|_| failure(ProblemCode::ServiceUnavailable, "subject-pseudonym"))?;
                let pseudonym = self
                    .audit
                    .pseudonym("subject-selector-bundle", scope, &protected)
                    .map_err(|_| failure(ProblemCode::ServiceUnavailable, "audit-pseudonym"))?;
                Ok(AuditSubject {
                    role: subject.role.clone(),
                    selector_profile: subject.selector_profile.clone(),
                    selector_bundle_pseudonym: Some(pseudonym),
                })
            })
            .collect::<Result<Vec<_>, RuntimeFailure>>()?;
        Ok(AuditMaterial {
            assurance_profile: self.bundle().config.assurance_profile,
            requirement: resolved.requirement.clone(),
            bundle_revision: self.bundle().revision().to_owned(),
            purpose: resolved.purpose.clone(),
            requester_pseudonym,
            actor_pseudonym,
            authority: AuditAuthority {
                kind: map_authority_kind(resolved.authority_kind),
                grant_pseudonym,
            },
            subjects,
            response_protection: map_response_protection(format),
        })
    }

    async fn append_authorization_refusal(
        &self,
        operation: &str,
        requester_pseudonym: String,
        actor_pseudonym: Option<String>,
        started: Instant,
    ) -> Result<(), RuntimeFailure> {
        let mut event = EvidenceAuthorizationRefusalAuditEvent::new(
            self.bundle().config.assurance_profile,
            operation.to_owned(),
            self.bundle().revision().to_owned(),
            requester_pseudonym,
            elapsed_millis(started),
        );
        event.actor_pseudonym = actor_pseudonym;
        self.audit
            .append_authorization_refusal(event)
            .await
            .map(|_| ())
            .map_err(|_| {
                failure(
                    ProblemCode::ServiceUnavailable,
                    "authorization-refusal-audit",
                )
            })
    }

    /// The claim each concept of one requirement projects into an SD-JWT VC.
    ///
    /// The projection re-encodes the constructed payload and re-derives
    /// nothing, so every member of one release shares it.
    fn structured_projections(
        &self,
        requirement_id: &str,
    ) -> Result<BTreeMap<String, String>, RuntimeFailure> {
        Ok(self
            .kernel
            .requirement(requirement_id)
            .ok_or_else(|| failure(ProblemCode::ServiceUnavailable, "sd-jwt-vc-mapping"))?
            .concepts
            .iter()
            .filter_map(|concept| {
                concept
                    .sd_jwt_vc
                    .as_ref()
                    .map(|projection| (concept.id.clone(), projection.claim.clone()))
            })
            .collect())
    }

    /// The subject bindings one released member carries, under the one scope
    /// that member is issued to.
    fn subject_bindings(
        &self,
        resolved: &ResolvedAuthorization,
        subject_scope: &ResolvedSubjectScope,
    ) -> Result<Vec<SubjectBinding>, RuntimeFailure> {
        resolved
            .subjects
            .iter()
            .map(|subject| {
                subject
                    .binding(
                        self.subject_binding_secret.expose_secret(),
                        self.bundle().config.subject_binding.key_version,
                        &self.bundle().config.service.trust_domain,
                        subject_scope.as_binding_scope(),
                        &resolved.purpose,
                    )
                    .map(|binding| SubjectBinding {
                        role: subject.role.clone(),
                        binding,
                    })
                    .map_err(|_| failure(ProblemCode::ServiceUnavailable, "subject-binding"))
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    async fn append_failure(
        &self,
        material: &AuditMaterial,
        operation: &str,
        decision: AuditDecision,
        category: &'static str,
        source_id: &str,
        adapter_id: &str,
        started: Instant,
    ) -> Result<(), RuntimeFailure> {
        let phase = match decision {
            AuditDecision::NoMatch | AuditDecision::Ambiguous | AuditDecision::FactMissing => {
                AuditPhase::Denial
            }
            _ => AuditPhase::TransientFailure,
        };
        let mut event = material.event(operation, phase, decision, elapsed_millis(started));
        event.source_id = Some(source_id.to_owned());
        event.adapter_id = Some(adapter_id.to_owned());
        event.safe_error_category = Some(category.to_owned());
        self.audit
            .append(event)
            .await
            .map(|_| ())
            .map_err(|_| failure(ProblemCode::ServiceUnavailable, "failure-audit"))
    }
}

struct SourceStageOutcome {
    lookup: LookupResult,
    source_id: String,
    adapter_id: String,
}

struct AuditMaterial {
    assurance_profile: AssuranceProfile,
    requirement: String,
    bundle_revision: String,
    purpose: String,
    requester_pseudonym: String,
    actor_pseudonym: Option<String>,
    authority: AuditAuthority,
    subjects: Vec<AuditSubject>,
    response_protection: ResponseProtection,
}

impl AuditMaterial {
    fn event(
        &self,
        operation: &str,
        phase: AuditPhase,
        decision: AuditDecision,
        duration_milliseconds: u64,
    ) -> EvidenceAuditEvent {
        let mut event = EvidenceAuditEvent::new(
            self.assurance_profile,
            operation.to_owned(),
            phase,
            self.requirement.clone(),
            self.bundle_revision.clone(),
            self.purpose.clone(),
            self.requester_pseudonym.clone(),
            self.authority.clone(),
            self.subjects.clone(),
            self.response_protection,
            decision,
            duration_milliseconds,
        );
        event.actor_pseudonym = self.actor_pseudonym.clone();
        event
    }
}

/// How long one source round-trip may still run, or `None` once the
/// acquisition ceiling is spent.
///
/// `tokio::time::timeout` polls the future it wraps before it consults its
/// timer, so handing it a zero remainder is not a refusal: the wrapped
/// execution is polled once, which is enough to acquire a credential and put an
/// evidence-data request on the wire, and only then is it abandoned. The
/// ceiling bounds when a request may leave the process, so a spent one has to
/// be answered before the future is polled at all. The stage's durable
/// access-attempt append and its preparation script both run after the
/// deadline was computed, so a remainder of zero is reachable on any stage,
/// including the first, where no between-stage guard precedes it.
fn stage_time_budget(deadline: Instant, now: Instant) -> Option<Duration> {
    let remaining = deadline.saturating_duration_since(now);
    (!remaining.is_zero()).then_some(remaining)
}

/// The assertion scope a resolved authorization issues under.
///
/// A holder-bound resolution names no relying party, so its assertion carries
/// neither an audience nor a request nonce: there is no verifier to echo the
/// nonce to, and freshness at presentation is the relying party's own
/// key-binding challenge. Deriving this from the resolved subject scope rather
/// than from the authenticated context is what keeps the declared binding mode
/// in agreement with the bindings the subjects actually carry.
fn evidence_scope<'a>(
    subject_scope: &'a ResolvedSubjectScope,
    request_nonce: &'a str,
) -> EvidenceScope<'a> {
    match subject_scope.audience() {
        Some(audience) => EvidenceScope::AudienceScoped {
            audience,
            request_nonce,
        },
        None => EvidenceScope::HolderBound,
    }
}

fn map_response_protection(format: ResponseFormat) -> ResponseProtection {
    match format {
        ResponseFormat::SignedJws => ResponseProtection::Signed,
        ResponseFormat::UnsignedJson => ResponseProtection::Unsigned,
        ResponseFormat::SdJwtVc | ResponseFormat::SdJwtVcBatch => ResponseProtection::SdJwtVc,
    }
}

fn source_selectors(
    resolved: &ResolvedAuthorization,
    inputs: &[SelectorInput],
) -> Result<Vec<ResolvedSourceSelector>, RuntimeFailure> {
    inputs
        .iter()
        .map(|input| {
            let Some(subject) = resolved
                .subjects
                .iter()
                .find(|subject| subject.role == input.role)
            else {
                return Ok(None);
            };
            let alternative = input
                .alternatives
                .iter()
                .find(|alternative| alternative.profile == subject.selector_profile)
                .ok_or_else(selector_contract_failure)?;
            let values = alternative
                .fields
                .iter()
                .map(|name| {
                    let field = subject
                        .fields
                        .iter()
                        .find(|field| &field.name == name)
                        .ok_or_else(selector_contract_failure)?;
                    let value = match &field.value {
                        ResolvedSelectorValue::String(value)
                        | ResolvedSelectorValue::Date(value)
                        | ResolvedSelectorValue::ControlledCode(value) => {
                            SelectorValue::String(value.clone())
                        }
                        ResolvedSelectorValue::Integer(value) => SelectorValue::Integer(*value),
                        ResolvedSelectorValue::Boolean(value) => SelectorValue::Boolean(*value),
                    };
                    Ok((name.clone(), value))
                })
                .collect::<Result<BTreeMap<_, _>, RuntimeFailure>>()?;
            Ok(Some(ResolvedSourceSelector {
                role: input.role.clone(),
                profile: alternative.profile.clone(),
                values,
            }))
        })
        .collect::<Result<Vec<_>, RuntimeFailure>>()
        .map(|selectors| selectors.into_iter().flatten().collect())
}

fn source_selector_input_value(
    resolved: &ResolvedAuthorization,
    inputs: &[SelectorInput],
) -> Result<Value, RuntimeFailure> {
    if inputs.is_empty() {
        return Ok(Value::Object(JsonMap::new()));
    }
    let active = inputs
        .iter()
        .filter(|input| {
            resolved
                .subjects
                .iter()
                .any(|subject| subject.role == input.role)
        })
        .cloned()
        .collect::<Vec<_>>();
    if active.is_empty() {
        return Err(selector_contract_failure());
    }
    selector_input_value(resolved, &active)
}

fn selector_input_value(
    resolved: &ResolvedAuthorization,
    inputs: &[SelectorInput],
) -> Result<Value, RuntimeFailure> {
    let mut selectors = JsonMap::new();
    for input in inputs {
        let (subject, alternative) = selector_input_subject(resolved, input)?;
        let mut values = JsonMap::new();
        for name in &alternative.fields {
            let field = subject
                .fields
                .iter()
                .find(|field| &field.name == name)
                .ok_or_else(selector_contract_failure)?;
            values.insert(name.clone(), field.value.as_json());
        }
        let mut selector = JsonMap::new();
        selector.insert(
            "profile".to_owned(),
            Value::String(alternative.profile.clone()),
        );
        selector.insert("values".to_owned(), Value::Object(values));
        if selectors
            .insert(input.role.clone(), Value::Object(selector))
            .is_some()
        {
            return Err(selector_contract_failure());
        }
    }
    Ok(Value::Object(selectors))
}

fn selector_input_subject<'a>(
    resolved: &'a ResolvedAuthorization,
    input: &'a SelectorInput,
) -> Result<
    (
        &'a crate::selector::ResolvedSubject,
        &'a crate::config::SelectorInputAlternative,
    ),
    RuntimeFailure,
> {
    let subject = resolved
        .subjects
        .iter()
        .find(|subject| subject.role == input.role)
        .ok_or_else(selector_contract_failure)?;
    let alternative = input
        .alternatives
        .iter()
        .find(|alternative| alternative.profile == subject.selector_profile)
        .ok_or_else(selector_contract_failure)?;
    Ok((subject, alternative))
}

fn selector_contract_failure() -> RuntimeFailure {
    failure(ProblemCode::ServiceUnavailable, "selector-contract")
}

fn failure(problem: ProblemCode, category: &'static str) -> RuntimeFailure {
    RuntimeFailure { problem, category }
}

fn evidence_unavailable_failure() -> RuntimeFailure {
    failure(ProblemCode::EvidenceNotAvailable, "evidence-unavailable")
}

fn map_authority(error: AuthorizationError) -> RuntimeFailure {
    match error {
        AuthorizationError::Selector => failure(ProblemCode::InvalidSelector, "selector"),
        AuthorizationError::Unauthorized | AuthorizationError::AmbiguousAuthority => {
            failure(ProblemCode::NotAuthorized, "authorization")
        }
        AuthorizationError::Binding => failure(ProblemCode::ServiceUnavailable, "subject-binding"),
    }
}

fn map_request_limit(error: RateLimitError) -> RuntimeFailure {
    match error {
        RateLimitError::RequestExceeded => failure(ProblemCode::RateLimited, "request-rate"),
        _ => failure(ProblemCode::ServiceUnavailable, "request-rate"),
    }
}

fn map_selector_limit(error: RateLimitError) -> RuntimeFailure {
    match error {
        RateLimitError::FailedSelectorExceeded => {
            failure(ProblemCode::RateLimited, "selector-rate")
        }
        _ => failure(ProblemCode::ServiceUnavailable, "selector-rate"),
    }
}

/// Whether a declared acquisition budget is spent before the next stage is
/// entered.
///
/// Read between stages rather than only inside one, because a stage entered
/// with nothing left would still poll its request once before abandoning it,
/// and one poll is enough to contact a source the budget no longer covers. The
/// forms that declare no budget bound each call on its own, so no instant
/// exhausts an acquisition they never bounded.
pub(crate) fn acquisition_budget_exhausted(deadline: Option<Instant>, now: Instant) -> bool {
    deadline.is_some_and(|deadline| now >= deadline)
}

fn source_failure_category(error: &SourceError) -> &'static str {
    match error {
        SourceError::Credential => "source-credential",
        SourceError::Concurrency => "source-concurrency",
        SourceError::Timeout => "source-timeout",
        SourceError::Redirect => "source-redirect",
        SourceError::Status(_) => "source-status",
        SourceError::WrongMediaType => "source-media-type",
        SourceError::ResponseTooLarge => "source-response-size",
        SourceError::InvalidJson
        | SourceError::ErrorEnvelope
        | SourceError::ProjectionViolation => "source-protocol",
        SourceError::InvalidPlan | SourceError::InvalidSelectors | SourceError::Transport => {
            "source-unavailable"
        }
        // A statement source has more than one way to fail and each one has a
        // different fix: mount the file, refresh it, correct the statement,
        // correct the parameters, raise a budget, or bring the result back
        // inside its declared contract. One shared label would tell an operator
        // only that something is wrong somewhere.
        SourceError::ExtractUnavailable(_) => "source-extract-unavailable",
        SourceError::ExtractTooOld(_) => "source-extract-stale",
        SourceError::StatementRefused(_) => "source-statement-refused",
        SourceError::StatementParameter(_) => "source-statement-parameter",
        SourceError::StatementBudget(_) => "source-statement-budget",
        SourceError::StatementResult(_) => "source-statement-result",
        SourceError::StatementUnavailable => "source-statement-unavailable",
    }
}

/// Map a closed source-boundary failure to its public problem class.
///
/// The offline fixture command uses this same function, so its symbolic
/// failure cases cannot drift from the production release pipeline.
///
/// Every source failure, on either transport, is one dependency this
/// deployment could not read. A statement source names a file rather than a
/// host, but the relying party's position is the same and the extra shape a
/// statement could carry is exactly the shape that would tell a caller
/// something about the extract's contents. The acting detail lives in the
/// audit category and, for the deployment path, in the artifact fault.
pub fn source_failure_problem(_error: &SourceError) -> ProblemCode {
    ProblemCode::DependencyUnavailable
}

fn kernel_failure_category(error: &KernelError) -> &'static str {
    match error {
        KernelError::Preparation => "request-preparation",
        KernelError::Extraction => "fact-unavailable",
        KernelError::DerivationInput => "derivation-input",
        KernelError::SourceProtocol => "source-protocol",
        KernelError::Script => "script-failure",
        KernelError::Output => "output-gate",
        KernelError::Bundle
        | KernelError::Artifact(_)
        | KernelError::Requirement
        | KernelError::Evidence => "kernel",
    }
}

/// Map a closed kernel failure to its public problem class. The unresolved
/// classes, including derivation-input inconsistency over a uniquely found
/// record, collapse to one public shape so status codes cannot become an
/// existence oracle. Native audit keeps only a value-free category.
fn kernel_failure_problem(error: &KernelError) -> ProblemCode {
    match error {
        KernelError::Preparation => ProblemCode::ServiceUnavailable,
        KernelError::Extraction | KernelError::DerivationInput => ProblemCode::EvidenceNotAvailable,
        KernelError::SourceProtocol => ProblemCode::DependencyUnavailable,
        KernelError::Script
        | KernelError::Output
        | KernelError::Bundle
        | KernelError::Artifact(_)
        | KernelError::Requirement
        | KernelError::Evidence => ProblemCode::ServiceUnavailable,
    }
}

fn map_authority_kind(kind: AuthorityKind) -> AuditAuthorityKind {
    match kind {
        AuthorityKind::Statutory => AuditAuthorityKind::Statutory,
        AuthorityKind::Organizational => AuditAuthorityKind::Organizational,
        AuthorityKind::Consent => AuditAuthorityKind::Consent,
        AuthorityKind::Delegated => AuditAuthorityKind::Delegated,
        AuthorityKind::ExplicitRequest => AuditAuthorityKind::ExplicitRequest,
    }
}

fn requirement_kind_name(kind: RequirementKind) -> &'static str {
    match kind {
        RequirementKind::Criterion => "criterion",
        RequirementKind::InformationRequirement => "information-requirement",
        RequirementKind::Constraint => "constraint",
    }
}

fn subject_cardinality_name(cardinality: SubjectCardinality) -> &'static str {
    match cardinality {
        SubjectCardinality::One => "one",
    }
}

fn value_origin_name(origin: ValueOrigin) -> &'static str {
    match origin {
        ValueOrigin::AuthenticatedContext => "authenticated-context",
        ValueOrigin::AuthenticatedGrant => "authenticated-grant",
        ValueOrigin::Request => "request",
    }
}

fn concept_form_name(form: ConceptForm) -> &'static str {
    match form {
        ConceptForm::Boolean => "boolean",
        ConceptForm::ControlledCode => "controlled-code",
        ConceptForm::ControlledCategory => "controlled-category",
        ConceptForm::BoundedInteger => "bounded-integer",
        ConceptForm::BoundedDecimal => "bounded-decimal",
        ConceptForm::DateBucket => "date-bucket",
        ConceptForm::TimeBucket => "time-bucket",
        ConceptForm::AudienceScopedEntityReference => "audience-scoped-entity-reference",
        ConceptForm::ControlledCodeList => "controlled-code-list",
        ConceptForm::EntityReferenceList => "entity-reference-list",
        ConceptForm::ReviewedStructuredValue => "reviewed-structured-value",
    }
}

fn audit_scope(trust_domain: &str, purpose: &str, audience: &str) -> String {
    format!(
        "v1:{}:{trust_domain}:{}:{purpose}:{}:{audience}",
        trust_domain.len(),
        purpose.len(),
        audience.len()
    )
}

/// Authorization refusals always remain scoped to the authenticated relying
/// party, before any later event is allowed to select a binding-mode scope.
fn authorization_refusal_audit_scope(trust_domain: &str, purpose: &str, audience: &str) -> String {
    audit_scope(trust_domain, purpose, audience)
}

/// Audit scope for a holder-bound operation, which has no audience to bind.
///
/// The distinct `v1-holder:` prefix keeps the derivation domain-separated from
/// the audience-scoped one, so no pseudonym can collide across the two modes
/// even where trust domain and purpose agree. The holder key thumbprint is
/// deliberately absent: a scope naming it would make the audit chain itself a
/// place where one wallet key's activity can be picked out.
fn audit_scope_holder_bound(trust_domain: &str, purpose: &str) -> String {
    format!(
        "v1-holder:{}:{trust_domain}:{}:{purpose}",
        trust_domain.len(),
        purpose.len()
    )
}

/// Rate-limit pseudonyms deliberately omit request-controlled dimensions so a
/// principal cannot multiply its budget by varying purpose, audience, or
/// requirement. The pseudonym class and protected input distinguish request
/// and selector-failure budgets within this deployment scope.
fn rate_limit_scope(trust_domain: &str) -> String {
    format!("v1-rate:{}:{trust_domain}", trust_domain.len())
}

fn canonical_pair(first: &[u8], second: &[u8]) -> Option<Vec<u8>> {
    let first_length = u32::try_from(first.len()).ok()?;
    let second_length = u32::try_from(second.len()).ok()?;
    let mut output = Vec::with_capacity(8 + first.len() + second.len());
    output.extend_from_slice(&first_length.to_be_bytes());
    output.extend_from_slice(first);
    output.extend_from_slice(&second_length.to_be_bytes());
    output.extend_from_slice(second);
    Some(output)
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis())
        .unwrap_or(u64::MAX)
        .min(86_400_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_failures_and_rate_keys_are_value_free() {
        let failure = failure(ProblemCode::InvalidSelector, "selector");
        let rendered = format!("{failure:?} {failure}");
        assert!(!rendered.contains("protected-principal"));

        let first = canonical_pair(b"a", b"bc").expect("pair");
        let second = canonical_pair(b"ab", b"c").expect("pair");
        assert_ne!(first, second);
    }

    #[test]
    fn every_statement_source_failure_audits_under_its_own_category() {
        use crate::bundle::ArtifactFault;
        use crate::config::SchemaFault;

        let fault = ArtifactFault::new("queries/example.sql", SchemaFault::because("a cause"));
        let failures = [
            SourceError::ExtractUnavailable(fault.clone()),
            SourceError::ExtractTooOld(fault.clone()),
            SourceError::StatementRefused(fault.clone()),
            SourceError::StatementParameter(fault.clone()),
            SourceError::StatementBudget(fault.clone()),
            SourceError::StatementResult(fault),
            SourceError::StatementUnavailable,
        ];

        let mut categories = BTreeSet::new();
        for failure in &failures {
            let category = source_failure_category(failure);
            assert!(
                categories.insert(category),
                "two statement failures share the category {category}"
            );
            // The public problem class stays one class for every transport, so
            // the category is the only place the acting difference is recorded.
            assert_eq!(
                source_failure_problem(failure),
                ProblemCode::DependencyUnavailable
            );
            // An audit category is a label, never a value.
            assert!(!category.contains("queries/example.sql"));
        }

        for other in [
            SourceError::Credential,
            SourceError::Timeout,
            SourceError::Transport,
            SourceError::ResponseTooLarge,
        ] {
            assert!(
                categories.insert(source_failure_category(&other)),
                "a statement failure took an existing category"
            );
        }
    }

    #[test]
    fn a_spent_acquisition_ceiling_leaves_no_time_for_one_more_source_call() {
        let now = Instant::now();

        // `tokio::time::timeout` polls the future it wraps before it consults
        // its timer, so a zero remainder handed to it would still let one
        // request leave the process after the ceiling. A spent deadline has to
        // be answered before the source future exists, not by the timer.
        assert_eq!(stage_time_budget(now, now), None);
        assert_eq!(stage_time_budget(now - Duration::from_millis(1), now), None);
        assert_eq!(
            stage_time_budget(now + Duration::from_millis(5), now),
            Some(Duration::from_millis(5))
        );
    }

    #[test]
    fn audit_scope_is_unambiguous_for_component_boundaries() {
        assert_ne!(
            audit_scope("urn:a", "bc", "https://d.invalid"),
            audit_scope("urn:ab", "c", "https://d.invalid")
        );
    }

    #[test]
    fn holder_bound_audit_scope_binds_no_relying_party_and_no_holder_key() {
        let trust_domain = "urn:example:evidence";
        let purpose = "service-enrolment";
        let thumbprint = "hFTvL0-xJhWk2mn9Zq3rXcQd7YbAe1UgPsN4iOtRvKw";

        // Two modes over the same trust domain and purpose derive different
        // scopes, so no pseudonym can be read as belonging to the other mode.
        assert_ne!(
            audit_scope_holder_bound(trust_domain, purpose),
            audit_scope(trust_domain, purpose, "https://relying-party.invalid")
        );
        assert_ne!(
            audit_scope_holder_bound(trust_domain, purpose),
            rate_limit_scope(trust_domain)
        );

        // The scope is the same whichever holder asks, which is the whole
        // point: the audit chain must not become a place where one wallet
        // key's activity can be picked out.
        let scope = audit_scope_holder_bound(trust_domain, purpose);
        assert!(!scope.contains(thumbprint));
        assert!(!scope.contains("relying-party"));
        assert_eq!(scope, audit_scope_holder_bound(trust_domain, purpose));

        // Component boundaries stay unambiguous without the audience field
        // that separated them in the audience-scoped form.
        assert_ne!(
            audit_scope_holder_bound("urn:a", "bc"),
            audit_scope_holder_bound("urn:ab", "c")
        );
    }

    #[test]
    fn rate_limit_scope_cannot_be_fragmented_by_request_dimensions() {
        let trust_domain = "urn:example:evidence";
        let shared = rate_limit_scope(trust_domain);

        for (requirement, purpose, audience) in [
            ("adult", "service-enrolment", "https://one.invalid"),
            ("residence", "benefit-eligibility", "https://two.invalid"),
            ("professional", "licence-check", "https://three.invalid"),
        ] {
            assert_eq!(rate_limit_scope(trust_domain), shared);
            assert_ne!(audit_scope(trust_domain, purpose, audience), shared);
            assert!(!shared.contains(requirement));
            assert!(!shared.contains(purpose));
            assert!(!shared.contains(audience));
        }
    }

    #[test]
    fn public_unavailability_does_not_distinguish_no_match_from_ambiguity() {
        let no_match = evidence_unavailable_failure();
        let ambiguous = evidence_unavailable_failure();

        assert_eq!(no_match.problem(), ambiguous.problem());
        assert_eq!(no_match.category(), ambiguous.category());
        assert_eq!(format!("{no_match:?}"), format!("{ambiguous:?}"));
    }

    #[test]
    fn fact_absence_and_trusted_script_failures_have_distinct_public_classes() {
        assert_eq!(
            kernel_failure_problem(&KernelError::Extraction),
            ProblemCode::EvidenceNotAvailable
        );
        for failure in [KernelError::Script, KernelError::Output] {
            assert_eq!(
                kernel_failure_problem(&failure),
                ProblemCode::ServiceUnavailable
            );
        }
    }

    #[test]
    fn derivation_input_inconsistency_collapses_with_the_unresolved_classes() {
        assert_eq!(
            kernel_failure_problem(&KernelError::DerivationInput),
            kernel_failure_problem(&KernelError::Extraction)
        );
        assert_eq!(
            kernel_failure_problem(&KernelError::DerivationInput),
            ProblemCode::EvidenceNotAvailable
        );
        assert_ne!(
            kernel_failure_category(&KernelError::DerivationInput),
            kernel_failure_category(&KernelError::Extraction)
        );
    }

    /// Naming the artifact an adopter has to fix is a startup diagnostic. It
    /// must not become a second externally visible failure class, so it keeps
    /// the audit category and the public problem the bundle class already has.
    #[test]
    fn a_named_artifact_failure_classifies_exactly_as_a_bundle_failure() {
        use crate::bundle::ArtifactFault;
        use crate::config::SchemaFault;

        let artifact = KernelError::Artifact(ArtifactFault::new(
            "derivations/adult-status.rhai",
            SchemaFault::because("script does not compile"),
        ));

        assert_eq!(
            kernel_failure_category(&artifact),
            kernel_failure_category(&KernelError::Bundle)
        );
        assert_eq!(
            kernel_failure_problem(&artifact),
            kernel_failure_problem(&KernelError::Bundle)
        );
    }
}
