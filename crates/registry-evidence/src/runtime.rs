//! Complete authenticated Evidence evaluation and fail-closed release pipeline.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    str,
    sync::Arc,
    time::Instant,
};

use chrono::Utc;
use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, PublicJwk};
use serde_json::{Map as JsonMap, Value};
use thiserror::Error;

use crate::{
    audit::{
        AuditAuthority, AuditDecision, AuditPhase, AuditSubject,
        AuthorityKind as AuditAuthorityKind, EvidenceAuditEvent, EvidenceAuditLog,
        ResponseProtection,
    },
    auth::{AuthenticatedContext, Authenticator},
    bundle::{Bundle, DeploymentInputs},
    config::{
        AuthorityKind, ConceptForm, RequirementKind, ResponseFormat, RuntimeConfig, SelectorField,
        SelectorInput, SubjectCardinality, ValueOrigin,
    },
    contracts::definitions_contract_accepts,
    kernel::{EvidenceConstruction, KernelError, KernelOutcome, OfflineKernel, ValueProjection},
    model::{
        request_nonce_is_canonical, EvidenceDefinition, EvidenceDefinitionConcept,
        EvidenceDefinitionSelector, EvidenceDefinitionSubject, EvidenceDefinitions,
        EvidenceRequest, EvidenceSelectorField, FlattenedJws, JwksDocument, RequestedSelector,
        RequestedSubject, SelectorValue, SubjectBinding, UnsignedEnvelopeType,
        UnsignedEnvelopeWarning, UnsignedEvidenceEnvelope, UnsignedIntegrityProtection,
    },
    problem::ProblemCode,
    rate_limit::{EvidenceRateLimiter, RateLimitConfig, RateLimitError},
    sdjwt_vc,
    secrets::{ProtectedSecret, SecretProvider, SecretResolver},
    selector::{
        match_entitlement, resolve_selectors, validate_entitlement_context,
        validate_subject_binding_key, AuthorizationError, MatchedEntitlement,
        ResolvedAuthorization, ResolvedSelectorValue,
    },
    signing::{jwks_document, EvidenceSigner},
    source::{ResolvedSourceSelector, SourceError, SourceExecutor},
    EVIDENCE_DEFINITIONS_SCHEMA_V1, EVIDENCE_JWS_MEDIA_TYPE, EVIDENCE_SD_JWT_VC_MEDIA_TYPE,
    EVIDENCE_UNSIGNED_ENVELOPE_SCHEMA_V1, EVIDENCE_UNSIGNED_MEDIA_TYPE,
};

const MAX_OPERATION_BYTES: usize = 128;

#[derive(Debug, Error)]
pub enum RuntimeInitializationError {
    #[error("the immutable Evidence bundle could not be loaded")]
    Bundle,
    #[error("the Evidence secret resolver could not initialize")]
    Secrets,
    #[error("the Evidence audit boundary could not initialize")]
    Audit,
    #[error("the Evidence signing boundary could not initialize")]
    Signing,
    #[error("an Evidence source plan could not initialize")]
    Source,
    #[error("the Evidence rate limiter could not initialize")]
    RateLimit,
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
    audit: EvidenceAuditLog,
    signer: EvidenceSigner,
    jwks: JwksDocument,
    subject_binding_secret: ProtectedSecret,
    rate_limiter: EvidenceRateLimiter,
}

impl std::fmt::Debug for EvidenceRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceRuntime")
            .field("configuration_revision", &self.kernel.bundle().revision())
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

        let audit_secret = secrets
            .resolve(bundle.config.audit.hash_secret_ref.as_str())
            .map_err(|_| RuntimeInitializationError::Audit)?;
        let audit = EvidenceAuditLog::initialize(
            &runtime_config.audit_storage.path,
            runtime_config.audit_storage.maximum_file_bytes,
            audit_secret.expose_secret().to_vec(),
            bundle.config.audit.hash_key_version,
        )
        .await
        .map_err(|_| RuntimeInitializationError::Audit)?;

        let subject_binding_secret = secrets
            .resolve(bundle.config.subject_binding.secret_ref.as_str())
            .map_err(|_| RuntimeInitializationError::Secrets)?;
        validate_subject_binding_key(
            subject_binding_secret.expose_secret(),
            bundle.config.subject_binding.key_version,
            &bundle.config.service.trust_domain,
        )
        .map_err(|_| RuntimeInitializationError::Secrets)?;

        let signing_secret = secrets
            .resolve(bundle.config.signing.active_key_ref.as_str())
            .map_err(|_| RuntimeInitializationError::Signing)?;
        let signing_json = str::from_utf8(signing_secret.expose_secret())
            .map_err(|_| RuntimeInitializationError::Signing)?;
        let private_jwk =
            PrivateJwk::parse(signing_json).map_err(|_| RuntimeInitializationError::Signing)?;
        let provider = Arc::new(
            LocalJwkSigner::new(private_jwk).map_err(|_| RuntimeInitializationError::Signing)?,
        );
        let signer = EvidenceSigner::initialize(provider, &bundle.config.signing.active_key_id)
            .await
            .map_err(|_| RuntimeInitializationError::Signing)?;
        let retired = bundle
            .retired_public_jwks
            .values()
            .map(|value| {
                serde_json::to_string(value)
                    .map_err(|_| RuntimeInitializationError::Signing)
                    .and_then(|json| {
                        PublicJwk::parse(&json).map_err(|_| RuntimeInitializationError::Signing)
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let jwks = jwks_document(signer.public_jwk(), retired)
            .map_err(|_| RuntimeInitializationError::Signing)?;

        let mut sources = BTreeMap::new();
        for (source_id, source) in bundle.config.sources.iter() {
            let allowed_selector_sets = bundle.config.source_selector_sets(source_id);
            let executor = SourceExecutor::new_with_selector_sets_and_tls(
                source,
                &allowed_selector_sets,
                &runtime_config.outbound_tls,
                &runtime_document.ca_bundles,
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

        Ok(Self {
            kernel,
            runtime_config,
            runtime_revision,
            authenticator: authenticator_override
                .unwrap_or_else(|| Authenticator::from_config(&bundle.config.authentication)),
            sources,
            audit,
            signer,
            jwks,
            subject_binding_secret,
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

    #[cfg(test)]
    pub(crate) fn replace_signer_for_test(&mut self, signer: EvidenceSigner) {
        self.signer = signer;
    }

    /// Readiness proves all locally required material and source credentials.
    /// It never performs an evidence-data request.
    pub async fn ready(&self) -> bool {
        if validate_subject_binding_key(
            self.subject_binding_secret.expose_secret(),
            self.bundle().config.subject_binding.key_version,
            &self.bundle().config.service.trust_domain,
        )
        .is_err()
            || !self.signer.ready()
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
                holder_key: None,
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
            configuration_revision: self.bundle().revision().to_owned(),
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

        Ok(EvidenceDefinition {
            requirement: requirement.id.clone(),
            kind: requirement_kind_name(requirement.kind).to_owned(),
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
        // An unacceptable holder key fails before any credential acquisition or
        // source access. The key never reaches authorization, selectors, Rhai,
        // sources, or audit.
        if request
            .holder_key
            .as_ref()
            .is_some_and(|key| !key.is_acceptable())
        {
            return Err(failure(ProblemCode::MalformedRequest, "holder-key"));
        }
        let started = Instant::now();
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

        let scope = audit_scope(
            &self.bundle().config.service.trust_domain,
            &request.purpose,
            context.evidence_audience(),
        );
        let requester_pseudonym = self
            .audit
            .pseudonym("requester", &scope, context.principal().as_bytes())
            .map_err(|_| failure(ProblemCode::ServiceUnavailable, "audit-pseudonym"))?;

        let matched = match_entitlement(self.bundle(), request, &context).map_err(map_authority)?;
        // The immutable bundle and the one complete matched grant must both
        // permit the requested format. API selection creates no permission,
        // and the denial does not reveal which layer withheld it.
        if !self.bundle().config.response_formats.contains(&format)
            || !matched.permits_response_format(format)
        {
            return Err(failure(ProblemCode::NotAuthorized, "response-format"));
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

        let material =
            self.audit_material(&scope, requester_pseudonym, &context, &resolved, format)?;
        let (source_id, adapter_id) = self.source_identity(&request.requirement)?;
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
        let requirement = self
            .kernel
            .requirement(&request.requirement)
            .ok_or_else(|| failure(ProblemCode::ServiceUnavailable, "requirement"))?;
        let source = self
            .bundle()
            .config
            .sources
            .get(&source_id)
            .ok_or_else(|| failure(ProblemCode::ServiceUnavailable, "source-plan"))?;
        let preparation_selector_value =
            source_selector_input_value(&resolved, &source.request.selector_inputs)?;
        let selectors = source_selectors(&resolved, &source.request.selector_inputs)?;
        let request_parts = match self
            .kernel
            .prepare(&request.requirement, &preparation_selector_value)
        {
            Ok(parts) => parts,
            Err(error) => {
                let category = kernel_failure_category(error);
                self.append_failure(
                    &material,
                    operation,
                    AuditDecision::EvaluationFailure,
                    category,
                    &source_id,
                    &adapter_id,
                    started,
                )
                .await?;
                return Err(failure(kernel_failure_problem(error), category));
            }
        };
        let source_response = match executor.execute(&selectors, &request_parts).await {
            Ok(response) => response,
            Err(error) => {
                let category = source_failure_category(&error);
                self.append_failure(
                    &material,
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
        let observed_at = evaluation_time.unwrap_or_else(Utc::now);
        let derivation_selectors =
            selector_input_value(&resolved, &requirement.derivation.selector_inputs)?;
        let values = match self.kernel.evaluate_with_selectors(
            &request.requirement,
            &source_response,
            &derivation_selectors,
            observed_at,
            ValueProjection {
                audience: context.evidence_audience(),
                binding_key: self.subject_binding_secret.expose_secret(),
                binding_key_version: self.bundle().config.subject_binding.key_version,
            },
        ) {
            Ok(KernelOutcome::Match(values)) => values,
            Ok(KernelOutcome::NoMatch) => {
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
            Ok(KernelOutcome::Ambiguous) => {
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
            Err(error) => {
                let category = kernel_failure_category(error);
                let problem = kernel_failure_problem(error);
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

        let subjects = match self.subject_bindings(&resolved) {
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
        // `issued_at` is read after the source round-trip, so a backward wall-clock
        // adjustment between it and `observed_at` could otherwise make `issued_at`
        // precede `observed_at` and fail evidence construction. Clamp the wall-clock
        // read so issuance never predates observation; an injected evaluation time
        // keeps both stamps equal.
        let issued_at = evaluation_time.unwrap_or_else(|| Utc::now().max(observed_at));
        let evidence = match self.kernel.construct_evidence(
            &request.requirement,
            values,
            EvidenceConstruction {
                evidence_id: &evidence_id,
                request_nonce: &request.request_nonce,
                purpose: &request.purpose,
                audience: context.evidence_audience(),
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
        let disclosed_concepts = evidence
            .supported_values
            .iter()
            .map(|value| value.provides_value_for.clone())
            .collect::<Vec<_>>();

        // Serialize the final immutable response bytes before the durable
        // disclosure-release audit; the released bytes are exactly these. A
        // signed-path failure never downgrades to unsigned output.
        let (bytes, media_type, signing_key_id) = match format {
            ResponseFormat::SignedJws => {
                let signed = match self.signer.sign_json(&evidence).await {
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
                let input = match sdjwt_vc::issuance_input(&evidence, request.holder_key.as_ref()) {
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
            ResponseFormat::UnsignedJson => {
                // No signing operation runs, but the ordinary signing
                // dependency must still be ready for the deployment.
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
                    evidence,
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
        release.disclosed_concepts = Some(disclosed_concepts);
        release.evidence_id = Some(evidence_id);
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

    fn source_identity(&self, requirement_id: &str) -> Result<(String, String), RuntimeFailure> {
        let requirement = self
            .kernel
            .requirement(requirement_id)
            .ok_or_else(|| failure(ProblemCode::ServiceUnavailable, "requirement"))?;
        let source = self
            .bundle()
            .config
            .sources
            .get(&requirement.source)
            .ok_or_else(|| failure(ProblemCode::ServiceUnavailable, "source-plan"))?;
        let adapter_id = Path::new(source.extract_script.as_str())
            .file_stem()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty() && name.len() <= 128)
            .ok_or_else(|| failure(ProblemCode::ServiceUnavailable, "adapter-id"))?;
        Ok((requirement.source.clone(), adapter_id.to_owned()))
    }

    fn audit_material(
        &self,
        scope: &str,
        requester_pseudonym: String,
        context: &AuthenticatedContext,
        resolved: &ResolvedAuthorization,
        format: ResponseFormat,
    ) -> Result<AuditMaterial, RuntimeFailure> {
        let actor_pseudonym = context
            .actor()
            .map(|actor| self.audit.pseudonym("actor", scope, actor.as_bytes()))
            .transpose()
            .map_err(|_| failure(ProblemCode::ServiceUnavailable, "audit-pseudonym"))?;
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
                    .audit_pseudonym_input(&resolved.audience, &resolved.purpose)
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

    fn subject_bindings(
        &self,
        resolved: &ResolvedAuthorization,
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
                        &resolved.audience,
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

struct AuditMaterial {
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

fn map_response_protection(format: ResponseFormat) -> ResponseProtection {
    match format {
        ResponseFormat::SignedJws => ResponseProtection::Signed,
        ResponseFormat::UnsignedJson => ResponseProtection::Unsigned,
        ResponseFormat::SdJwtVc => ResponseProtection::SdJwtVc,
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
    }
}

/// Map a closed source-boundary failure to its public problem class.
///
/// The offline fixture command uses this same function, so its symbolic
/// failure cases cannot drift from the production release pipeline.
pub fn source_failure_problem(_error: &SourceError) -> ProblemCode {
    ProblemCode::DependencyUnavailable
}

fn kernel_failure_category(error: KernelError) -> &'static str {
    match error {
        KernelError::Preparation => "request-preparation",
        KernelError::Extraction => "fact-unavailable",
        KernelError::DerivationInput => "derivation-input",
        KernelError::SourceProtocol => "source-protocol",
        KernelError::Script => "script-failure",
        KernelError::Output => "output-gate",
        KernelError::Bundle | KernelError::Requirement | KernelError::Evidence => "kernel",
    }
}

/// Map a closed kernel failure to its public problem class. The unresolved
/// classes, including derivation-input inconsistency over a uniquely found
/// record, collapse to one public shape so status codes cannot become an
/// existence oracle. Native audit keeps only a value-free category.
fn kernel_failure_problem(error: KernelError) -> ProblemCode {
    match error {
        KernelError::Preparation => ProblemCode::ServiceUnavailable,
        KernelError::Extraction | KernelError::DerivationInput => ProblemCode::EvidenceNotAvailable,
        KernelError::SourceProtocol => ProblemCode::DependencyUnavailable,
        KernelError::Script
        | KernelError::Output
        | KernelError::Bundle
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
    fn audit_scope_is_unambiguous_for_component_boundaries() {
        assert_ne!(
            audit_scope("urn:a", "bc", "https://d.invalid"),
            audit_scope("urn:ab", "c", "https://d.invalid")
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
            kernel_failure_problem(KernelError::Extraction),
            ProblemCode::EvidenceNotAvailable
        );
        for failure in [KernelError::Script, KernelError::Output] {
            assert_eq!(
                kernel_failure_problem(failure),
                ProblemCode::ServiceUnavailable
            );
        }
    }

    #[test]
    fn derivation_input_inconsistency_collapses_with_the_unresolved_classes() {
        assert_eq!(
            kernel_failure_problem(KernelError::DerivationInput),
            kernel_failure_problem(KernelError::Extraction)
        );
        assert_eq!(
            kernel_failure_problem(KernelError::DerivationInput),
            ProblemCode::EvidenceNotAvailable
        );
        assert_ne!(
            kernel_failure_category(KernelError::DerivationInput),
            kernel_failure_category(KernelError::Extraction)
        );
    }
}
