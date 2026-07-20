// SPDX-License-Identifier: Apache-2.0

use super::cel::*;
use super::*;

#[derive(Debug, Clone)]
pub struct RegistryNotaryRuntime {
    subject_access_rate_keys: Arc<SubjectAccessRateLimitKeys>,
    activated_relay: Option<Arc<dyn ActivatedRelayConsultations>>,
    #[cfg(feature = "registry-notary-cel")]
    cel_worker: Option<Arc<CelWorker>>,
    #[cfg(feature = "registry-notary-cel")]
    cel_config: Arc<RegistryNotaryCelConfig>,
}

struct PreparedRegistryBatchItem {
    input_index: usize,
    request: EvaluateRequest,
    context: EvidenceRequestContext,
    purpose: String,
    claim_versions: ClaimVersionSelections,
    levels: Vec<Vec<String>>,
    disclosure: DisclosureProfile,
    format: String,
    evaluation_id: String,
    relay_plan: Arc<RequestScopedRelayPlan>,
    audit: Arc<EvaluationAuditCollector>,
    evaluation_capability: EvaluationCapability,
}

struct EvaluatedRegistryClaims {
    views: Vec<ClaimResultView>,
    issuance_provenance: Option<StoredIssuanceProvenance>,
}

fn clear_batch_runtime_audit(response: &mut BatchEvaluateResponse) {
    for item in &mut response.items {
        item.runtime_audit = Default::default();
    }
}

pub(crate) fn registry_backed_batch_requested(
    evidence: &EvidenceConfig,
    request: &BatchEvaluateRequest,
) -> Result<bool, EvidenceError> {
    let claim_versions = requested_claim_versions(&request.claims)?;
    let levels = build_claim_levels(evidence, &request.claims, &claim_versions)?;
    let mut registry_backed = false;
    for claim_id in levels.iter().flatten() {
        let claim = find_claim_for_selection(evidence, claim_id, &claim_versions)?;
        match claim.evidence_mode {
            ClaimEvidenceMode::RegistryBacked { .. } => registry_backed = true,
            ClaimEvidenceMode::SelfAttested => {}
        }
    }
    Ok(registry_backed)
}

impl Default for RegistryNotaryRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryNotaryRuntime {
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_audit_hasher(AuditKeyHasher::unkeyed_dev_only())
    }

    #[must_use]
    pub fn new_with_audit_hasher(audit_hasher: AuditKeyHasher) -> Self {
        Self::new_with_subject_access_rate_keys(Arc::new(SubjectAccessRateLimitKeys::new(
            audit_hasher,
        )))
    }

    #[must_use]
    pub fn new_with_subject_access_rate_keys(
        subject_access_rate_keys: Arc<SubjectAccessRateLimitKeys>,
    ) -> Self {
        Self {
            subject_access_rate_keys,
            activated_relay: None,
            #[cfg(feature = "registry-notary-cel")]
            cel_worker: None,
            #[cfg(feature = "registry-notary-cel")]
            cel_config: Arc::new(RegistryNotaryCelConfig::default()),
        }
    }

    #[must_use]
    pub(crate) fn with_activated_relay(
        mut self,
        activated_relay: Option<Arc<dyn ActivatedRelayConsultations>>,
    ) -> Self {
        self.activated_relay = activated_relay;
        self
    }

    #[cfg(feature = "registry-notary-cel")]
    #[must_use]
    pub fn with_cel_worker(mut self, cel_worker: Option<Arc<CelWorker>>) -> Self {
        self.cel_worker = cel_worker;
        self
    }

    #[cfg(feature = "registry-notary-cel")]
    #[must_use]
    pub fn with_cel_config(mut self, cel_config: Arc<RegistryNotaryCelConfig>) -> Self {
        self.cel_config = cel_config;
        self
    }

    pub fn service_document(evidence: &EvidenceConfig) -> Value {
        let issuer = evidence
            .credential_profiles
            .values()
            .next()
            .map(|profile| profile.issuer.as_str())
            .unwrap_or(evidence.service_id.as_str());
        json!({
            "service_id": evidence.service_id,
            "api_version": evidence.api_version,
            "base_url": evidence.api_base_url,
            "issuer": {
                "id": issuer,
                "name": evidence.service_id,
            },
            "auth": {
                "methods": ["api_key", "bearer"],
                "api_key": {
                    "header": "X-Api-Key",
                },
                "bearer": {
                    "header": "Authorization",
                    "scheme": "bearer",
                    "format": "Bearer <token>",
                },
                "audience": evidence.service_id,
            },
            "operations": {
                "evaluate": true,
                "batch_evaluate": true,
                "render": true,
                "credential_issue": !evidence.credential_profiles.is_empty()
            },
            "claims_url": evidence.claims_url,
            "formats_url": evidence.formats_url,
            "credential_capabilities": Self::credential_capabilities(evidence),
            "batch": {
                "max_inline_subjects": evidence.inline_batch_limit,
                "idempotency_window": "PT15M",
            },
            "identity": {
                "mapper": "common_subject_id",
                "production_mapper": false
            },
            "formats": formats(evidence),
        })
    }

    fn credential_capabilities(evidence: &EvidenceConfig) -> Value {
        let signing_algs = Self::credential_signing_algs(evidence);
        let issuer_key_types = Self::credential_issuer_key_types(&signing_algs);
        json!({
            "formats": [FORMAT_SD_JWT_VC],
            "sd_jwt_vc": {
                "media_type": FORMAT_SD_JWT_VC,
                "jwt_typ": SD_JWT_VC_JWT_TYP,
                "signing_algs": signing_algs,
                "issuer_key_types": issuer_key_types,
                "holder_binding_methods": [SD_JWT_VC_HOLDER_BINDING_METHOD],
                "status_methods": [],
                "credential_profiles": Self::credential_profile_capabilities(evidence),
                "openid4vci": {
                    "support": "not_full_issuer"
                }
            },
            "unsupported_features": [
                "application/vc+sd-jwt",
                "json_ld_vc_issuance",
                "data_integrity_proofs",
                "credential_status",
                "delegated_credential_issuance",
                "mso_mdoc",
                "openid4vci_full_issuer"
            ]
        })
    }

    fn credential_signing_algs(evidence: &EvidenceConfig) -> Vec<String> {
        let mut algs = BTreeSet::new();
        for profile in evidence.credential_profiles.values() {
            if profile.format != FORMAT_SD_JWT_VC {
                continue;
            }
            if let Some(key) = evidence.signing_keys.get(&profile.signing_key) {
                algs.insert(key.alg.clone());
            }
        }
        if algs.is_empty() {
            algs.insert(SD_JWT_VC_SIGNING_ALG.to_string());
        }
        algs.into_iter().collect()
    }

    fn credential_issuer_key_types(signing_algs: &[String]) -> Vec<String> {
        let mut key_types = BTreeSet::new();
        for alg in signing_algs {
            match alg.as_str() {
                "ES256" => {
                    key_types.insert(SD_JWT_VC_P256_ISSUER_KEY_TYPE.to_string());
                }
                "RS256" => {
                    key_types.insert(SD_JWT_VC_RSA_ISSUER_KEY_TYPE.to_string());
                }
                _ => {
                    key_types.insert(SD_JWT_VC_ISSUER_KEY_TYPE.to_string());
                }
            }
        }
        key_types.into_iter().collect()
    }

    fn credential_profile_capabilities(evidence: &EvidenceConfig) -> Vec<Value> {
        evidence
            .credential_profiles
            .iter()
            .map(|(profile_id, profile)| {
                json!({
                    "id": profile_id,
                    "format": profile.format.as_str(),
                    "issuer": profile.issuer.as_str(),
                    "vct": profile.vct.as_str(),
                    "validity_seconds": profile.validity_seconds,
                    "holder_binding": {
                        "mode": profile.holder_binding.mode.as_str(),
                        "proof_of_possession": profile.holder_binding.proof_of_possession.as_deref(),
                        "allowed_did_methods": &profile.holder_binding.allowed_did_methods
                    },
                    "allowed_claims": &profile.allowed_claims,
                    "disclosure": {
                        "allowed": &profile.disclosure.allowed
                    },
                })
            })
            .collect()
    }

    pub fn service_document_with_subject_access(
        evidence: &EvidenceConfig,
        subject_access: &SubjectAccessConfig,
        include_subject_access_details: bool,
    ) -> Value {
        let mut document = Self::service_document(evidence);
        if subject_access.enabled {
            let mut subject_access_document = json!({
                "enabled": true,
            });
            if include_subject_access_details {
                subject_access_document = json!({
                    "enabled": true,
                    "allowed_operations": subject_access.allowed_operations,
                    "allowed_claim_ids": subject_access.allowed_claims,
                    "allowed_formats": subject_access.allowed_formats,
                    "allowed_disclosures": subject_access.allowed_disclosures,
                    "credential_profile_ids": subject_access.credential_profiles,
                    "subject_id_type": subject_access.subject_binding.id_type,
                    "token_claim_name": subject_access.subject_binding.token_claim,
                    "scope_policy": subject_access.scope_policy,
                    "required_scopes": subject_access.required_scopes,
                    "max_evaluation_age_seconds": subject_access
                        .token_policy
                        .max_evaluation_age_seconds,
                    "max_credential_validity_seconds": subject_access
                        .token_policy
                        .max_credential_validity_seconds,
                });
            }
            document["subject_access"] = subject_access_document;
        }
        document
    }

    pub fn list_claims(evidence: &EvidenceConfig, principal: &EvidencePrincipal) -> Vec<Value> {
        evidence
            .claims
            .iter()
            .filter(|claim| principal_can_see_claim(principal, claim))
            .map(claim_summary)
            .collect()
    }

    pub fn get_claim(
        evidence: &EvidenceConfig,
        principal: &EvidencePrincipal,
        claim_id: &str,
    ) -> Result<Value, EvidenceError> {
        let claim = find_claim(evidence, claim_id)?;
        if !principal_can_see_claim(principal, claim) {
            return Err(EvidenceError::ClaimNotFound);
        }
        Ok(claim_summary(claim))
    }

    pub fn list_formats(evidence: &EvidenceConfig) -> Vec<EvidenceFormat> {
        formats(evidence)
    }

    pub async fn evaluate(
        &self,
        evidence: Arc<EvidenceConfig>,
        store: &EvidenceStore,
        principal: &EvidencePrincipal,
        request: EvaluateRequest,
        header_purpose: Option<&str>,
    ) -> Result<Vec<ClaimResultView>, EvidenceError> {
        self.evaluate_with_audit_collector(
            evidence,
            store,
            principal,
            request,
            header_purpose,
            Arc::new(EvaluationAuditCollector::new()),
        )
        .await
    }

    pub(crate) async fn evaluate_for_api(
        &self,
        evidence: Arc<EvidenceConfig>,
        store: &EvidenceStore,
        principal: &EvidencePrincipal,
        request: EvaluateRequest,
        header_purpose: Option<&str>,
    ) -> (
        Result<Vec<ClaimResultView>, EvidenceError>,
        EvaluationAuditSnapshot,
    ) {
        let audit = Arc::new(EvaluationAuditCollector::new());
        let result = self
            .evaluate_with_audit_collector(
                evidence,
                store,
                principal,
                request,
                header_purpose,
                Arc::clone(&audit),
            )
            .await;
        (result, audit.snapshot())
    }

    #[allow(clippy::too_many_arguments)]
    async fn evaluate_with_audit_collector(
        &self,
        evidence: Arc<EvidenceConfig>,
        store: &EvidenceStore,
        principal: &EvidencePrincipal,
        request: EvaluateRequest,
        header_purpose: Option<&str>,
        audit: Arc<EvaluationAuditCollector>,
    ) -> Result<Vec<ClaimResultView>, EvidenceError> {
        let request_claim_ids = claim_ids(&request.claims);
        let evaluation_capability = evaluation_capability_for_principal(
            &self.subject_access_rate_keys,
            principal,
            &request_claim_ids,
        )?;
        self.evaluate_with_capability_and_audit(
            evidence,
            store,
            principal,
            evaluation_capability,
            request,
            header_purpose,
            None,
            None,
            audit,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn evaluate_with_capability(
        &self,
        evidence: Arc<EvidenceConfig>,
        store: &EvidenceStore,
        principal: &EvidencePrincipal,
        evaluation_capability: EvaluationCapability,
        request: EvaluateRequest,
        header_purpose: Option<&str>,
        subject_access: Option<StoredSubjectAccessMetadata>,
        correlation_id: Option<BoundedCorrelationId>,
    ) -> Result<Vec<ClaimResultView>, EvidenceError> {
        self.evaluate_with_capability_and_audit(
            evidence,
            store,
            principal,
            evaluation_capability,
            request,
            header_purpose,
            subject_access,
            correlation_id,
            Arc::new(EvaluationAuditCollector::new()),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn evaluate_with_capability_for_api(
        &self,
        evidence: Arc<EvidenceConfig>,
        store: &EvidenceStore,
        principal: &EvidencePrincipal,
        evaluation_capability: EvaluationCapability,
        request: EvaluateRequest,
        header_purpose: Option<&str>,
        subject_access: Option<StoredSubjectAccessMetadata>,
        correlation_id: Option<BoundedCorrelationId>,
    ) -> (
        Result<Vec<ClaimResultView>, EvidenceError>,
        EvaluationAuditSnapshot,
    ) {
        let audit = Arc::new(EvaluationAuditCollector::new());
        let result = self
            .evaluate_with_capability_and_audit(
                evidence,
                store,
                principal,
                evaluation_capability,
                request,
                header_purpose,
                subject_access,
                correlation_id,
                Arc::clone(&audit),
            )
            .await;
        (result, audit.snapshot())
    }

    #[allow(clippy::too_many_arguments)]
    async fn evaluate_with_capability_and_audit(
        &self,
        evidence: Arc<EvidenceConfig>,
        store: &EvidenceStore,
        principal: &EvidencePrincipal,
        evaluation_capability: EvaluationCapability,
        request: EvaluateRequest,
        header_purpose: Option<&str>,
        subject_access: Option<StoredSubjectAccessMetadata>,
        correlation_id: Option<BoundedCorrelationId>,
        audit: Arc<EvaluationAuditCollector>,
    ) -> Result<Vec<ClaimResultView>, EvidenceError> {
        ensure_evaluation_capability_matches_principal(principal, &evaluation_capability)?;
        if request.claims.is_empty() {
            return Err(EvidenceError::InvalidRequest);
        }
        let target = request
            .target
            .as_ref()
            .ok_or(EvidenceError::InvalidRequest)?;
        if !target.has_matching_input() {
            return Err(EvidenceError::InvalidRequest);
        }
        let claim_versions = requested_claim_versions(&request.claims)?;
        let request_claim_ids = claim_ids(&request.claims);
        for claim_id in &request.claims {
            require_evaluation_capability(&evaluation_capability, claim_id)?;
        }
        let purpose = resolve_purpose(header_purpose, request.purpose.as_deref())?;
        require_purpose_allowed(
            &evidence,
            &request.claims,
            &claim_versions,
            purpose.as_str(),
        )?;
        let format = request
            .format
            .clone()
            .unwrap_or_else(|| FORMAT_CLAIM_RESULT_JSON.to_string());
        for claim_ref in &request.claims {
            require_claim_format(
                find_claim_for_selection(&evidence, claim_ref, &claim_versions)?,
                &format,
            )?;
        }
        let disclosure = requested_disclosure(
            &evidence,
            &request.claims,
            &claim_versions,
            &request.disclosure,
        )?;
        validate_requested_disclosure_before_source(
            &evidence,
            &request.claims,
            &claim_versions,
            disclosure,
        )?;
        let context = request
            .request_context()
            .ok_or(EvidenceError::InvalidRequest)?;
        let levels = build_claim_levels(&evidence, &request.claims, &claim_versions)?;
        validate_request_variables_before_relay(&evidence, &context, &claim_versions, &levels)?;
        preflight_claim_closure(
            &evidence,
            principal,
            &evaluation_capability,
            &claim_versions,
            &levels,
            &purpose,
            self.activated_relay.is_some(),
        )?;
        let request_hash = hash_json(&request)?;
        let evaluation_ulid = audit.begin_evaluation();
        let evaluation_id = evaluation_ulid.to_string();
        let relay_plan = plan_relay_consultations(
            &evidence,
            principal,
            &context,
            &claim_versions,
            &levels,
            &purpose,
            evaluation_ulid,
            self.activated_relay.as_ref(),
            Arc::clone(&audit),
            None,
            &evaluation_capability,
        )?;
        let now = OffsetDateTime::now_utc();
        #[cfg(feature = "registry-notary-cel")]
        let cel_concurrency = self
            .cel_worker
            .as_ref()
            .map(|_| Arc::new(Semaphore::new(self.cel_config.worker_count.max(1))));
        let policy = evaluation_policy_from_subject_access(subject_access.as_ref());
        let internal = self
            .evaluate_claims_dag(
                Arc::clone(&evidence),
                context,
                purpose.clone(),
                evaluation_id.clone(),
                now,
                claim_versions.clone(),
                levels,
                evaluation_capability,
                relay_plan,
                #[cfg(feature = "registry-notary-cel")]
                cel_concurrency,
                correlation_id,
                policy,
            )
            .await?;
        let issuance_provenance =
            stored_issuance_provenance(&evidence, &request.claims, &claim_versions, &internal)?;
        let views = request
            .claims
            .iter()
            .map(|claim_id| {
                let claim = find_claim_for_selection(&evidence, claim_id, &claim_versions)?;
                let result = internal
                    .get(claim_id.id.as_str())
                    .ok_or(EvidenceError::RuleEvaluationFailed)?;
                view_claim(
                    &self.subject_access_rate_keys,
                    result,
                    claim,
                    disclosure,
                    &format,
                )
            })
            .collect::<Result<Vec<_>, EvidenceError>>()?;
        let expires_at = subject_access
            .as_ref()
            .and_then(|metadata| metadata.evaluation_expires_at.as_deref())
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            .unwrap_or_else(|| default_stored_evaluation_expires_at(now));
        let client_id = stored_evaluation_client_id(principal, subject_access.as_ref());
        store
            .insert(registry_notary_core::StoredEvaluation {
                client_id,
                purpose,
                claim_ids: request_claim_ids,
                claim_refs: request.claims.clone(),
                disclosure: stored_disclosure(&views),
                format,
                results: views.clone(),
                created_at: format_time(now),
                expires_at: format_time(expires_at),
                request_hash,
                issuance_provenance,
                subject_access,
            })
            .await?;
        Ok(views)
    }

    pub async fn batch_evaluate(
        &self,
        evidence: Arc<EvidenceConfig>,
        store: &EvidenceStore,
        principal: &EvidencePrincipal,
        request: BatchEvaluateRequest,
        options: BatchEvaluateOptions<'_>,
    ) -> Result<BatchEvaluateResponse, EvidenceError> {
        if principal.is_subject_access() {
            return Err(EvidenceError::SubjectAccessDenied {
                reason: SubjectAccessDenialCode::BatchDenied,
            });
        }
        if request.claims.is_empty() || request.items.is_empty() {
            return Err(EvidenceError::InvalidRequest);
        }
        if request.items.len() > registry_notary_core::MAX_BATCH_EVALUATION_MEMBERS_V1 {
            return Err(EvidenceError::BatchTooLarge);
        }
        let claim_versions = requested_claim_versions(&request.claims)?;
        let max_subjects = max_batch_subjects(&evidence, &request.claims, &claim_versions)?;
        if request.items.len() > max_subjects {
            return Err(EvidenceError::BatchTooLarge);
        }
        let registry_backed_batch = registry_backed_batch_requested(&evidence, &request)?;
        if registry_backed_batch
            && options
                .idempotency_key
                .is_none_or(|key| key.is_empty() || key.len() > 256)
        {
            return Err(EvidenceError::ConsultationInvalidRequest);
        }
        let request_claim_ids = claim_ids(&request.claims);
        let scoped_key = options
            .idempotency_key
            .map(|key| batch_idempotency_key(&principal.principal_id, key));
        let evaluation_capability = evaluation_capability_for_principal(
            &self.subject_access_rate_keys,
            principal,
            &request_claim_ids,
        )?;
        let batch_purpose =
            resolve_batch_default_purpose(options.header_purpose, request.purpose.as_deref())?;
        let subject_purposes =
            resolve_batch_subject_purposes(&request.items, batch_purpose.as_deref())?;
        let unique_purposes =
            validate_batch_inputs_and_collect_purposes(&request.items, &subject_purposes)?;
        for purpose in unique_purposes {
            require_purpose_allowed(&evidence, &request.claims, &claim_versions, purpose)?;
        }
        let request_hash = batch_request_binding_hash(
            &evidence,
            &request,
            principal,
            &subject_purposes,
            &claim_versions,
        )?;
        if registry_backed_batch {
            return self
                .batch_evaluate_registry_backed(
                    evidence,
                    store,
                    principal,
                    request,
                    options
                        .idempotency_key
                        .ok_or(EvidenceError::ConsultationInvalidRequest)?,
                    request_hash,
                    scoped_key.ok_or(EvidenceError::ConsultationInvalidRequest)?,
                    evaluation_capability,
                    subject_purposes,
                    claim_versions,
                    options.owner_quota,
                )
                .await;
        }
        let batch_id = Ulid::new().to_string();
        let claims = request_claim_ids.clone();
        let subject_count = request.items.len();
        let mut items: Vec<Option<BatchItemResponse>> = (0..subject_count).map(|_| None).collect();
        let mut succeeded = 0usize;
        let mut failed = 0usize;
        let subject_concurrency = Arc::new(Semaphore::new(evidence.concurrency.subjects));
        #[cfg(feature = "registry-notary-cel")]
        let cel_concurrency = self
            .cel_worker
            .as_ref()
            .map(|_| Arc::new(Semaphore::new(self.cel_config.worker_count.max(1))));
        let disclosure = requested_disclosure(
            &evidence,
            &request.claims,
            &claim_versions,
            &request.disclosure,
        )?;
        validate_requested_disclosure_before_source(
            &evidence,
            &request.claims,
            &claim_versions,
            disclosure,
        )?;
        let reservation_key = scoped_key.or_else(|| {
            store
                .uses_postgresql()
                .then(|| format!("notary-internal-batch:{batch_id}"))
        });
        let mut idempotency_owner = if let Some(key) = reservation_key {
            match store
                .reserve_idempotent_batch(
                    key,
                    request_hash.clone(),
                    &principal.principal_id,
                    options.owner_quota,
                )
                .await?
            {
                BatchIdempotencyReservation::Replay(mut response) => {
                    clear_batch_runtime_audit(&mut response);
                    return Ok(response);
                }
                BatchIdempotencyReservation::Owner(owner) => Some(owner),
            }
        } else {
            None
        };
        let quota_charged_by_reservation = idempotency_owner
            .as_ref()
            .is_some_and(BatchIdempotencyOwner::quota_charged);
        if let Some((quota, cost)) = options
            .owner_quota
            .filter(|_| !quota_charged_by_reservation)
        {
            let quota_enabled = idempotency_owner.is_some() && quota.is_enabled();
            if let Err(error) = quota.check_and_consume(&principal.principal_id, cost).await {
                if let Some(owner) = idempotency_owner.take() {
                    owner.abandon_uncharged()?;
                }
                return Err(EvidenceError::MachineQuotaExceeded {
                    retry_after_seconds: error.retry_after_seconds,
                });
            }
            if let Some(owner) = idempotency_owner.as_mut().filter(|_| quota_enabled) {
                owner.mark_quota_charged()?;
            }
        }
        let mut retained_evaluations = Vec::new();
        let mut join_set: JoinSet<(usize, Result<Vec<ClaimResultView>, EvidenceError>)> =
            JoinSet::new();
        for (input_index, item) in request.items.clone().into_iter().enumerate() {
            let runtime = self.clone();
            let evidence = Arc::clone(&evidence);
            let permit_semaphore = Arc::clone(&subject_concurrency);
            let claims_list = request.claims.clone();
            let disclosure = request.disclosure.clone();
            let format = request.format.clone();
            let purpose_for_task = subject_purposes[input_index].clone();
            let auth_profile_id = principal.auth_profile_id;
            let principal_id = principal.principal_id.clone();
            let principal_scopes = principal.scopes.clone();
            let principal_authorization_details = principal.authorization_details.clone();
            let evaluation_capability = evaluation_capability.clone();
            #[cfg(feature = "registry-notary-cel")]
            let cel_concurrency = cel_concurrency.as_ref().map(Arc::clone);
            join_set.spawn(async move {
                let _permit = match permit_semaphore.acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => return (input_index, Err(EvidenceError::RuleEvaluationFailed)),
                };
                let eval = EvaluateRequest {
                    requester: item.requester,
                    target: Some(item.target),
                    relationship: item.relationship,
                    on_behalf_of: item.on_behalf_of,
                    variables: Default::default(),
                    claims: claims_list,
                    disclosure,
                    format,
                    purpose: Some(purpose_for_task.clone()),
                };
                let principal = EvidencePrincipal {
                    auth_profile_id,
                    principal_id,
                    scopes: principal_scopes,
                    access_mode: registry_notary_core::AccessMode::MachineClient,
                    verified_claims: None,
                    authorization_details: principal_authorization_details,
                };
                let result = runtime
                    .evaluate_subject_for_batch(
                        evidence,
                        &principal,
                        evaluation_capability,
                        eval,
                        purpose_for_task.as_str(),
                        #[cfg(feature = "registry-notary-cel")]
                        cel_concurrency,
                    )
                    .await;
                (input_index, result)
            });
        }
        // Collect results and surface panics as request-level errors. Drop
        // semantics for `JoinSet` cancel remaining tasks if we early-return.
        while let Some(joined) = join_set.join_next().await {
            let (input_index, result) = match joined {
                Ok(pair) => pair,
                Err(join_error) if join_error.is_panic() => {
                    tracing::error!(
                        target: "registry_notary_server::runtime",
                        error = %join_error,
                        "subject task panicked",
                    );
                    return Err(EvidenceError::RuleEvaluationFailed);
                }
                Err(_) => return Err(EvidenceError::RuleEvaluationFailed),
            };
            match result {
                Ok(results) => {
                    let evaluation_id = results.first().map(|result| result.evaluation_id.clone());
                    let claim_results = results
                        .iter()
                        .map(|result| batch_claim_result(&evidence, result))
                        .collect::<Result<Vec<_>, EvidenceError>>()?;
                    // Retain per-subject evaluations on the calling task. An
                    // idempotent batch publishes these and its completed
                    // response together after all subjects finish.
                    if !results.is_empty() {
                        // Retention is a Notary storage lifecycle. It does not
                        // inherit any evidence observation timestamp.
                        let stored_at = OffsetDateTime::now_utc();
                        retained_evaluations.push(registry_notary_core::StoredEvaluation {
                            client_id: principal.principal_id.clone(),
                            purpose: subject_purposes[input_index].clone(),
                            claim_ids: request_claim_ids.clone(),
                            claim_refs: request.claims.clone(),
                            disclosure: stored_disclosure(&results),
                            format: results
                                .first()
                                .map(|view| view.format.clone())
                                .unwrap_or_default(),
                            results: results.clone(),
                            created_at: format_time(stored_at),
                            expires_at: format_time(default_stored_evaluation_expires_at(
                                stored_at,
                            )),
                            request_hash: request_hash.clone(),
                            issuance_provenance: None,
                            subject_access: None,
                        });
                    }
                    succeeded += 1;
                    let batch_item = &request.items[input_index];
                    let target_ref =
                        target_ref_view(&self.subject_access_rate_keys, &batch_item.target)?;
                    let requester_ref = batch_item
                        .requester
                        .as_ref()
                        .map(|requester| {
                            entity_ref_view(&self.subject_access_rate_keys, "requester", requester)
                        })
                        .transpose()?;
                    items[input_index] = Some(BatchItemResponse {
                        input_index,
                        target_ref,
                        requester_ref,
                        evaluation_id,
                        status: BatchItemStatus::Succeeded,
                        claim_results,
                        errors: Vec::new(),
                        runtime_audit: Default::default(),
                    });
                }
                Err(error) => {
                    failed += 1;
                    let batch_item = &request.items[input_index];
                    let target_ref =
                        target_ref_view(&self.subject_access_rate_keys, &batch_item.target)?;
                    let requester_ref = batch_item
                        .requester
                        .as_ref()
                        .map(|requester| {
                            entity_ref_view(&self.subject_access_rate_keys, "requester", requester)
                        })
                        .transpose()?;
                    items[input_index] = Some(BatchItemResponse {
                        input_index,
                        target_ref,
                        requester_ref,
                        evaluation_id: None,
                        status: BatchItemStatus::Failed,
                        claim_results: Vec::new(),
                        errors: vec![batch_item_error(&error)],
                        runtime_audit: Default::default(),
                    });
                }
            }
        }
        let items: Vec<BatchItemResponse> = items
            .into_iter()
            .map(|slot| slot.ok_or(EvidenceError::RuleEvaluationFailed))
            .collect::<Result<Vec<_>, _>>()?;
        let response = BatchEvaluateResponse {
            batch_id,
            status: BatchStatus::Completed,
            claims,
            items,
            summary: BatchSummary { succeeded, failed },
        };
        match idempotency_owner {
            Some(owner) => owner.complete(response, retained_evaluations).await,
            None => {
                for evaluation in retained_evaluations {
                    store.insert(evaluation).await?;
                }
                Ok(response)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn batch_evaluate_registry_backed(
        &self,
        evidence: Arc<EvidenceConfig>,
        store: &EvidenceStore,
        principal: &EvidencePrincipal,
        request: BatchEvaluateRequest,
        outer_idempotency_key: &str,
        request_hash: String,
        scoped_key: String,
        evaluation_capability: EvaluationCapability,
        subject_purposes: Vec<String>,
        claim_versions: ClaimVersionSelections,
        owner_quota: Option<(&crate::MachineQuotaLimiter, u32)>,
    ) -> Result<BatchEvaluateResponse, EvidenceError> {
        ensure_evaluation_capability_matches_principal(principal, &evaluation_capability)?;
        let format = request
            .format
            .clone()
            .unwrap_or_else(|| FORMAT_CLAIM_RESULT_JSON.to_string());
        let disclosure = requested_disclosure(
            &evidence,
            &request.claims,
            &claim_versions,
            &request.disclosure,
        )?;
        validate_requested_disclosure_before_source(
            &evidence,
            &request.claims,
            &claim_versions,
            disclosure,
        )?;
        let levels = build_claim_levels(&evidence, &request.claims, &claim_versions)?;
        // This loop is intentionally pure with respect to Relay
        // execution. Every item must pass the complete authorization and
        // request-shape preflight before any item can be forwarded.
        let mut prepared = Vec::with_capacity(request.items.len());
        let mut total_groups = 0usize;
        for (input_index, (item, purpose)) in request
            .items
            .iter()
            .zip(subject_purposes.iter())
            .enumerate()
        {
            if !item.target.has_matching_input() {
                return Err(EvidenceError::InvalidRequest);
            }
            for claim_ref in &request.claims {
                require_evaluation_capability(&evaluation_capability, claim_ref)?;
                let claim = find_claim_for_selection(&evidence, claim_ref, &claim_versions)?;
                require_claim_access(principal, claim)?;
                require_claim_format(claim, &format)?;
            }
            let context = item.request_context();
            validate_request_variables_before_relay(&evidence, &context, &claim_versions, &levels)?;
            preflight_claim_closure(
                &evidence,
                principal,
                &evaluation_capability,
                &claim_versions,
                &levels,
                purpose,
                self.activated_relay.is_some(),
            )?;
            let audit = Arc::new(EvaluationAuditCollector::new());
            let evaluation_ulid = audit.begin_evaluation();
            let relay_plan = plan_relay_consultations(
                &evidence,
                principal,
                &context,
                &claim_versions,
                &levels,
                purpose,
                evaluation_ulid,
                self.activated_relay.as_ref(),
                Arc::clone(&audit),
                Some((outer_idempotency_key, input_index)),
                &evaluation_capability,
            )?
            .ok_or(EvidenceError::ConsultationInvalidRequest)?;
            total_groups = total_groups
                .checked_add(relay_plan.group_count())
                .ok_or(EvidenceError::ConsultationInvalidRequest)?;
            if total_groups > MAX_BATCH_CONSULTATION_GROUPS_V1 {
                return Err(EvidenceError::ConsultationInvalidRequest);
            }
            prepared.push(PreparedRegistryBatchItem {
                input_index,
                request: EvaluateRequest {
                    requester: item.requester.clone(),
                    target: Some(item.target.clone()),
                    relationship: item.relationship.clone(),
                    on_behalf_of: item.on_behalf_of.clone(),
                    variables: Default::default(),
                    claims: request.claims.clone(),
                    disclosure: request.disclosure.clone(),
                    format: request.format.clone(),
                    purpose: Some(purpose.clone()),
                },
                context,
                purpose: purpose.clone(),
                claim_versions: claim_versions.clone(),
                levels: levels.clone(),
                disclosure,
                format: format.clone(),
                evaluation_id: evaluation_ulid.to_string(),
                relay_plan,
                audit,
                evaluation_capability: evaluation_capability.clone(),
            });
        }

        let mut idempotency_owner = match store
            .reserve_idempotent_batch(
                scoped_key,
                request_hash.clone(),
                &principal.principal_id,
                owner_quota,
            )
            .await?
        {
            BatchIdempotencyReservation::Replay(mut response) => {
                clear_batch_runtime_audit(&mut response);
                return Ok(response);
            }
            BatchIdempotencyReservation::Owner(owner) => owner,
        };
        let quota_charged_by_reservation = idempotency_owner.quota_charged();
        if let Some((quota, cost)) = owner_quota.filter(|_| !quota_charged_by_reservation) {
            let quota_enabled = quota.is_enabled();
            if let Err(error) = quota.check_and_consume(&principal.principal_id, cost).await {
                idempotency_owner.abandon_uncharged()?;
                return Err(EvidenceError::MachineQuotaExceeded {
                    retry_after_seconds: error.retry_after_seconds,
                });
            }
            if quota_enabled {
                idempotency_owner.mark_quota_charged()?;
            }
        }

        let subject_concurrency = Arc::new(Semaphore::new(evidence.concurrency.subjects));
        #[cfg(feature = "registry-notary-cel")]
        let cel_concurrency = self
            .cel_worker
            .as_ref()
            .map(|_| Arc::new(Semaphore::new(self.cel_config.worker_count.max(1))));
        let mut join_set = JoinSet::new();
        for item in prepared {
            let runtime = self.clone();
            let evidence = Arc::clone(&evidence);
            let permit_semaphore = Arc::clone(&subject_concurrency);
            #[cfg(feature = "registry-notary-cel")]
            let cel_concurrency = cel_concurrency.as_ref().map(Arc::clone);
            join_set.spawn(async move {
                let input_index = item.input_index;
                let audit = Arc::clone(&item.audit);
                let _permit = permit_semaphore
                    .acquire_owned()
                    .await
                    .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
                let result = runtime
                    .evaluate_prepared_registry_batch_item(
                        evidence,
                        item,
                        #[cfg(feature = "registry-notary-cel")]
                        cel_concurrency,
                    )
                    .await;
                Ok::<_, EvidenceError>((input_index, result, audit.snapshot()))
            });
        }

        let subject_count = request.items.len();
        let mut items: Vec<Option<BatchItemResponse>> = (0..subject_count).map(|_| None).collect();
        let mut succeeded = 0usize;
        let mut failed = 0usize;
        let mut retained_evaluations = Vec::new();
        while let Some(joined) = join_set.join_next().await {
            let (input_index, result, runtime_audit) = match joined {
                Ok(Ok(item_result)) => item_result,
                Ok(Err(error)) => return Err(error),
                Err(join_error) if join_error.is_panic() => {
                    tracing::error!(
                        target: "registry_notary_server::runtime",
                        error = %join_error,
                        "registry-backed batch subject task panicked",
                    );
                    return Err(EvidenceError::RuleEvaluationFailed);
                }
                Err(_) => return Err(EvidenceError::RuleEvaluationFailed),
            };
            let batch_item = &request.items[input_index];
            let target_ref = target_ref_view(&self.subject_access_rate_keys, &batch_item.target)?;
            let requester_ref = batch_item
                .requester
                .as_ref()
                .map(|requester| {
                    entity_ref_view(&self.subject_access_rate_keys, "requester", requester)
                })
                .transpose()?;
            let relay_forwarded_count = runtime_audit.relay_forwarded_count();
            let (_, relay_consultation_ids) = runtime_audit.into_parts();
            let runtime_audit = registry_notary_core::BatchItemRuntimeAudit {
                relay_forwarded_count,
                relay_consultation_ids,
            };
            match result {
                Ok(evaluated) => {
                    let results = evaluated.views;
                    succeeded += 1;
                    let evaluation_id = results.first().map(|result| result.evaluation_id.clone());
                    let claim_results = results
                        .iter()
                        .map(|result| batch_claim_result(&evidence, result))
                        .collect::<Result<Vec<_>, EvidenceError>>()?;
                    if let Some(first) = results.first() {
                        // Relay acquisition time belongs to claim provenance;
                        // evaluation retention starts when Notary stores it.
                        let stored_at = OffsetDateTime::now_utc();
                        retained_evaluations.push(registry_notary_core::StoredEvaluation {
                            client_id: principal.principal_id.clone(),
                            purpose: subject_purposes[input_index].clone(),
                            claim_ids: claim_ids(&request.claims),
                            claim_refs: request.claims.clone(),
                            disclosure: stored_disclosure(&results),
                            format: first.format.clone(),
                            results: results.clone(),
                            created_at: format_time(stored_at),
                            expires_at: format_time(default_stored_evaluation_expires_at(
                                stored_at,
                            )),
                            request_hash: request_hash.clone(),
                            issuance_provenance: evaluated.issuance_provenance,
                            subject_access: None,
                        });
                    }
                    items[input_index] = Some(BatchItemResponse {
                        input_index,
                        target_ref,
                        requester_ref,
                        evaluation_id,
                        status: BatchItemStatus::Succeeded,
                        claim_results,
                        errors: Vec::new(),
                        runtime_audit,
                    });
                }
                Err(error) => {
                    failed += 1;
                    items[input_index] = Some(BatchItemResponse {
                        input_index,
                        target_ref,
                        requester_ref,
                        evaluation_id: None,
                        status: BatchItemStatus::Failed,
                        claim_results: Vec::new(),
                        errors: vec![batch_item_error(&error)],
                        runtime_audit,
                    });
                }
            }
        }
        let response = BatchEvaluateResponse {
            batch_id: Ulid::new().to_string(),
            status: BatchStatus::Completed,
            claims: claim_ids(&request.claims),
            items: items
                .into_iter()
                .map(|item| item.ok_or(EvidenceError::RuleEvaluationFailed))
                .collect::<Result<Vec<_>, _>>()?,
            summary: BatchSummary { succeeded, failed },
        };
        idempotency_owner
            .complete(response, retained_evaluations)
            .await
    }

    async fn evaluate_prepared_registry_batch_item(
        &self,
        evidence: Arc<EvidenceConfig>,
        item: PreparedRegistryBatchItem,
        #[cfg(feature = "registry-notary-cel")] cel_concurrency: Option<Arc<Semaphore>>,
    ) -> Result<EvaluatedRegistryClaims, EvidenceError> {
        let now = OffsetDateTime::now_utc();
        let internal = self
            .evaluate_claims_dag(
                Arc::clone(&evidence),
                item.context,
                item.purpose,
                item.evaluation_id,
                now,
                item.claim_versions.clone(),
                item.levels,
                item.evaluation_capability,
                Some(item.relay_plan),
                #[cfg(feature = "registry-notary-cel")]
                cel_concurrency,
                None,
                EvaluationPolicy::default(),
            )
            .await?;
        let issuance_provenance = stored_issuance_provenance(
            &evidence,
            &item.request.claims,
            &item.claim_versions,
            &internal,
        )?;
        let views = item
            .request
            .claims
            .iter()
            .map(|claim_ref| {
                let claim = find_claim_for_selection(&evidence, claim_ref, &item.claim_versions)?;
                let result = internal
                    .get(claim_ref.id.as_str())
                    .ok_or(EvidenceError::RuleEvaluationFailed)?;
                view_claim(
                    &self.subject_access_rate_keys,
                    result,
                    claim,
                    item.disclosure,
                    &item.format,
                )
            })
            .collect::<Result<Vec<_>, EvidenceError>>()?;
        Ok(EvaluatedRegistryClaims {
            views,
            issuance_provenance,
        })
    }

    /// Like `evaluate` but without writing the per-subject evaluation to the
    /// store (the caller is responsible). Used by `batch_evaluate` so that
    /// store inserts happen on the calling task that owns `&EvidenceStore`.
    #[allow(clippy::too_many_arguments)]
    async fn evaluate_subject_for_batch(
        &self,
        evidence: Arc<EvidenceConfig>,
        principal: &EvidencePrincipal,
        evaluation_capability: EvaluationCapability,
        request: EvaluateRequest,
        purpose_override: &str,
        #[cfg(feature = "registry-notary-cel")] cel_concurrency: Option<Arc<Semaphore>>,
    ) -> Result<Vec<ClaimResultView>, EvidenceError> {
        ensure_evaluation_capability_matches_principal(principal, &evaluation_capability)?;
        if request.claims.is_empty() {
            return Err(EvidenceError::InvalidRequest);
        }
        let claim_versions = requested_claim_versions(&request.claims)?;
        for claim_id in &request.claims {
            require_evaluation_capability(&evaluation_capability, claim_id)?;
        }
        for claim_ref in &request.claims {
            let claim = find_claim_for_selection(&evidence, claim_ref, &claim_versions)?;
            require_claim_access(principal, claim)?;
        }
        let format = request
            .format
            .clone()
            .unwrap_or_else(|| FORMAT_CLAIM_RESULT_JSON.to_string());
        for claim_ref in &request.claims {
            require_claim_format(
                find_claim_for_selection(&evidence, claim_ref, &claim_versions)?,
                &format,
            )?;
        }
        let disclosure = requested_disclosure(
            &evidence,
            &request.claims,
            &claim_versions,
            &request.disclosure,
        )?;
        validate_requested_disclosure_before_source(
            &evidence,
            &request.claims,
            &claim_versions,
            disclosure,
        )?;
        let levels = build_claim_levels(&evidence, &request.claims, &claim_versions)?;
        if levels.iter().flatten().any(|claim_id| {
            find_claim_for_selection(&evidence, claim_id, &claim_versions)
                .is_ok_and(|claim| claim.evidence_mode.is_registry_backed())
        }) {
            return Err(EvidenceError::OperationUnsupported);
        }
        let evaluation_id = Ulid::new().to_string();
        let now = OffsetDateTime::now_utc();
        let internal = self
            .evaluate_claims_dag(
                Arc::clone(&evidence),
                request
                    .request_context()
                    .ok_or(EvidenceError::InvalidRequest)?,
                purpose_override.to_string(),
                evaluation_id.clone(),
                now,
                claim_versions.clone(),
                levels,
                evaluation_capability,
                None,
                #[cfg(feature = "registry-notary-cel")]
                cel_concurrency,
                None,
                // Batch evaluation is a machine-client flow with no named
                // evaluation policy; the policy fields stay unset.
                EvaluationPolicy::default(),
            )
            .await?;
        request
            .claims
            .iter()
            .map(|claim_id| {
                let claim = find_claim_for_selection(&evidence, claim_id, &claim_versions)?;
                let result = internal
                    .get(claim_id.id.as_str())
                    .ok_or(EvidenceError::RuleEvaluationFailed)?;
                view_claim(
                    &self.subject_access_rate_keys,
                    result,
                    claim,
                    disclosure,
                    &format,
                )
            })
            .collect::<Result<Vec<_>, EvidenceError>>()
    }

    /// Walk the claim `depends_on` DAG in topological levels, running all
    /// sibling claims at one level concurrently bounded by
    /// `concurrency.bindings`. Returns the populated `prior` map.
    #[allow(clippy::too_many_arguments)]
    async fn evaluate_claims_dag(
        &self,
        evidence: Arc<EvidenceConfig>,
        context: EvidenceRequestContext,
        purpose: String,
        evaluation_id: String,
        now: OffsetDateTime,
        claim_versions: ClaimVersionSelections,
        levels: Vec<Vec<String>>,
        evaluation_capability: EvaluationCapability,
        relay_plan: Option<Arc<RequestScopedRelayPlan>>,
        #[cfg(feature = "registry-notary-cel")] cel_concurrency: Option<Arc<Semaphore>>,
        correlation_id: Option<BoundedCorrelationId>,
        policy: EvaluationPolicy,
    ) -> Result<BTreeMap<String, ClaimResultInternal>, EvidenceError> {
        let prior: Arc<Mutex<BTreeMap<String, ClaimResultInternal>>> =
            Arc::new(Mutex::new(BTreeMap::new()));
        for level in levels {
            // Spawn one task per claim in this level. All deps are already in
            // `prior` because previous levels finished.
            let mut tasks: JoinSet<(String, Result<ClaimResultInternal, EvidenceError>)> =
                JoinSet::new();
            for claim_id in level {
                if prior
                    .lock()
                    .expect("prior mutex is not poisoned")
                    .contains_key(&claim_id)
                {
                    continue;
                }
                let ctx = ClaimEvaluationContext {
                    evidence: Arc::clone(&evidence),
                    subject_access_rate_keys: Arc::clone(&self.subject_access_rate_keys),
                    evaluation_capability: evaluation_capability.clone(),
                    relay_plan: relay_plan.as_ref().map(Arc::clone),
                    context: context.clone(),
                    purpose: purpose.clone(),
                    correlation_id: correlation_id.clone(),
                    evaluation_id: evaluation_id.clone(),
                    policy: policy.clone(),
                    now,
                    claim_versions: claim_versions.clone(),
                    #[cfg(feature = "registry-notary-cel")]
                    cel_worker: self.cel_worker.as_ref().map(Arc::clone),
                    #[cfg(feature = "registry-notary-cel")]
                    cel_concurrency: cel_concurrency.as_ref().map(Arc::clone),
                    #[cfg(feature = "registry-notary-cel")]
                    cel_config: Arc::clone(&self.cel_config),
                };
                let prior_for_task = Arc::clone(&prior);
                tasks.spawn(async move {
                    let correlation_id = ctx.correlation_id.clone();
                    let evaluation = evaluate_claim_task(ctx, &claim_id, prior_for_task);
                    let result = if let Some(correlation_id) = correlation_id {
                        with_request_correlation_id(correlation_id, evaluation).await
                    } else {
                        evaluation.await
                    };
                    (claim_id, result)
                });
            }
            while let Some(joined) = tasks.join_next().await {
                let (claim_id, result) = match joined {
                    Ok(pair) => pair,
                    Err(join_error) if join_error.is_panic() => {
                        tracing::error!(
                            target: "registry_notary_server::runtime",
                            error = %join_error,
                            "claim task panicked",
                        );
                        return Err(EvidenceError::RuleEvaluationFailed);
                    }
                    Err(_) => return Err(EvidenceError::RuleEvaluationFailed),
                };
                let value = result?;
                prior
                    .lock()
                    .expect("prior mutex is not poisoned")
                    .insert(claim_id, value);
            }
        }
        let map = Arc::try_unwrap(prior)
            .map_err(|_| EvidenceError::RuleEvaluationFailed)?
            .into_inner()
            .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
        Ok(map)
    }

    pub async fn render(
        &self,
        evidence: &EvidenceConfig,
        store: &EvidenceStore,
        principal: &EvidencePrincipal,
        request: RenderRequest,
    ) -> Result<Value, EvidenceError> {
        let evaluation = store
            .get(&request.evaluation_id, &principal.principal_id)
            .await?
            .ok_or(EvidenceError::EvaluationNotFound)?;
        if evaluation.client_id != principal.principal_id {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
        if request.format != evaluation.format {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
        let requested = request
            .disclosure
            .as_deref()
            .unwrap_or(evaluation.disclosure.as_str());
        if requested != evaluation.disclosure {
            return Err(EvidenceError::EvaluationBindingMismatch);
        }
        if let Some(claims) = &request.claims {
            if claims != &evaluation.claim_ids {
                return Err(EvidenceError::EvaluationBindingMismatch);
            }
        }
        if let Some(purpose) = request.purpose.as_deref() {
            if purpose != evaluation.purpose {
                return Err(EvidenceError::EvaluationBindingMismatch);
            }
        }
        render_results(evidence, &evaluation.results, &request.format)
    }
}

fn validate_request_variables_before_relay(
    evidence: &EvidenceConfig,
    context: &EvidenceRequestContext,
    claim_versions: &ClaimVersionSelections,
    levels: &[Vec<String>],
) -> Result<(), EvidenceError> {
    if context
        .variables
        .iter()
        .any(|(name, _)| !evidence.variables.contains_key(name))
    {
        return Err(EvidenceError::InvalidRequest);
    }
    for claim_id in levels.iter().flatten() {
        let claim = find_claim_for_selection(evidence, claim_id, claim_versions)?;
        if !claim.evidence_mode.is_registry_backed() {
            continue;
        }
        let RuleConfig::Cel { expression, .. } = &claim.rule else {
            continue;
        };
        let required = registry_cel_required_variables(
            expression,
            evidence.variables.keys().map(String::as_str),
        );
        if required
            .iter()
            .any(|name| context.variables.get(name).is_none())
        {
            return Err(EvidenceError::InvalidRequest);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn preflight_claim_closure(
    evidence: &EvidenceConfig,
    principal: &EvidencePrincipal,
    evaluation_capability: &EvaluationCapability,
    claim_versions: &ClaimVersionSelections,
    levels: &[Vec<String>],
    purpose: &str,
    relay_is_activated: bool,
) -> Result<(), EvidenceError> {
    for claim_id in levels.iter().flatten() {
        let claim = find_claim_for_selection(evidence, claim_id, claim_versions)?;
        if !claim.operations.evaluate.enabled {
            return Err(EvidenceError::OperationUnsupported);
        }
        require_claim_access(principal, claim)?;
        match &claim.evidence_mode {
            ClaimEvidenceMode::RegistryBacked { .. } => {
                require_relay_consultation_capability(evaluation_capability, &claim.id)?;
                if !relay_is_activated {
                    return Err(EvidenceError::EvidenceNotAvailable);
                }
                if claim.purpose.as_deref() != Some(purpose) {
                    return Err(EvidenceError::PurposeNotAllowed);
                }
            }
            ClaimEvidenceMode::SelfAttested => {}
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn plan_relay_consultations(
    evidence: &EvidenceConfig,
    principal: &EvidencePrincipal,
    context: &EvidenceRequestContext,
    claim_versions: &ClaimVersionSelections,
    levels: &[Vec<String>],
    purpose: &str,
    evaluation_id: Ulid,
    activated_relay: Option<&Arc<dyn ActivatedRelayConsultations>>,
    audit: Arc<EvaluationAuditCollector>,
    batch: Option<(&str, usize)>,
    evaluation_capability: &EvaluationCapability,
) -> Result<Option<Arc<RequestScopedRelayPlan>>, EvidenceError> {
    let mut entries = Vec::new();
    for claim_id in levels.iter().flatten() {
        let claim = find_claim_for_selection(evidence, claim_id, claim_versions)?;
        let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode else {
            continue;
        };
        let (_, consultation) = consultations
            .first_key_value()
            .filter(|_| consultations.len() == 1)
            .ok_or(EvidenceError::RuleEvaluationFailed)?;
        if !(1..=16).contains(&consultation.inputs.len()) {
            return Err(EvidenceError::RuleEvaluationFailed);
        }
        let inputs = consultation
            .inputs
            .iter()
            .map(|(input_name, input_mapping)| {
                context
                    .lookup_value(input_mapping.request_context_path())
                    .and_then(|value| canonical_request_scalar(&value))
                    .map(|value| (input_name.clone(), Zeroizing::new(value)))
                    .ok_or(EvidenceError::InvalidRequest)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let input_names = consultation.inputs.keys().cloned().collect::<Vec<_>>();
        let expected_result = relay_expected_result(
            evidence,
            consultation,
            claim
                .purpose
                .as_deref()
                .ok_or(EvidenceError::InvalidRequest)?,
            &input_names,
        )?;
        let key = ConsultationGroupKeyV1::new_with_expected_result(
            evaluation_id,
            principal.auth_profile_id,
            principal.principal_id.clone(),
            claim.required_scopes.clone(),
            consultation.profile.id.as_str(),
            consultation.profile.contract_hash.as_str(),
            purpose,
            inputs,
            expected_result,
        )
        .map_err(|_| EvidenceError::InvalidRequest)?;
        entries.push((claim.id.clone(), key));
    }
    if entries.is_empty() {
        return Ok(None);
    }
    let activated = activated_relay
        .map(Arc::clone)
        .ok_or(EvidenceError::EvidenceNotAvailable)?;
    let plan = match batch {
        Some((outer_key, item_position)) => {
            RequestScopedRelayPlan::new_batch(entries, outer_key, item_position, activated, audit)
        }
        None => RequestScopedRelayPlan::new(entries, activated, audit),
    };
    plan.map(Arc::new).map(Some).map_err(|_| {
        if matches!(
            evaluation_capability,
            EvaluationCapability::DelegatedAttestation { .. }
        ) {
            delegated_proof_denied()
        } else {
            EvidenceError::InvalidRequest
        }
    })
}

pub(super) fn canonical_request_scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => value.as_i64().map(|value| value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn relay_expected_result(
    _evidence: &EvidenceConfig,
    selected: &registry_notary_core::RelayConsultationConfig,
    _purpose: &str,
    _input_names: &[String],
) -> Result<RuntimeRelayExpectedResult, EvidenceError> {
    RuntimeRelayExpectedResult::output_map(selected.outputs.clone())
        .map_err(|_| EvidenceError::InvalidRequest)
}

fn stored_issuance_provenance(
    evidence: &EvidenceConfig,
    selected_claims: &[ClaimRef],
    claim_versions: &ClaimVersionSelections,
    internal: &BTreeMap<String, ClaimResultInternal>,
) -> Result<Option<StoredIssuanceProvenance>, EvidenceError> {
    // Retain restricted Relay identifiers only when the selected roots share
    // an actual credential profile. Root configuration validation closes both
    // sides of these bindings and validates the registry-backed dependency
    // closure. OID4VCI configurations use the same profile binding.
    let credential_capable = evidence
        .credential_profiles
        .iter()
        .any(|(profile_id, profile)| {
            selected_claims.iter().all(|claim_ref| {
                find_claim_for_selection(evidence, claim_ref, claim_versions).is_ok_and(|claim| {
                    claim
                        .credential_profiles
                        .iter()
                        .any(|candidate| candidate == profile_id)
                        && profile
                            .allowed_claims
                            .iter()
                            .any(|candidate| candidate == &claim.id)
                })
            })
        });
    if !credential_capable {
        return Ok(None);
    }

    let levels = build_claim_levels(evidence, selected_claims, claim_versions)?;
    let closure = levels.iter().flatten().collect::<Vec<_>>();
    if closure.len() > MAX_CLAIM_DEPENDENCY_NODES_V1 {
        return Err(EvidenceError::RuleEvaluationFailed);
    }
    for claim_id in &closure {
        if !find_claim_for_selection(evidence, claim_id.as_str(), claim_versions)?
            .evidence_mode
            .is_registry_backed()
        {
            return Ok(None);
        }
    }

    let mut claims = Vec::with_capacity(closure.len());
    let mut consultations: BTreeMap<String, StoredIssuanceConsultationProvenance> = BTreeMap::new();
    for claim_id in closure {
        let provenance = internal
            .get(claim_id.as_str())
            .and_then(|result| result.own_issuance_provenance.clone())
            .ok_or(EvidenceError::RuleEvaluationFailed)?;
        match consultations.get(&provenance.consultation.consultation_id) {
            Some(existing) if existing.acquired_at != provenance.consultation.acquired_at => {
                return Err(EvidenceError::RuleEvaluationFailed);
            }
            Some(_) => {}
            None => {
                consultations.insert(
                    provenance.consultation.consultation_id.clone(),
                    provenance.consultation.clone(),
                );
            }
        }
        let result = internal
            .get(claim_id.as_str())
            .ok_or(EvidenceError::RuleEvaluationFailed)?;
        let mut claim = provenance.claim;
        claim.execution_binding = issuance_execution_binding(
            &claim,
            &provenance.consultation,
            &result.evaluation_id,
            &format_time(result.issued_at),
            &result.provenance,
        )?;
        claims.push(claim);
    }
    Ok(Some(StoredIssuanceProvenance {
        claims,
        consultations: consultations.into_values().collect(),
    }))
}

fn default_stored_evaluation_expires_at(stored_at: OffsetDateTime) -> OffsetDateTime {
    stored_at + time::Duration::minutes(15)
}

/// Derive the evaluation policy identity for provenance from stored
/// subject-access metadata. Self-attestation results are produced under the
/// canonical `subject-access` evaluation policy; the version and hash come
/// from the metadata when present. Non-subject-access flows pass `None` and
/// receive an empty policy.
pub(super) fn evaluation_policy_from_subject_access(
    subject_access: Option<&StoredSubjectAccessMetadata>,
) -> EvaluationPolicy {
    match subject_access {
        Some(metadata) => EvaluationPolicy {
            policy_id: Some(SELF_ATTESTATION_POLICY_ID.to_string()),
            policy_version: metadata
                .policy_version
                .as_ref()
                .map(|version| version.as_str().to_string()),
            policy_hash: metadata
                .policy_hash
                .as_ref()
                .map(|hash| hash.as_str().to_string()),
        },
        None => EvaluationPolicy::default(),
    }
}

/// Canonical evaluation `policy_id` for subject-access flows (D3).
pub(super) const SELF_ATTESTATION_POLICY_ID: &str = "subject-access";

pub(super) fn stored_evaluation_client_id(
    principal: &EvidencePrincipal,
    subject_access: Option<&StoredSubjectAccessMetadata>,
) -> String {
    subject_access
        .map(|metadata| metadata.principal_hash.as_str().to_string())
        .unwrap_or_else(|| principal.principal_id.clone())
}

pub(super) async fn evaluate_claim_task(
    ctx: ClaimEvaluationContext,
    claim_id: &str,
    prior: Arc<Mutex<BTreeMap<String, ClaimResultInternal>>>,
) -> Result<ClaimResultInternal, EvidenceError> {
    if let Some(existing) = prior
        .lock()
        .expect("prior mutex is not poisoned")
        .get(claim_id)
        .cloned()
    {
        return Ok(existing);
    }
    let claim = find_claim_for_selection(&ctx.evidence, claim_id, &ctx.claim_versions)?.clone();
    if !claim.operations.evaluate.enabled {
        return Err(EvidenceError::OperationUnsupported);
    }
    ensure_delegated_capability_context_binding(&ctx)?;
    if let Some(proof_claim_id) = ctx
        .evaluation_capability
        .required_delegated_proof_for_claim(claim_id)
    {
        let proof_satisfied = prior
            .lock()
            .expect("prior mutex is not poisoned")
            .get(proof_claim_id)
            .and_then(|proof| proof.value.as_bool())
            .unwrap_or(false);
        if !proof_satisfied {
            return Err(delegated_relationship_unproven());
        }
    }
    let delegated_proof_claim = ctx.evaluation_capability.is_delegated_proof_claim(claim_id);
    let (consultation_outputs, observed_at, mut relay_consultation_ids, own_issuance_provenance) =
        match &claim.evidence_mode {
            ClaimEvidenceMode::SelfAttested => (BTreeMap::new(), None, BTreeSet::new(), None),
            ClaimEvidenceMode::RegistryBacked { consultations } => {
                require_relay_consultation_capability(&ctx.evaluation_capability, &claim.id)?;
                let (_, consultation) = consultations
                    .first_key_value()
                    .filter(|_| consultations.len() == 1)
                    .ok_or(EvidenceError::RuleEvaluationFailed)?;
                let plan = ctx
                    .relay_plan
                    .as_ref()
                    .ok_or(EvidenceError::EvidenceNotAvailable)?;
                let result = plan.consult(&claim.id).await.map_err(|_| {
                    if delegated_proof_claim {
                        delegated_proof_denied()
                    } else {
                        EvidenceError::EvidenceNotAvailable
                    }
                })?;
                let relay_outcome = result.outcome();
                let consultation_outputs_result = match relay_outcome {
                    RuntimeRelayOutcome::Match => materialize_relay_match(&claim, &result),
                    RuntimeRelayOutcome::NoMatch
                        if matches!(&claim.rule, RuleConfig::ConsultationOutput { .. })
                            && registry_claim_has_typed_outputs(&claim) =>
                    {
                        materialize_relay_absence(&claim)
                    }
                    RuntimeRelayOutcome::NoMatch
                        if matches!(&claim.rule, RuleConfig::ConsultationOutput { .. }) =>
                    {
                        Err(EvidenceError::EvidenceNotAvailable)
                    }
                    RuntimeRelayOutcome::NoMatch
                        if matches!(&claim.rule, RuleConfig::Cel { .. }) =>
                    {
                        materialize_relay_absence(&claim)
                    }
                    RuntimeRelayOutcome::NoMatch => Ok(BTreeMap::new()),
                    RuntimeRelayOutcome::Ambiguous => Err(EvidenceError::EvidenceNotAvailable),
                };
                let consultation_outputs = consultation_outputs_result.map_err(|error| {
                    if delegated_proof_claim {
                        if relay_outcome == RuntimeRelayOutcome::NoMatch {
                            delegated_relationship_unproven()
                        } else {
                            delegated_proof_denied()
                        }
                    } else {
                        error
                    }
                })?;
                let acquired_at = result.acquired_at();
                let consultation_id = result.consultation_id().to_string();
                (
                    consultation_outputs,
                    Some(acquired_at),
                    BTreeSet::from([consultation_id.clone()]),
                    Some(ClaimIssuanceProvenanceInternal {
                        claim: StoredIssuanceClaimProvenance {
                            claim_id: claim.id.clone(),
                            claim_version: claim.version.clone(),
                            relay_profile_id: consultation.profile.id.clone(),
                            relay_contract_hash: consultation.profile.contract_hash.clone(),
                            canonical_purpose: ctx.purpose.clone(),
                            consultation_id: consultation_id.clone(),
                            execution_binding: String::new(),
                        },
                        consultation: StoredIssuanceConsultationProvenance {
                            consultation_id,
                            acquired_at: format_time(acquired_at),
                        },
                    }),
                )
            }
        };
    // Relay acquisition time pins the result to the consultation evidence.
    let issued_at = observed_at.unwrap_or(ctx.now);
    let value_result = match &claim.rule {
        RuleConfig::ConsultationOutput {
            consultation,
            output,
        } => {
            let record = consultation_outputs
                .get(consultation)
                .ok_or(EvidenceError::EvidenceNotAvailable)?;
            let value = get_json_path(record, output)
                .cloned()
                .ok_or(EvidenceError::RuleEvaluationFailed)?;
            validate_claim_value_config(&value, &claim.value)?;
            Ok(value)
        }
        RuleConfig::ConsultationMatched { consultation } => {
            let value = Value::Bool(consultation_outputs.contains_key(consultation));
            validate_claim_value_config(&value, &claim.value)?;
            Ok(value)
        }
        RuleConfig::Cel {
            expression,
            bindings,
        } => {
            let snapshot = prior.lock().expect("prior mutex is not poisoned").clone();
            let target_subject = ctx.context.target_subject();
            #[cfg(feature = "registry-notary-cel")]
            let _cel_permit = if let Some(cel_concurrency) = ctx.cel_concurrency.as_ref() {
                Some(
                    Arc::clone(cel_concurrency)
                        .acquire_owned()
                        .await
                        .map_err(|_| EvidenceError::RuleEvaluationFailed)?,
                )
            } else {
                None
            };
            let value = evaluate_cel_expression(&CelEvaluationContext {
                evidence: &ctx.evidence,
                claim: &claim,
                expression,
                bindings,
                claims: &snapshot,
                consultation_outputs: &consultation_outputs,
                variables: &ctx.context.variables,
                subject: target_subject.as_ref(),
                target: &ctx.context.target,
                purpose: ctx.purpose.as_str(),
                today: ctx.now.date().to_string(),
                #[cfg(feature = "registry-notary-cel")]
                worker: ctx.cel_worker.as_deref(),
                #[cfg(feature = "registry-notary-cel")]
                config: &ctx.cel_config,
            })
            .await?;
            validate_claim_value_config(&value, &claim.value)?;
            Ok(value)
        }
    };
    let value = match value_result {
        Ok(value) => value,
        Err(_) if delegated_proof_claim => return Err(delegated_proof_denied()),
        Err(error) => return Err(error),
    };
    if delegated_proof_claim && value.as_bool() != Some(true) {
        return Err(delegated_relationship_unproven());
    }
    {
        let snapshot = prior.lock().expect("prior mutex is not poisoned");
        for dep in claim
            .depends_on
            .iter()
            .filter_map(|dep_id| snapshot.get(dep_id))
        {
            relay_consultation_ids.extend(dep.relay_consultation_ids.iter().cloned());
        }
    }
    let mut provenance = ClaimProvenance::new(
        ctx.evidence.service_id.clone(),
        ctx.evaluation_id.clone(),
        claim.id.clone(),
        claim.version.clone(),
        ProvenanceUsed {
            relay_consultation_count: relay_consultation_ids.len(),
        },
    );
    provenance.generated_by.policy_id = ctx.policy.policy_id.clone();
    provenance.generated_by.policy_version = ctx.policy.policy_version.clone();
    provenance.generated_by.policy_hash = ctx.policy.policy_hash.clone();
    Ok(ClaimResultInternal {
        evaluation_id: ctx.evaluation_id.clone(),
        claim_id: claim.id.clone(),
        claim_version: claim.version.clone(),
        subject_type: claim.subject_type.clone(),
        target: ctx.context.target.clone(),
        requester: ctx.context.requester.clone(),
        value,
        redaction_fields: BTreeSet::new(),
        issued_at,
        expires_at: None,
        provenance,
        relay_consultation_ids,
        own_issuance_provenance,
    })
}

pub(super) fn materialize_relay_match(
    claim: &ClaimDefinition,
    result: &RuntimeRelayConsultationResult,
) -> Result<BTreeMap<String, Value>, EvidenceError> {
    let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode else {
        return Err(EvidenceError::RuleEvaluationFailed);
    };
    let (consultation_name, _) = consultations
        .first_key_value()
        .filter(|_| consultations.len() == 1)
        .ok_or(EvidenceError::RuleEvaluationFailed)?;
    let (_, consultation) = consultations
        .first_key_value()
        .filter(|_| consultations.len() == 1)
        .ok_or(EvidenceError::RuleEvaluationFailed)?;
    if consultation.outputs.is_empty() {
        return Err(EvidenceError::RuleEvaluationFailed);
    }
    let mut record = result
        .outputs()
        .ok_or(EvidenceError::RuleEvaluationFailed)?
        .to_json_object();
    record.insert("matched".to_string(), Value::Bool(true));
    record.insert("outcome".to_string(), Value::String("match".to_string()));
    Ok(BTreeMap::from([(
        consultation_name.clone(),
        Value::Object(record),
    )]))
}

pub(super) fn materialize_relay_absence(
    claim: &ClaimDefinition,
) -> Result<BTreeMap<String, Value>, EvidenceError> {
    let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode else {
        return Err(EvidenceError::RuleEvaluationFailed);
    };
    let (consultation_name, consultation) = consultations
        .first_key_value()
        .filter(|_| consultations.len() == 1 && !consultations.is_empty())
        .ok_or(EvidenceError::RuleEvaluationFailed)?;
    let mut record: serde_json::Map<String, Value> = consultation
        .outputs
        .keys()
        .map(|name| (name.clone(), Value::Null))
        .collect();
    record.insert("matched".to_string(), Value::Bool(false));
    record.insert("outcome".to_string(), Value::String("no_match".to_string()));
    Ok(BTreeMap::from([(
        consultation_name.clone(),
        Value::Object(record),
    )]))
}

fn registry_claim_has_typed_outputs(claim: &ClaimDefinition) -> bool {
    let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode else {
        return false;
    };
    consultations
        .first_key_value()
        .is_some_and(|(_, consultation)| !consultation.outputs.is_empty())
}
