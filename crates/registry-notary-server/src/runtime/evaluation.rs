// SPDX-License-Identifier: Apache-2.0

use super::cel::*;
use super::*;

#[derive(Debug, Clone)]
pub struct RegistryNotaryRuntime {
    self_attestation_rate_keys: Arc<SelfAttestationRateLimitKeys>,
    #[cfg(feature = "registry-notary-cel")]
    cel_worker: Option<Arc<CelWorker>>,
    #[cfg(feature = "registry-notary-cel")]
    cel_config: Arc<RegistryNotaryCelConfig>,
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
        Self::new_with_self_attestation_rate_keys(Arc::new(SelfAttestationRateLimitKeys::new(
            audit_hasher,
        )))
    }

    #[must_use]
    pub fn new_with_self_attestation_rate_keys(
        self_attestation_rate_keys: Arc<SelfAttestationRateLimitKeys>,
    ) -> Self {
        Self {
            self_attestation_rate_keys,
            #[cfg(feature = "registry-notary-cel")]
            cel_worker: None,
            #[cfg(feature = "registry-notary-cel")]
            cel_config: Arc::new(RegistryNotaryCelConfig::default()),
        }
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

    pub fn service_document_with_self_attestation(
        evidence: &EvidenceConfig,
        self_attestation: &SelfAttestationConfig,
        include_self_attestation_details: bool,
    ) -> Value {
        let mut document = Self::service_document(evidence);
        if self_attestation.enabled {
            let mut self_attestation_document = json!({
                "enabled": true,
            });
            if include_self_attestation_details {
                self_attestation_document = json!({
                    "enabled": true,
                    "allowed_operations": self_attestation.allowed_operations,
                    "allowed_claim_ids": self_attestation.allowed_claims,
                    "allowed_formats": self_attestation.allowed_formats,
                    "allowed_disclosures": self_attestation.allowed_disclosures,
                    "credential_profile_ids": self_attestation.credential_profiles,
                    "subject_id_type": self_attestation.subject_binding.id_type,
                    "token_claim_name": self_attestation.subject_binding.token_claim,
                    "scope_policy": self_attestation.scope_policy,
                    "required_scopes": self_attestation.required_scopes,
                    "max_evaluation_age_seconds": self_attestation
                        .token_policy
                        .max_evaluation_age_seconds,
                    "max_credential_validity_seconds": self_attestation
                        .token_policy
                        .max_credential_validity_seconds,
                    "rate_limit_mode": self_attestation.rate_limits.mode,
                });
            }
            document["self_attestation"] = self_attestation_document;
        }
        document
    }

    pub fn list_claims<R: SourceReader + ?Sized>(
        evidence: &EvidenceConfig,
        source: &R,
        principal: &EvidencePrincipal,
    ) -> Vec<Value> {
        evidence
            .claims
            .iter()
            .filter(|claim| principal_can_see_claim(evidence, source, principal, claim))
            .map(claim_summary)
            .collect()
    }

    pub fn get_claim<R: SourceReader + ?Sized>(
        evidence: &EvidenceConfig,
        source: &R,
        principal: &EvidencePrincipal,
        claim_id: &str,
    ) -> Result<Value, EvidenceError> {
        let claim = find_claim(evidence, claim_id)?;
        if !principal_can_see_claim(evidence, source, principal, claim) {
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
        source: Arc<dyn SourceReader>,
        store: &EvidenceStore,
        principal: &EvidencePrincipal,
        request: EvaluateRequest,
        header_purpose: Option<&str>,
    ) -> Result<Vec<ClaimResultView>, EvidenceError> {
        let request_claim_ids = claim_ids(&request.claims);
        let source_capability = source_capability_for_principal(
            &self.self_attestation_rate_keys,
            principal,
            &request_claim_ids,
        )?;
        self.evaluate_with_source_capability(
            evidence,
            source,
            store,
            principal,
            source_capability,
            request,
            header_purpose,
            None,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn evaluate_with_source_capability(
        &self,
        evidence: Arc<EvidenceConfig>,
        source: Arc<dyn SourceReader>,
        store: &EvidenceStore,
        principal: &EvidencePrincipal,
        source_capability: SourceCapability,
        request: EvaluateRequest,
        header_purpose: Option<&str>,
        self_attestation: Option<StoredSelfAttestationMetadata>,
        correlation_id: Option<BoundedCorrelationId>,
    ) -> Result<Vec<ClaimResultView>, EvidenceError> {
        ensure_source_capability_matches_principal(principal, &source_capability)?;
        if request.claims.is_empty() {
            return Err(EvidenceError::InvalidRequest);
        }
        let target = request
            .target
            .as_ref()
            .ok_or(EvidenceError::InvalidRequest)?;
        if !target.has_matching_input() {
            return Err(EvidenceError::TargetAttributesInsufficient);
        }
        let claim_versions = requested_claim_versions(&request.claims)?;
        let request_claim_ids = claim_ids(&request.claims);
        for claim_id in &request.claims {
            require_source_read_capability(&source_capability, claim_id)?;
        }
        for claim_ref in &request.claims {
            let claim = find_claim_for_selection(&evidence, claim_ref, &claim_versions)?;
            require_claim_access(&evidence, source.as_ref(), principal, claim)?;
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
        for claim_id in &request.claims {
            require_claim_format(&evidence, claim_id, &format)?;
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
        let request_hash = hash_json(&request)?;
        let evaluation_id = Ulid::new().to_string();
        let now = OffsetDateTime::now_utc();
        let binding_concurrency = Arc::new(Semaphore::new(evidence.concurrency.bindings));
        #[cfg(feature = "registry-notary-cel")]
        let cel_concurrency = self
            .cel_worker
            .as_ref()
            .map(|_| Arc::new(Semaphore::new(self.cel_config.worker_count.max(1))));
        let policy = evaluation_policy_from_self_attestation(self_attestation.as_ref());
        let request_claim_refs = scoped_authorization_claim_refs(
            &evidence,
            &request.claims,
            &claim_versions,
            &source_capability,
        )?;
        let trusted_policy =
            TrustedPolicyContext::from_principal(principal).with_request_claims(request_claim_refs);
        let internal = self
            .evaluate_claims_dag(
                Arc::clone(&evidence),
                Arc::clone(&source),
                request
                    .request_context()
                    .ok_or(EvidenceError::InvalidRequest)?,
                trusted_policy,
                purpose.clone(),
                disclosure,
                format.clone(),
                evaluation_id.clone(),
                now,
                request.claims.clone(),
                claim_versions.clone(),
                binding_concurrency,
                source_capability,
                None, // single-subject evaluate: no cross-subject memo needed
                #[cfg(feature = "registry-notary-cel")]
                cel_concurrency,
                correlation_id,
                policy,
            )
            .await?;
        let views = request
            .claims
            .iter()
            .map(|claim_id| {
                let claim = find_claim_for_selection(&evidence, claim_id, &claim_versions)?;
                let result = internal
                    .get(claim_id.id.as_str())
                    .ok_or(EvidenceError::RuleEvaluationFailed)?;
                view_claim(
                    &self.self_attestation_rate_keys,
                    result,
                    claim,
                    disclosure,
                    &format,
                )
            })
            .collect::<Result<Vec<_>, EvidenceError>>()?;
        let expires_at = self_attestation
            .as_ref()
            .and_then(|metadata| metadata.evaluation_expires_at.as_deref())
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            .unwrap_or(now + time::Duration::minutes(15));
        let client_id = stored_evaluation_client_id(principal, self_attestation.as_ref());
        store.insert(registry_notary_core::StoredEvaluation {
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
            self_attestation,
        });
        Ok(views)
    }

    pub async fn batch_evaluate(
        &self,
        evidence: Arc<EvidenceConfig>,
        source: Arc<dyn SourceReader>,
        store: &EvidenceStore,
        principal: &EvidencePrincipal,
        request: BatchEvaluateRequest,
        options: BatchEvaluateOptions<'_>,
    ) -> Result<BatchEvaluateResponse, EvidenceError> {
        if principal.is_self_attestation() {
            return Err(EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::BatchDenied,
            });
        }
        if request.claims.is_empty() || request.items.is_empty() {
            return Err(EvidenceError::InvalidRequest);
        }
        let request_claim_ids = claim_ids(&request.claims);
        let request_hash = batch_request_hash(&request)?;
        let scoped_key = options
            .idempotency_key
            .map(|key| batch_idempotency_key(&principal.principal_id, key));
        if let Some(key) = scoped_key.as_deref() {
            if let Some(response) = store.idempotent_batch(key, &request_hash)? {
                return Ok(response);
            }
        }
        let claim_versions = requested_claim_versions(&request.claims)?;
        let source_capability = source_capability_for_principal(
            &self.self_attestation_rate_keys,
            principal,
            &request_claim_ids,
        )?;
        let max_subjects = max_batch_subjects(&evidence, &request.claims, &claim_versions)?;
        if request.items.len() > max_subjects {
            return Err(EvidenceError::BatchTooLarge);
        }
        let batch_purpose =
            resolve_batch_default_purpose(options.header_purpose, request.purpose.as_deref())?;
        let subject_purposes =
            resolve_batch_subject_purposes(&request.items, batch_purpose.as_deref())?;
        let unique_purposes =
            validate_batch_inputs_and_collect_purposes(&request.items, &subject_purposes)?;
        for purpose in unique_purposes {
            require_purpose_allowed(&evidence, &request.claims, &claim_versions, purpose)?;
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
        // Per-batch memoization table shared across all concurrent subject
        // tasks. Scoped to this `batch_evaluate` call; dropped when the call
        // returns, so no state leaks between batches. Tests can pre-create the
        // table via `options.memo_observer` to read counters after the call.
        let fetch_memo: FetchMemo = options
            .memo_observer
            .map(Arc::clone)
            .unwrap_or_else(|| Arc::new(MemoState::new()));
        let request_claim_refs = selected_claim_refs(&evidence, &request.claims, &claim_versions)?;
        let trusted_policy =
            TrustedPolicyContext::from_principal(principal).with_request_claims(request_claim_refs);
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
        // Stage 3: when a connection declares `bulk_mode != None`, prefetch
        // all bindings across all target contexts via `SourceReader::read_many`
        // and seed the memo with the results. The per-target evaluation pipeline
        // then naturally hits the memo and skips its own per-target upstream
        // call. We do this before the JoinSet so the bulk request runs
        // exactly once per group instead of being raced by N sibling subject
        // tasks.
        let mut prefetch_contexts_by_purpose: BTreeMap<String, Vec<EvidenceRequestContext>> =
            BTreeMap::new();
        for (item, purpose) in request.items.iter().zip(&subject_purposes) {
            prefetch_contexts_by_purpose
                .entry(purpose.clone())
                .or_default()
                .push(item.request_context());
        }
        for (purpose, contexts) in prefetch_contexts_by_purpose {
            prefetch_bulk_bindings(
                Arc::clone(&evidence),
                Arc::clone(&source),
                source_capability.clone(),
                &contexts,
                &request.claims,
                &claim_versions,
                purpose.as_str(),
                disclosure,
                FORMAT_CLAIM_RESULT_JSON,
                &trusted_policy,
                Arc::clone(&fetch_memo),
            )
            .await;
        }
        let mut join_set: JoinSet<(usize, Result<Vec<ClaimResultView>, EvidenceError>)> =
            JoinSet::new();
        for (input_index, item) in request.items.clone().into_iter().enumerate() {
            let runtime = self.clone();
            let evidence = Arc::clone(&evidence);
            let source = Arc::clone(&source);
            let permit_semaphore = Arc::clone(&subject_concurrency);
            let claims_list = request.claims.clone();
            let disclosure = request.disclosure.clone();
            let format = request.format.clone();
            let purpose_for_task = subject_purposes[input_index].clone();
            let principal_id = principal.principal_id.clone();
            let principal_scopes = principal.scopes.clone();
            let principal_authorization_details = principal.authorization_details.clone();
            let memo_for_task = Arc::clone(&fetch_memo);
            let source_capability = source_capability.clone();
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
                    claims: claims_list,
                    disclosure,
                    format,
                    purpose: Some(purpose_for_task.clone()),
                };
                let principal = EvidencePrincipal {
                    principal_id,
                    scopes: principal_scopes,
                    access_mode: registry_notary_core::AccessMode::MachineClient,
                    verified_claims: None,
                    authorization_details: principal_authorization_details,
                };
                let result = runtime
                    .evaluate_subject_for_batch(
                        evidence,
                        source,
                        &principal,
                        source_capability,
                        eval,
                        purpose_for_task.as_str(),
                        memo_for_task,
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
                    // Surface the per-subject evaluation in the store after we
                    // have the result. Doing this inside the task would require
                    // an Arc<EvidenceStore>; instead we walk results here on the
                    // calling task which still owns the &EvidenceStore.
                    if let Some(first) = results.first() {
                        let now_parsed = OffsetDateTime::parse(&first.issued_at, &Rfc3339)
                            .unwrap_or(OffsetDateTime::now_utc());
                        let expires_at = now_parsed + time::Duration::minutes(15);
                        store.insert(registry_notary_core::StoredEvaluation {
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
                            created_at: first.issued_at.clone(),
                            expires_at: format_time(expires_at),
                            request_hash: request_hash.clone(),
                            self_attestation: None,
                        });
                    }
                    succeeded += 1;
                    let batch_item = &request.items[input_index];
                    let target_ref =
                        target_ref_view(&self.self_attestation_rate_keys, &batch_item.target)?;
                    let requester_ref = batch_item
                        .requester
                        .as_ref()
                        .map(|requester| {
                            entity_ref_view(
                                &self.self_attestation_rate_keys,
                                "requester",
                                requester,
                            )
                        })
                        .transpose()?;
                    let matching = results.first().and_then(|result| result.matching.clone());
                    items[input_index] = Some(BatchItemResponse {
                        input_index,
                        target_ref,
                        requester_ref,
                        matching,
                        evaluation_id,
                        status: BatchItemStatus::Succeeded,
                        claim_results,
                        errors: Vec::new(),
                    });
                }
                Err(error) => {
                    failed += 1;
                    let batch_item = &request.items[input_index];
                    let target_ref =
                        target_ref_view(&self.self_attestation_rate_keys, &batch_item.target)?;
                    let requester_ref = batch_item
                        .requester
                        .as_ref()
                        .map(|requester| {
                            entity_ref_view(
                                &self.self_attestation_rate_keys,
                                "requester",
                                requester,
                            )
                        })
                        .transpose()?;
                    items[input_index] = Some(BatchItemResponse {
                        input_index,
                        target_ref,
                        requester_ref,
                        matching: None,
                        evaluation_id: None,
                        status: BatchItemStatus::Failed,
                        claim_results: Vec::new(),
                        errors: vec![batch_item_error(&error)],
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
        if let Some(key) = scoped_key {
            store.insert_idempotent_batch(key, request_hash, response.clone());
        }
        Ok(response)
    }

    /// Like `evaluate` but without writing the per-subject evaluation to the
    /// store (the caller is responsible). Used by `batch_evaluate` so that
    /// store inserts happen on the calling task that owns `&EvidenceStore`.
    /// Accepts the per-batch memoization table so sibling subjects can share
    /// upstream reads.
    #[allow(clippy::too_many_arguments)]
    async fn evaluate_subject_for_batch(
        &self,
        evidence: Arc<EvidenceConfig>,
        source: Arc<dyn SourceReader>,
        principal: &EvidencePrincipal,
        source_capability: SourceCapability,
        request: EvaluateRequest,
        purpose_override: &str,
        fetch_memo: FetchMemo,
        #[cfg(feature = "registry-notary-cel")] cel_concurrency: Option<Arc<Semaphore>>,
    ) -> Result<Vec<ClaimResultView>, EvidenceError> {
        ensure_source_capability_matches_principal(principal, &source_capability)?;
        if request.claims.is_empty() {
            return Err(EvidenceError::InvalidRequest);
        }
        let claim_versions = requested_claim_versions(&request.claims)?;
        for claim_id in &request.claims {
            require_source_read_capability(&source_capability, claim_id)?;
        }
        for claim_ref in &request.claims {
            let claim = find_claim_for_selection(&evidence, claim_ref, &claim_versions)?;
            require_claim_access(&evidence, source.as_ref(), principal, claim)?;
        }
        let format = request
            .format
            .clone()
            .unwrap_or_else(|| FORMAT_CLAIM_RESULT_JSON.to_string());
        for claim_id in &request.claims {
            require_claim_format(&evidence, claim_id, &format)?;
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
        let evaluation_id = Ulid::new().to_string();
        let now = OffsetDateTime::now_utc();
        let binding_concurrency = Arc::new(Semaphore::new(evidence.concurrency.bindings));
        let internal = self
            .evaluate_claims_dag(
                Arc::clone(&evidence),
                Arc::clone(&source),
                request
                    .request_context()
                    .ok_or(EvidenceError::InvalidRequest)?,
                TrustedPolicyContext::from_principal(principal).with_request_claims(
                    selected_claim_refs(&evidence, &request.claims, &claim_versions)?,
                ),
                purpose_override.to_string(),
                disclosure,
                format.clone(),
                evaluation_id.clone(),
                now,
                request.claims.clone(),
                claim_versions.clone(),
                binding_concurrency,
                source_capability,
                Some(fetch_memo),
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
                    &self.self_attestation_rate_keys,
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
        source: Arc<dyn SourceReader>,
        context: EvidenceRequestContext,
        trusted_policy: TrustedPolicyContext,
        purpose: String,
        disclosure: DisclosureProfile,
        format: String,
        evaluation_id: String,
        now: OffsetDateTime,
        requested: Vec<ClaimRef>,
        claim_versions: ClaimVersionSelections,
        binding_concurrency: Arc<Semaphore>,
        source_capability: SourceCapability,
        fetch_memo: Option<FetchMemo>,
        #[cfg(feature = "registry-notary-cel")] cel_concurrency: Option<Arc<Semaphore>>,
        correlation_id: Option<BoundedCorrelationId>,
        policy: EvaluationPolicy,
    ) -> Result<BTreeMap<String, ClaimResultInternal>, EvidenceError> {
        let levels = build_claim_levels(&evidence, &requested, &claim_versions)?;
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
                    source: Arc::clone(&source),
                    self_attestation_rate_keys: Arc::clone(&self.self_attestation_rate_keys),
                    source_capability: source_capability.clone(),
                    context: context.clone(),
                    trusted_policy: trusted_policy.clone(),
                    purpose: purpose.clone(),
                    disclosure,
                    format: format.clone(),
                    correlation_id: correlation_id.clone(),
                    evaluation_id: evaluation_id.clone(),
                    policy: policy.clone(),
                    now,
                    binding_concurrency: Arc::clone(&binding_concurrency),
                    fetch_memo: fetch_memo.as_ref().map(Arc::clone),
                    claim_versions: claim_versions.clone(),
                    #[cfg(feature = "registry-notary-cel")]
                    cel_worker: self.cel_worker.as_ref().map(Arc::clone),
                    #[cfg(feature = "registry-notary-cel")]
                    cel_concurrency: cel_concurrency.as_ref().map(Arc::clone),
                    #[cfg(feature = "registry-notary-cel")]
                    cel_config: Arc::clone(&self.cel_config),
                };
                let prior_for_task = Arc::clone(&prior);
                // We do not acquire a permit here. The `bindings` cap applies to
                // outbound source reads (the actual upstream work) and is taken
                // inside `load_sources`. Acquiring at this level too would
                // deadlock when bindings <= sibling claims, since each spawned
                // task would hold a permit and then block waiting for one inside
                // load_sources.
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

    pub fn render(
        &self,
        evidence: &EvidenceConfig,
        store: &EvidenceStore,
        principal: &EvidencePrincipal,
        request: RenderRequest,
    ) -> Result<Value, EvidenceError> {
        let evaluation = store
            .get(&request.evaluation_id)
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

/// Derive the evaluation policy identity for provenance from stored
/// self-attestation metadata. Self-attestation results are produced under the
/// canonical `self-attestation` evaluation policy; the version and hash come
/// from the metadata when present. Non-self-attestation flows pass `None` and
/// receive an empty policy.
pub(super) fn evaluation_policy_from_self_attestation(
    self_attestation: Option<&StoredSelfAttestationMetadata>,
) -> EvaluationPolicy {
    match self_attestation {
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

/// Canonical evaluation `policy_id` for self-attestation flows (D3).
pub(super) const SELF_ATTESTATION_POLICY_ID: &str = "self-attestation";

pub(super) fn stored_evaluation_client_id(
    principal: &EvidencePrincipal,
    self_attestation: Option<&StoredSelfAttestationMetadata>,
) -> String {
    self_attestation
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
        .source_capability
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
    let delegated_proof_claim = ctx.source_capability.is_delegated_proof_claim(claim_id);
    let sources_result = load_sources(
        Arc::clone(&ctx.evidence),
        Arc::clone(&ctx.source),
        Arc::clone(&claim_arc(&claim)),
        ctx.source_capability.clone(),
        ctx.context.clone(),
        ctx.trusted_policy.clone(),
        ctx.purpose.clone(),
        ctx.disclosure,
        ctx.format.clone(),
        Arc::clone(&ctx.binding_concurrency),
        ctx.fetch_memo.clone(),
    )
    .await;
    let (sources, observed_at, redaction_fields, matching_policy_audit) = match sources_result {
        Ok(loaded) => loaded,
        Err(_) if delegated_proof_claim => return Err(delegated_proof_denied()),
        Err(error) => return Err(error),
    };
    // When a memoized entry was used, `observed_at` carries the timestamp of
    // the original upstream read. Use that as `iat` so sibling subjects that
    // share a read produce credentials with identical issued_at values.
    let issued_at = observed_at.unwrap_or(ctx.now);
    let value_result = match &claim.rule {
        RuleConfig::Extract { source, field } => {
            let record = sources
                .get(source)
                .ok_or(EvidenceError::SourceUnavailable)?;
            let value = get_json_path(record, field)
                .cloned()
                .ok_or(EvidenceError::SourceNotFound)?;
            validate_claim_value_type(&value, &claim.value.value_type)?;
            Ok(value)
        }
        RuleConfig::Exists { source } => {
            let value = Value::Bool(sources.contains_key(source));
            validate_claim_value_type(&value, &claim.value.value_type)?;
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
                sources: &sources,
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
            validate_claim_value_type(&value, &claim.value.value_type)?;
            Ok(value)
        }
        RuleConfig::Plugin { .. } => return Err(EvidenceError::OperationUnsupported),
    };
    let value = match value_result {
        Ok(value) => value,
        Err(_) if delegated_proof_claim => return Err(delegated_proof_denied()),
        Err(error) => return Err(error),
    };
    if delegated_proof_claim && value.as_bool() != Some(true) {
        return Err(delegated_relationship_unproven());
    }
    // The source_count for this claim is the number of direct sources it
    // read, plus the accumulated source_count from any dependency claims
    // that were evaluated to satisfy depends_on. This ensures predicate
    // and CEL claims that have no source_bindings of their own still
    // report the registry reads performed by their dependencies.
    let (dep_source_count, mut source_runtime_summaries): (
        usize,
        BTreeMap<(String, String), SourceRuntimeSummary>,
    ) = {
        let snapshot = prior.lock().expect("prior mutex is not poisoned");
        let mut count = 0;
        let mut summaries = BTreeMap::new();
        for dep in claim
            .depends_on
            .iter()
            .filter_map(|dep_id| snapshot.get(dep_id))
        {
            count += dep.provenance.used.source_count;
            for summary in &dep.provenance.used.source_runtimes {
                summaries
                    .entry((summary.kind.clone(), summary.config_hash.clone()))
                    .or_insert_with(|| summary.clone());
            }
        }
        (count, summaries)
    };
    for summary in ctx
        .source
        .observed_source_runtimes(&ctx.evidence, &claim.id)
        .await
    {
        source_runtime_summaries
            .insert((summary.kind.clone(), summary.config_hash.clone()), summary);
    }
    let source_runtimes = source_runtime_summaries.into_values().collect();
    let matching = claim_matching_metadata(&ctx.evidence, &claim, matching_policy_audit.as_ref());
    let mut provenance = ClaimProvenance::new(
        ctx.evidence.service_id.clone(),
        ctx.evaluation_id.clone(),
        claim.id.clone(),
        claim.version.clone(),
        ProvenanceUsed {
            source_count: sources.len() + dep_source_count,
            source_versions: BTreeMap::new(),
            source_runtimes,
        },
    );
    provenance.generated_by.policy_id = ctx.policy.policy_id.clone();
    provenance.generated_by.policy_version = ctx.policy.policy_version.clone();
    provenance.generated_by.policy_hash = ctx.policy.policy_hash.clone();
    if let Some(matching) = &matching {
        provenance.generated_by.pack_id = matching.pack_id.clone();
        provenance.generated_by.pack_version = matching.pack_version.clone();
    }
    Ok(ClaimResultInternal {
        evaluation_id: ctx.evaluation_id.clone(),
        claim_id: claim.id.clone(),
        claim_version: claim.version.clone(),
        subject_type: claim.subject_type.clone(),
        target: ctx.context.target.clone(),
        requester: ctx.context.requester.clone(),
        matching,
        value,
        redaction_fields,
        issued_at,
        expires_at: None,
        provenance,
    })
}
