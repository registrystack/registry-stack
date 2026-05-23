// SPDX-License-Identifier: Apache-2.0
//! Registry Witness evaluation runtime.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

#[cfg(feature = "registry-witness-cel")]
use cel_mapper_core::{
    MappingRuntime, RuntimeOptions, StandaloneEvalError, StandaloneExpressionInput,
};
use registry_witness_core::{
    BatchClaimResultView, BatchEvaluateRequest, BatchEvaluateResponse, BatchItemError,
    BatchItemResponse, BatchItemStatus, BatchStatus, BatchSummary, CelBindingsConfig,
    ClaimDefinition, ClaimProvenance, ClaimResultView, CredentialProfileConfig,
    DisclosureDowngrade, DisclosureProfile, EvaluateRequest, EvidenceConfig, EvidenceError,
    EvidenceFormat, EvidencePrincipal, RenderRequest, RuleConfig, SourceBindingConfig,
    SubjectRequest, FORMAT_CCCEV_JSONLD, FORMAT_CLAIM_RESULT_JSON, FORMAT_SD_JWT_VC,
};
#[cfg(feature = "registry-witness-cel")]
use serde_json::Map;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use ulid::Ulid;

pub trait SourceReader: Send + Sync {
    fn map_subject<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        subject: &'a SubjectRequest,
    ) -> Pin<Box<dyn Future<Output = Result<SubjectRequest, EvidenceError>> + Send + 'a>> {
        Box::pin(async move { Ok(subject.clone()) })
    }

    fn read_one<'a>(
        &'a self,
        binding: &'a SourceBindingConfig,
        subject: &'a SubjectRequest,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>>;

    fn required_scopes(
        &self,
        evidence: &EvidenceConfig,
        claim_id: &str,
    ) -> Result<Vec<String>, EvidenceError>;
}

#[derive(Debug, Clone)]
struct ClaimResultInternal {
    evaluation_id: String,
    claim_id: String,
    claim_version: String,
    subject_type: String,
    subject_ref: String,
    value: Value,
    issued_at: OffsetDateTime,
    expires_at: Option<OffsetDateTime>,
    provenance: ClaimProvenance,
}

#[derive(Debug, Clone)]
struct IdempotencyRecord {
    request_hash: String,
    response: BatchEvaluateResponse,
    expires_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
struct HolderProofRecord {
    expires_at: OffsetDateTime,
}

#[derive(Debug, Default)]
pub struct EvidenceStore {
    evaluations: Mutex<HashMap<String, registry_witness_core::StoredEvaluation>>,
    idempotency: Mutex<HashMap<String, IdempotencyRecord>>,
    holder_proofs: Mutex<HashMap<String, HolderProofRecord>>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BatchEvaluateOptions<'a> {
    pub header_purpose: Option<&'a str>,
    pub idempotency_key: Option<&'a str>,
}

struct ClaimEvaluationContext<'a, R: SourceReader + ?Sized> {
    evidence: &'a EvidenceConfig,
    source: &'a R,
    subject: &'a SubjectRequest,
    purpose: &'a str,
    evaluation_id: &'a str,
    now: OffsetDateTime,
}

#[cfg_attr(not(feature = "registry-witness-cel"), allow(dead_code))]
struct CelEvaluationContext<'a> {
    evidence: &'a EvidenceConfig,
    claim: &'a ClaimDefinition,
    expression: &'a str,
    bindings: &'a CelBindingsConfig,
    claims: &'a BTreeMap<String, ClaimResultInternal>,
    sources: &'a BTreeMap<String, Value>,
    subject: &'a SubjectRequest,
    purpose: &'a str,
}

impl EvidenceStore {
    pub fn insert(&self, evaluation: registry_witness_core::StoredEvaluation) {
        let now = OffsetDateTime::now_utc();
        let mut evaluations = self
            .evaluations
            .lock()
            .expect("evidence store mutex is not poisoned");
        evaluations.retain(|_, evaluation| {
            OffsetDateTime::parse(&evaluation.expires_at, &Rfc3339)
                .is_ok_and(|expires_at| expires_at > now)
        });
        let Some(first) = evaluation.results.first() else {
            return;
        };
        evaluations.insert(first.evaluation_id.clone(), evaluation);
    }

    pub fn get(&self, evaluation_id: &str) -> Option<registry_witness_core::StoredEvaluation> {
        let evaluation = self
            .evaluations
            .lock()
            .expect("evidence store mutex is not poisoned")
            .get(evaluation_id)
            .cloned()?;
        let expires_at = OffsetDateTime::parse(&evaluation.expires_at, &Rfc3339).ok()?;
        if expires_at <= OffsetDateTime::now_utc() {
            return None;
        }
        Some(evaluation)
    }

    fn idempotent_batch(
        &self,
        key: &str,
        request_hash: &str,
    ) -> Result<Option<BatchEvaluateResponse>, EvidenceError> {
        let now = OffsetDateTime::now_utc();
        let mut records = self
            .idempotency
            .lock()
            .expect("evidence idempotency mutex is not poisoned");
        records.retain(|_, record| record.expires_at > now);
        let Some(record) = records.get(key) else {
            return Ok(None);
        };
        if record.request_hash == request_hash {
            Ok(Some(record.response.clone()))
        } else {
            Err(EvidenceError::IdempotencyConflict)
        }
    }

    fn insert_idempotent_batch(
        &self,
        key: String,
        request_hash: String,
        response: BatchEvaluateResponse,
    ) {
        let now = OffsetDateTime::now_utc();
        self.idempotency
            .lock()
            .expect("evidence idempotency mutex is not poisoned")
            .insert(
                key,
                IdempotencyRecord {
                    request_hash,
                    response,
                    expires_at: now + time::Duration::minutes(15),
                },
            );
    }

    pub fn record_holder_proof(
        &self,
        key: String,
        expires_at: OffsetDateTime,
    ) -> Result<(), EvidenceError> {
        let now = OffsetDateTime::now_utc();
        let mut records = self
            .holder_proofs
            .lock()
            .expect("evidence holder proof mutex is not poisoned");
        records.retain(|_, record| record.expires_at > now);
        if records.contains_key(&key) {
            return Err(EvidenceError::HolderProofReplay);
        }
        records.insert(key, HolderProofRecord { expires_at });
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct RegistryWitnessRuntime;

impl RegistryWitnessRuntime {
    #[must_use]
    pub fn new() -> Self {
        Self
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
                    "header": "x-api-key",
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

    pub async fn evaluate<R: SourceReader + ?Sized>(
        &self,
        evidence: &EvidenceConfig,
        source: &R,
        store: &EvidenceStore,
        principal: &EvidencePrincipal,
        request: EvaluateRequest,
        header_purpose: Option<&str>,
    ) -> Result<Vec<ClaimResultView>, EvidenceError> {
        if request.claims.is_empty() {
            return Err(EvidenceError::InvalidRequest);
        }
        for claim_id in &request.claims {
            require_claim_access(evidence, source, principal, claim_id)?;
        }
        let purpose = resolve_purpose(header_purpose, request.purpose.as_deref())?;
        let format = request
            .format
            .clone()
            .unwrap_or_else(|| FORMAT_CLAIM_RESULT_JSON.to_string());
        for claim_id in &request.claims {
            require_claim_format(evidence, claim_id, &format)?;
        }
        let disclosure = requested_disclosure(evidence, &request.claims, &request.disclosure)?;
        let request_hash = hash_json(&request)?;
        let evaluation_id = Ulid::new().to_string();
        let now = OffsetDateTime::now_utc();
        let mut internal = BTreeMap::new();
        for claim_id in &request.claims {
            let ctx = ClaimEvaluationContext {
                evidence,
                source,
                subject: &request.subject,
                purpose: &purpose,
                evaluation_id: &evaluation_id,
                now,
            };
            let result = self.evaluate_claim(&ctx, claim_id, &mut internal).await?;
            internal.insert(claim_id.clone(), result);
        }
        let views = request
            .claims
            .iter()
            .map(|claim_id| {
                let claim = find_claim(evidence, claim_id)?;
                let result = internal
                    .get(claim_id)
                    .ok_or(EvidenceError::RuleEvaluationFailed)?;
                view_claim(result, claim, disclosure, &format)
            })
            .collect::<Result<Vec<_>, EvidenceError>>()?;
        let expires_at = now + time::Duration::minutes(15);
        store.insert(registry_witness_core::StoredEvaluation {
            client_id: principal.principal_id.clone(),
            purpose,
            subject_id: request.subject.id,
            claim_ids: request.claims,
            disclosure: stored_disclosure(&views),
            format,
            results: views.clone(),
            created_at: format_time(now),
            expires_at: format_time(expires_at),
            request_hash,
        });
        Ok(views)
    }

    pub async fn batch_evaluate<R: SourceReader + ?Sized>(
        &self,
        evidence: &EvidenceConfig,
        source: &R,
        store: &EvidenceStore,
        principal: &EvidencePrincipal,
        request: BatchEvaluateRequest,
        options: BatchEvaluateOptions<'_>,
    ) -> Result<BatchEvaluateResponse, EvidenceError> {
        if request.claims.is_empty() || request.subjects.is_empty() {
            return Err(EvidenceError::InvalidRequest);
        }
        let max_subjects = max_batch_subjects(evidence, &request.claims)?;
        if request.subjects.len() > max_subjects {
            return Err(EvidenceError::BatchTooLarge);
        }
        let request_hash = hash_json(&request)?;
        let scoped_key = options.idempotency_key.map(|key| {
            format!(
                "{}:/claims/batch-evaluate:{}",
                principal.principal_id,
                sha256_hex(key.as_bytes())
            )
        });
        if let Some(key) = scoped_key.as_deref() {
            if let Some(response) = store.idempotent_batch(key, &request_hash)? {
                return Ok(response);
            }
        }
        let purpose = resolve_purpose(options.header_purpose, request.purpose.as_deref())?;
        let batch_id = Ulid::new().to_string();
        let claims = request.claims.clone();
        let mut items = Vec::with_capacity(request.subjects.len());
        let mut succeeded = 0;
        let mut failed = 0;
        for (input_index, subject) in request.subjects.clone().into_iter().enumerate() {
            let eval = EvaluateRequest {
                subject: subject.clone(),
                claims: request.claims.clone(),
                disclosure: request.disclosure.clone(),
                format: request.format.clone(),
                purpose: Some(purpose.clone()),
            };
            match self
                .evaluate(evidence, source, store, principal, eval, Some(&purpose))
                .await
            {
                Ok(results) => {
                    let evaluation_id = results.first().map(|result| result.evaluation_id.clone());
                    let claim_results = results
                        .iter()
                        .map(|result| batch_claim_result(evidence, result))
                        .collect::<Result<Vec<_>, EvidenceError>>()?;
                    succeeded += 1;
                    items.push(BatchItemResponse {
                        input_index,
                        subject_ref: batch_subject_ref(input_index),
                        evaluation_id,
                        status: BatchItemStatus::Succeeded,
                        claim_results,
                        errors: Vec::new(),
                    });
                }
                Err(error) => {
                    failed += 1;
                    items.push(BatchItemResponse {
                        input_index,
                        subject_ref: batch_subject_ref(input_index),
                        evaluation_id: None,
                        status: BatchItemStatus::Failed,
                        claim_results: Vec::new(),
                        errors: vec![batch_item_error(&error)],
                    });
                }
            }
        }
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

    fn evaluate_claim<'a, R: SourceReader + ?Sized>(
        &'a self,
        ctx: &'a ClaimEvaluationContext<'a, R>,
        claim_id: &'a str,
        prior: &'a mut BTreeMap<String, ClaimResultInternal>,
    ) -> Pin<Box<dyn Future<Output = Result<ClaimResultInternal, EvidenceError>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(existing) = prior.get(claim_id) {
                return Ok(existing.clone());
            }
            let claim = find_claim(ctx.evidence, claim_id)?;
            if !claim.operations.evaluate.enabled {
                return Err(EvidenceError::OperationUnsupported);
            }
            for dep in &claim.depends_on {
                let dep_result = self.evaluate_claim(ctx, dep, prior).await?;
                prior.insert(dep.clone(), dep_result);
            }
            let sources = load_sources(ctx.source, claim, ctx.subject, ctx.purpose).await?;
            let value = match &claim.rule {
                RuleConfig::Extract { source, field } => {
                    let record = sources
                        .get(source)
                        .ok_or(EvidenceError::SourceUnavailable)?;
                    get_path(record, field)
                        .cloned()
                        .ok_or(EvidenceError::SourceNotFound)?
                }
                RuleConfig::Exists { source } => Value::Bool(sources.contains_key(source)),
                RuleConfig::Cel {
                    expression,
                    bindings,
                } => evaluate_cel_expression(&CelEvaluationContext {
                    evidence: ctx.evidence,
                    claim,
                    expression,
                    bindings,
                    claims: prior,
                    sources: &sources,
                    subject: ctx.subject,
                    purpose: ctx.purpose,
                })?,
                RuleConfig::Plugin { .. } => return Err(EvidenceError::OperationUnsupported),
            };
            // The source_count for this claim is the number of direct sources it
            // read, plus the accumulated source_count from any dependency claims
            // that were evaluated to satisfy depends_on. This ensures predicate
            // and CEL claims that have no source_bindings of their own still
            // report the registry reads performed by their dependencies.
            let dep_source_count: usize = claim
                .depends_on
                .iter()
                .filter_map(|dep_id| prior.get(dep_id))
                .map(|dep| dep.provenance.source_count)
                .sum();
            Ok(ClaimResultInternal {
                evaluation_id: ctx.evaluation_id.to_string(),
                claim_id: claim.id.clone(),
                claim_version: claim.version.clone(),
                subject_type: claim.subject_type.clone(),
                subject_ref: subject_ref(&ctx.subject.id),
                value,
                issued_at: ctx.now,
                expires_at: None,
                provenance: ClaimProvenance {
                    source_count: sources.len() + dep_source_count,
                    source_versions: BTreeMap::new(),
                    computed_by: ctx.evidence.service_id.clone(),
                },
            })
        })
    }
}

pub fn find_claim<'a>(
    config: &'a EvidenceConfig,
    claim_id: &str,
) -> Result<&'a ClaimDefinition, EvidenceError> {
    config
        .claims
        .iter()
        .find(|claim| claim.id == claim_id)
        .ok_or(EvidenceError::ClaimNotFound)
}

fn principal_can_see_claim<R: SourceReader + ?Sized>(
    evidence: &EvidenceConfig,
    source: &R,
    principal: &EvidencePrincipal,
    claim: &ClaimDefinition,
) -> bool {
    source
        .required_scopes(evidence, &claim.id)
        .is_ok_and(|scopes| scopes.iter().all(|scope| principal.has_scope(scope)))
}

fn require_claim_access<R: SourceReader + ?Sized>(
    evidence: &EvidenceConfig,
    source: &R,
    principal: &EvidencePrincipal,
    claim_id: &str,
) -> Result<(), EvidenceError> {
    for scope in source.required_scopes(evidence, claim_id)? {
        if !principal.has_scope(&scope) {
            return Err(EvidenceError::ScopeDenied { required: scope });
        }
    }
    Ok(())
}

pub fn claim_summary(claim: &ClaimDefinition) -> Value {
    // Only publish the oots block when oots is explicitly enabled. When disabled,
    // the sub-fields (requirement, LoA, etc.) are intentionally not advertised,
    // so emitting them as null would be misleading.
    let oots = claim
        .oots
        .as_ref()
        .filter(|o| o.enabled)
        .map(|o| serde_json::to_value(o).unwrap_or(Value::Null))
        .unwrap_or(Value::Null);
    json!({
        "id": claim.id,
        "title": claim.title,
        "version": claim.version,
        "subject_type": claim.subject_type,
        "operations": {
            "evaluate": claim.operations.evaluate.enabled,
            "batch_evaluate": claim.operations.batch_evaluate.enabled,
        },
        "formats": claim.formats,
        "disclosure": {
            "default": claim.disclosure.default,
            "allowed": claim.disclosure.allowed,
            "downgrade": claim.disclosure.downgrade,
        },
        "cccev": claim.cccev,
        "oots": oots,
    })
}

pub fn formats(config: &EvidenceConfig) -> Vec<EvidenceFormat> {
    let mut seen = BTreeMap::new();
    seen.insert(FORMAT_CLAIM_RESULT_JSON.to_string(), true);
    seen.insert(FORMAT_CCCEV_JSONLD.to_string(), true);
    seen.insert(
        FORMAT_SD_JWT_VC.to_string(),
        !config.credential_profiles.is_empty(),
    );
    for claim in &config.claims {
        for format in &claim.formats {
            seen.entry(format.clone()).or_insert(true);
        }
    }
    seen.into_iter()
        .map(|(id, enabled)| EvidenceFormat {
            kind: format_kind(&id).to_string(),
            status: if enabled { "enabled" } else { "disabled" }.to_string(),
            id,
        })
        .collect()
}

fn format_kind(format: &str) -> &'static str {
    match format {
        FORMAT_CLAIM_RESULT_JSON => "claim_result",
        FORMAT_SD_JWT_VC => "credential",
        _ => "renderer",
    }
}

fn resolve_purpose(header: Option<&str>, body: Option<&str>) -> Result<String, EvidenceError> {
    match (header, body) {
        (Some(header), Some(body)) if header != body => Err(EvidenceError::InvalidRequest),
        (Some(header), _) if !header.trim().is_empty() => Ok(header.to_string()),
        (_, Some(body)) if !body.trim().is_empty() => Ok(body.to_string()),
        (Some(_), _) | (_, Some(_)) => Err(EvidenceError::InvalidRequest),
        _ => Err(EvidenceError::PurposeRequired),
    }
}

fn require_claim_format(
    evidence: &EvidenceConfig,
    claim_id: &str,
    format: &str,
) -> Result<(), EvidenceError> {
    let claim = find_claim(evidence, claim_id)?;
    if claim.formats.iter().any(|candidate| candidate == format) {
        Ok(())
    } else {
        Err(EvidenceError::FormatUnsupported)
    }
}

fn requested_disclosure(
    config: &EvidenceConfig,
    claim_ids: &[String],
    requested: &Option<String>,
) -> Result<DisclosureProfile, EvidenceError> {
    let raw = requested
        .as_deref()
        .or_else(|| {
            claim_ids
                .first()
                .and_then(|claim_id| find_claim(config, claim_id).ok())
                .map(|claim| claim.disclosure.default.as_str())
        })
        .unwrap_or("redacted");
    DisclosureProfile::parse(raw).ok_or(EvidenceError::InvalidRequest)
}

fn max_batch_subjects(config: &EvidenceConfig, claims: &[String]) -> Result<usize, EvidenceError> {
    let mut max = config.inline_batch_limit;
    for claim_id in claims {
        let claim = find_claim(config, claim_id)?;
        if !claim.operations.batch_evaluate.enabled {
            return Err(EvidenceError::OperationUnsupported);
        }
        max = max.min(claim.operations.batch_evaluate.max_subjects);
    }
    Ok(max)
}

async fn load_sources<R: SourceReader + ?Sized>(
    source: &R,
    claim: &ClaimDefinition,
    subject: &SubjectRequest,
    purpose: &str,
) -> Result<BTreeMap<String, Value>, EvidenceError> {
    let mut out = BTreeMap::new();
    for (id, binding) in &claim.source_bindings {
        let mapped_subject = source.map_subject(binding, subject).await?;
        let row = source.read_one(binding, &mapped_subject, purpose).await?;
        for field in binding.fields.values().filter(|field| field.required) {
            match get_path(&row, &field.field) {
                Some(value) if !value.is_null() => {}
                _ => return Err(EvidenceError::SourceNotFound),
            }
        }
        out.insert(id.clone(), row);
    }
    Ok(out)
}

fn get_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

fn evaluate_cel_expression(ctx: &CelEvaluationContext<'_>) -> Result<Value, EvidenceError> {
    validate_cel_policy(ctx.expression, ctx.bindings, ctx.claim)?;
    #[cfg(feature = "registry-witness-cel")]
    {
        evaluate_with_cel(ctx)
    }
    #[cfg(not(feature = "registry-witness-cel"))]
    {
        let _ = ctx;
        Err(EvidenceError::OperationUnsupported)
    }
}

fn validate_cel_policy(
    expression: &str,
    bindings: &CelBindingsConfig,
    claim: &ClaimDefinition,
) -> Result<(), EvidenceError> {
    let _ = (bindings, claim);
    if expression.trim().is_empty() {
        return Err(EvidenceError::InvalidRequest);
    }
    #[cfg(not(feature = "registry-witness-cel"))]
    {
        let _ = expression;
    }
    Ok(())
}

#[cfg(feature = "registry-witness-cel")]
fn evaluate_with_cel(ctx: &CelEvaluationContext<'_>) -> Result<Value, EvidenceError> {
    let mut claim_values = Map::new();
    for (alias, binding) in &ctx.bindings.claims {
        let result = ctx
            .claims
            .get(&binding.claim)
            .ok_or(EvidenceError::RuleEvaluationFailed)?;
        claim_values.insert(
            alias.clone(),
            json!({
                "value": result.value,
                "satisfied": result.value.as_bool(),
                "claim_id": result.claim_id,
                "version": result.claim_version,
            }),
        );
    }
    let root_bindings = BTreeMap::from([
        (
            "source".to_string(),
            Value::Object(ctx.sources.clone().into_iter().collect()),
        ),
        ("claims".to_string(), Value::Object(claim_values)),
        (
            "ctx".to_string(),
            json!({
                "purpose": ctx.purpose,
                "subject": { "id": ctx.subject.id },
            }),
        ),
        (
            "vars".to_string(),
            Value::Object(ctx.bindings.vars.clone().into_iter().collect()),
        ),
        ("meta".to_string(), cel_meta(ctx.evidence, ctx.claim)),
    ]);
    let runtime = MappingRuntime::new(RuntimeOptions::default());
    runtime
        .evaluate_cel_expression_with_input(
            ctx.expression,
            StandaloneExpressionInput::new(root_bindings),
        )
        .map_err(|error| match error {
            StandaloneEvalError::Compile(_) | StandaloneEvalError::InvalidBindingName { .. } => {
                EvidenceError::InvalidRequest
            }
            StandaloneEvalError::Evaluate { .. } => EvidenceError::RuleEvaluationFailed,
        })
}

#[cfg(feature = "registry-witness-cel")]
fn cel_meta(evidence: &EvidenceConfig, claim: &ClaimDefinition) -> Value {
    let mut sources = Map::new();
    for (alias, binding) in &claim.source_bindings {
        let connector = match binding.connector {
            registry_witness_core::config::SourceConnectorKind::RegistryDataApi => {
                "registry_data_api"
            }
            registry_witness_core::config::SourceConnectorKind::Dci => "dci",
        };
        sources.insert(
            alias.clone(),
            json!({
                "dataset": binding.dataset,
                "entity": binding.entity,
                "connector": connector,
            }),
        );
    }
    json!({
        "service_id": evidence.service_id,
        "api_version": evidence.api_version,
        "claim": {
            "id": claim.id,
            "version": claim.version,
            "subject_type": claim.subject_type,
        },
        "sources": sources,
    })
}

fn view_claim(
    result: &ClaimResultInternal,
    claim: &ClaimDefinition,
    disclosure: DisclosureProfile,
    format: &str,
) -> Result<ClaimResultView, EvidenceError> {
    let mut effective_disclosure = disclosure;
    let allowed = claim
        .disclosure
        .allowed
        .iter()
        .any(|candidate| candidate == effective_disclosure.as_str());
    if !allowed {
        effective_disclosure = match DisclosureDowngrade::parse(&claim.disclosure.downgrade)
            .ok_or(EvidenceError::InvalidRequest)?
        {
            DisclosureDowngrade::Default => DisclosureProfile::parse(&claim.disclosure.default)
                .ok_or(EvidenceError::InvalidRequest)?,
            DisclosureDowngrade::Redacted => DisclosureProfile::Redacted,
            DisclosureDowngrade::Deny => return Err(EvidenceError::DisclosureNotAllowed),
        };
        if !claim
            .disclosure
            .allowed
            .iter()
            .any(|candidate| candidate == effective_disclosure.as_str())
        {
            return Err(EvidenceError::DisclosureNotAllowed);
        }
    }
    let value = match effective_disclosure {
        DisclosureProfile::Value => Some(result.value.clone()),
        DisclosureProfile::Predicate => result.value.as_bool().map(Value::Bool),
        DisclosureProfile::Redacted => None,
    };
    let satisfied = match effective_disclosure {
        DisclosureProfile::Value | DisclosureProfile::Predicate => result.value.as_bool(),
        DisclosureProfile::Redacted => None,
    };
    Ok(ClaimResultView {
        evaluation_id: result.evaluation_id.clone(),
        claim_id: result.claim_id.clone(),
        claim_version: result.claim_version.clone(),
        subject_type: result.subject_type.clone(),
        subject_ref: result.subject_ref.clone(),
        value,
        satisfied,
        disclosure: effective_disclosure.as_str().to_string(),
        format: format.to_string(),
        issued_at: format_time(result.issued_at),
        expires_at: result.expires_at.map(format_time),
        provenance: result.provenance.clone(),
    })
}

fn render_results(
    evidence: &EvidenceConfig,
    results: &[ClaimResultView],
    format: &str,
) -> Result<Value, EvidenceError> {
    match format {
        FORMAT_CLAIM_RESULT_JSON => Ok(json!({ "results": results })),
        FORMAT_CCCEV_JSONLD => Ok(render_cccev(evidence, results)),
        FORMAT_SD_JWT_VC => Err(EvidenceError::FormatUnsupported),
        _ => Err(EvidenceError::FormatUnsupported),
    }
}

fn render_cccev(config: &EvidenceConfig, results: &[ClaimResultView]) -> Value {
    let evidence_nodes = results
        .iter()
        .map(|result| render_cccev_evidence_node(config, result))
        .collect::<Vec<_>>();
    json!({
        "@context": {
            "cccev": "http://data.europa.eu/m8g/",
            "dcterms": "http://purl.org/dc/terms/",
            "foaf": "http://xmlns.com/foaf/0.1/",
            "time": "http://www.w3.org/2006/time#",
            "xsd": "http://www.w3.org/2001/XMLSchema#",
            "cccev:isProvidedBy": { "@type": "@id" },
            "cccev:supportsRequirement": { "@type": "@id" },
            "cccev:supportsValue": { "@type": "@id" },
            "cccev:providesValueFor": { "@type": "@id" },
            "cccev:validityPeriod": { "@type": "@id" },
            "time:hasBeginning": { "@type": "xsd:dateTime" },
            "time:hasEnd": { "@type": "xsd:dateTime" }
        },
        "@graph": evidence_nodes
    })
}

fn render_cccev_evidence_node(config: &EvidenceConfig, result: &ClaimResultView) -> Value {
    let evidence_id = format!(
        "urn:registry-witness:evidence-render:{}:{}",
        result.evaluation_id, result.claim_id
    );
    let value_id = format!("{evidence_id}#value");
    let period_id = format!("{evidence_id}#validity");

    // Look up the requirement IRI from the claim's oots config when present.
    // Fall back to a urn: reference so the output is always valid JSON-LD.
    let requirement_iri = config
        .claims
        .iter()
        .find(|c| c.id == result.claim_id)
        .and_then(|c| c.oots.as_ref())
        .and_then(|o| o.requirement.as_deref())
        .map(|iri| json!({ "@id": iri }))
        .unwrap_or_else(|| json!({ "@id": format!("urn:claim:{}", result.claim_id) }));

    // Build the issuing authority as an Agent node using the service_id.
    let provided_by = json!({
        "@type": "foaf:Agent",
        "dcterms:identifier": result.provenance.computed_by,
    });

    // Build the validity period from issued_at / expires_at.
    let mut validity_period = json!({
        "@id": period_id,
        "@type": "time:ProperInterval",
        "time:hasBeginning": { "@value": result.issued_at, "@type": "xsd:dateTime" },
    });
    if let Some(expires_at) = result.expires_at.as_deref() {
        validity_period["time:hasEnd"] = json!({ "@value": expires_at, "@type": "xsd:dateTime" });
    }

    // Build the SupportedValue node with the claim's value.
    let concept_iri = format!("urn:claim-concept:{}", result.claim_id);
    let supports_value = json!({
        "@id": value_id,
        "@type": "cccev:SupportedValue",
        "cccev:providesValueFor": {
            "@id": concept_iri,
            "@type": "cccev:InformationConcept",
            "dcterms:identifier": result.claim_id,
        },
        "cccev:value": result.value,
    });

    json!({
        "@id": evidence_id,
        "@type": "cccev:Evidence",
        "dcterms:identifier": result.evaluation_id,
        "cccev:isProvidedBy": provided_by,
        "cccev:isConformantTo": result.satisfied.unwrap_or(false),
        "cccev:supportsRequirement": requirement_iri,
        "cccev:supportsValue": supports_value,
        "cccev:validityPeriod": validity_period,
    })
}

pub fn credential_profile_for<'a>(
    config: &'a EvidenceConfig,
    evaluation: &registry_witness_core::StoredEvaluation,
    requested_profile: Option<&'a str>,
) -> Result<(&'a str, &'a CredentialProfileConfig), EvidenceError> {
    if let Some(profile_id) = requested_profile {
        let profile = config
            .credential_profiles
            .get(profile_id)
            .ok_or(EvidenceError::CredentialIssuerNotConfigured)?;
        // The caller-supplied profile must also be on the allow-list of at
        // least one claim in the evaluation. Without this check a client
        // could mint a credential against a profile the claim never opted
        // in to, bypassing per-claim policy.
        let allowed = evaluation
            .claim_ids
            .iter()
            .filter_map(|claim_id| find_claim(config, claim_id).ok())
            .any(|claim| {
                claim
                    .credential_profiles
                    .iter()
                    .any(|allowed| allowed == profile_id)
            });
        if !allowed {
            return Err(EvidenceError::CredentialIssuerNotConfigured);
        }
        return Ok((profile_id, profile));
    }
    for claim_id in &evaluation.claim_ids {
        let claim = find_claim(config, claim_id)?;
        for profile_id in &claim.credential_profiles {
            if let Some(profile) = config.credential_profiles.get(profile_id) {
                return Ok((profile_id, profile));
            }
        }
    }
    Err(EvidenceError::CredentialIssuerNotConfigured)
}

pub fn format_time(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .expect("OffsetDateTime within supported RFC3339 range")
}

pub fn subject_ref(subject_id: &str) -> String {
    let digest = sha256_hex(subject_id.as_bytes());
    format!("urn:subject:sha256:{digest}")
}

fn batch_subject_ref(input_index: usize) -> String {
    format!("request.subjects[{input_index}]")
}

fn batch_claim_result(
    evidence: &EvidenceConfig,
    result: &ClaimResultView,
) -> Result<BatchClaimResultView, EvidenceError> {
    let claim = find_claim(evidence, &result.claim_id)?;
    Ok(BatchClaimResultView {
        result_id: Ulid::new().to_string(),
        claim_id: result.claim_id.clone(),
        claim_version: result.claim_version.clone(),
        value_type: batch_value_type(claim, result),
        value: result.value.clone(),
        satisfied: result.satisfied,
        disclosure: result.disclosure.clone(),
        provenance: result.provenance.clone(),
    })
}

fn batch_value_type(claim: &ClaimDefinition, result: &ClaimResultView) -> String {
    if !claim.value.value_type.is_empty() {
        return claim.value.value_type.clone();
    }
    match result.value.as_ref() {
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
        Some(Value::Null) | None => "unknown",
    }
    .to_string()
}

fn batch_item_error(error: &EvidenceError) -> BatchItemError {
    BatchItemError {
        code: error.code().to_string(),
        title: batch_error_title(error).to_string(),
        retryable: matches!(error, EvidenceError::SourceUnavailable),
    }
}

fn batch_error_title(error: &EvidenceError) -> &'static str {
    match error {
        EvidenceError::ServerDisabled => "Evidence server disabled",
        EvidenceError::ClaimNotFound => "Claim not found",
        EvidenceError::OperationUnsupported => "Claim operation unsupported",
        EvidenceError::InvalidRequest => "Invalid evidence request",
        EvidenceError::DisclosureNotAllowed => "Disclosure not allowed",
        EvidenceError::SourceNotFound => "Source record not found",
        EvidenceError::SourceAmbiguous => "Source lookup ambiguous",
        EvidenceError::SourceUnavailable => "Source unavailable",
        EvidenceError::BatchTooLarge => "Batch too large",
        EvidenceError::EvaluationNotFound => "Evaluation not found",
        EvidenceError::EvaluationBindingMismatch => "Evaluation binding mismatch",
        EvidenceError::FormatUnsupported => "Format unsupported",
        EvidenceError::CredentialIssuerNotConfigured => "Credential issuer not configured",
        EvidenceError::HolderProofRequired => "Holder proof required",
        EvidenceError::HolderProofReplay => "Holder proof replay",
        EvidenceError::CredentialIssuanceFailed => "Credential issuance failed",
        EvidenceError::RuleEvaluationFailed => "Claim rule evaluation failed",
        EvidenceError::IdempotencyConflict => "Idempotency conflict",
        EvidenceError::PurposeRequired => "Purpose required",
        EvidenceError::MissingCredential => "Missing credential",
        EvidenceError::ScopeDenied { .. } => "Scope denied",
        _ => "Evidence error",
    }
}

fn stored_disclosure(results: &[ClaimResultView]) -> String {
    let Some(first) = results.first() else {
        return "redacted".to_string();
    };
    if results
        .iter()
        .all(|result| result.disclosure == first.disclosure)
    {
        first.disclosure.clone()
    } else {
        "mixed".to_string()
    }
}

fn hash_json<T: serde::Serialize>(value: &T) -> Result<String, EvidenceError> {
    let bytes = serde_json::to_vec(value).map_err(|_| EvidenceError::InvalidRequest)?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_document_advertises_api_key_and_bearer_auth() {
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "evidence.test".to_string(),
            ..EvidenceConfig::default()
        };

        let document = RegistryWitnessRuntime::service_document(&evidence);

        assert_eq!(document["auth"]["methods"], json!(["api_key", "bearer"]));
        assert_eq!(document["auth"]["api_key"]["header"], json!("x-api-key"));
        assert_eq!(document["auth"]["bearer"]["header"], json!("Authorization"));
        assert_eq!(document["auth"]["bearer"]["scheme"], json!("bearer"));
        assert_eq!(
            document["auth"]["bearer"]["format"],
            json!("Bearer <token>")
        );
        assert_eq!(document["auth"]["audience"], json!("evidence.test"));
    }

    #[test]
    fn credential_profile_for_rejects_profile_not_listed_in_claim() {
        // A caller-supplied credential_profile must be in the requested claim's
        // own credential_profiles allow-list. Otherwise a client could mint a
        // credential against a profile the claim never opted in to.
        let evidence: EvidenceConfig = serde_yml::from_str(
            r#"
enabled: true
service_id: test.witness
claims:
  - id: claim-a
    title: A
    version: "1.0"
    subject_type: person
    rule:
      type: exists
      source: src
    credential_profiles:
      - profile_a
credential_profiles:
  profile_a:
    format: sd_jwt_vc
    issuer: https://issuer.example
    issuer_key_env: ISSUER_KEY
    vct: https://vct.example/a
    allowed_claims:
      - claim-a
  profile_b:
    format: sd_jwt_vc
    issuer: https://issuer.example
    issuer_key_env: ISSUER_KEY_B
    vct: https://vct.example/b
    allowed_claims:
      - claim-a
"#,
        )
        .expect("evidence config is valid YAML");

        let evaluation = registry_witness_core::StoredEvaluation {
            client_id: "client".to_string(),
            purpose: "test".to_string(),
            claim_ids: vec!["claim-a".to_string()],
            disclosure: "redacted".to_string(),
            format: FORMAT_SD_JWT_VC.to_string(),
            results: Vec::new(),
            created_at: "1970-01-01T00:00:00Z".to_string(),
            expires_at: "1970-01-01T00:00:00Z".to_string(),
            request_hash: "h".to_string(),
        };

        let err = credential_profile_for(&evidence, &evaluation, Some("profile_b"))
            .expect_err("profile_b is not listed on claim-a");
        assert!(matches!(err, EvidenceError::CredentialIssuerNotConfigured));

        let (profile_id, _) = credential_profile_for(&evidence, &evaluation, Some("profile_a"))
            .expect("profile_a is listed on claim-a");
        assert_eq!(profile_id, "profile_a");
    }
}
