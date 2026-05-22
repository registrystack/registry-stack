// SPDX-License-Identifier: Apache-2.0
//! Evidence Server evaluation runtime.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use evidence_core::{
    BatchEvaluateRequest, BatchEvaluateResponse, BatchItemResponse, CelBindingsConfig,
    ClaimDefinition, ClaimProvenance, ClaimResultView, CredentialProfileConfig,
    DisclosureDowngrade, DisclosureProfile, EvaluateRequest, EvidenceConfig, EvidenceError,
    EvidenceFormat, EvidencePrincipal, RenderRequest, RuleConfig, SourceBindingConfig,
    SubjectRequest, FORMAT_CCCEV_JSONLD, FORMAT_CLAIM_RESULT_JSON, FORMAT_SD_JWT_VC,
};
#[cfg(feature = "evidence-server-cel")]
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
    evaluations: Mutex<HashMap<String, evidence_core::StoredEvaluation>>,
    idempotency: Mutex<HashMap<String, IdempotencyRecord>>,
    holder_proofs: Mutex<HashMap<String, HolderProofRecord>>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BatchEvaluateOptions<'a> {
    pub header_purpose: Option<&'a str>,
    pub idempotency_key: Option<&'a str>,
}

struct ClaimEvaluationContext<'a, R: SourceReader> {
    evidence: &'a EvidenceConfig,
    source: &'a R,
    subject: &'a SubjectRequest,
    purpose: &'a str,
    evaluation_id: &'a str,
    now: OffsetDateTime,
}

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
    pub fn insert(&self, evaluation: evidence_core::StoredEvaluation) {
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

    pub fn get(&self, evaluation_id: &str) -> Option<evidence_core::StoredEvaluation> {
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
pub struct EvidenceRuntime;

impl EvidenceRuntime {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    pub fn service_document(evidence: &EvidenceConfig) -> Value {
        json!({
            "service_id": evidence.service_id,
            "api_version": evidence.api_version,
            "operations": {
                "evaluate": true,
                "batch_evaluate": true,
                "render": true,
                "credential_issue": !evidence.credential_profiles.is_empty()
            },
            "claims_url": evidence.claims_url,
            "formats_url": evidence.formats_url,
            "inline_batch_limit": evidence.inline_batch_limit,
            "identity": {
                "mapper": "common_subject_id",
                "production_mapper": false
            },
            "formats": formats(evidence),
        })
    }

    pub fn list_claims<R: SourceReader>(
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

    pub fn get_claim<R: SourceReader>(
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

    pub async fn evaluate<R: SourceReader>(
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
        let disclosure = requested_disclosure(evidence, &request.disclosure)?;
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
        store.insert(evidence_core::StoredEvaluation {
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

    pub async fn batch_evaluate<R: SourceReader>(
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
        let mut items = Vec::with_capacity(request.subjects.len());
        for subject in request.subjects.clone() {
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
                Ok(results) => items.push(BatchItemResponse::Ok {
                    subject_ref: subject_ref(&subject.id),
                    evaluation_id: results[0].evaluation_id.clone(),
                    results,
                }),
                Err(error) => items.push(BatchItemResponse::Error {
                    subject_ref: subject_ref(&subject.id),
                    code: error.code(),
                    detail: "subject evaluation failed",
                }),
            }
        }
        let response = BatchEvaluateResponse { items };
        if let Some(key) = scoped_key {
            store.insert_idempotent_batch(key, request_hash, response.clone());
        }
        Ok(response)
    }

    pub fn render(
        &self,
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
        render_results(&evaluation.results, &request.format)
    }

    fn evaluate_claim<'a, R: SourceReader>(
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
                    source_count: sources.len(),
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

fn principal_can_see_claim<R: SourceReader>(
    evidence: &EvidenceConfig,
    source: &R,
    principal: &EvidencePrincipal,
    claim: &ClaimDefinition,
) -> bool {
    source
        .required_scopes(evidence, &claim.id)
        .is_ok_and(|scopes| scopes.iter().all(|scope| principal.has_scope(scope)))
}

fn require_claim_access<R: SourceReader>(
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
        "oots": claim.oots,
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
        .map(|(format, enabled)| EvidenceFormat { format, enabled })
        .collect()
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
    requested: &Option<String>,
) -> Result<DisclosureProfile, EvidenceError> {
    let raw = requested
        .as_deref()
        .or_else(|| {
            config
                .claims
                .first()
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

async fn load_sources<R: SourceReader>(
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
    #[cfg(feature = "evidence-server-cel")]
    {
        evaluate_with_cel_mapper(ctx)
    }
    #[cfg(not(feature = "evidence-server-cel"))]
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
    #[cfg(feature = "evidence-server-cel")]
    {
        let program =
            cel::Program::compile(expression).map_err(|_| EvidenceError::InvalidRequest)?;
        if expression_violates_cel_policy(program.expression()) {
            return Err(EvidenceError::InvalidRequest);
        }
        if expression_has_undeclared_references(program.expression(), bindings, claim) {
            return Err(EvidenceError::InvalidRequest);
        }
    }
    #[cfg(not(feature = "evidence-server-cel"))]
    {
        let _ = (expression, bindings, claim);
    }
    Ok(())
}

#[cfg(feature = "evidence-server-cel")]
fn expression_violates_cel_policy(expr: &cel::common::ast::IdedExpr) -> bool {
    use cel::common::ast::{EntryExpr, Expr};
    match &expr.expr {
        Expr::Call(call) => {
            let allowed = matches!(
                call.func_name.as_str(),
                "!_" | "-_"
                    | "_&&_"
                    | "_||_"
                    | "_+_"
                    | "_-_"
                    | "_*_"
                    | "_/_"
                    | "_%_"
                    | "_==_"
                    | "_!=_"
                    | "_>_"
                    | "_>=_"
                    | "_<_"
                    | "_<=_"
                    | "_[_]"
                    | "@in"
                    | "has"
                    | "size"
                    | "string"
            );
            !allowed
                || call
                    .target
                    .as_deref()
                    .is_some_and(expression_violates_cel_policy)
                || call.args.iter().any(expression_violates_cel_policy)
        }
        Expr::Select(select) => expression_violates_cel_policy(&select.operand),
        Expr::List(list) => list.elements.iter().any(expression_violates_cel_policy),
        Expr::Map(map) => map.entries.iter().any(|entry| match &entry.expr {
            EntryExpr::MapEntry(entry) => {
                expression_violates_cel_policy(&entry.key)
                    || expression_violates_cel_policy(&entry.value)
            }
            EntryExpr::StructField(entry) => expression_violates_cel_policy(&entry.value),
        }),
        Expr::Struct(strct) => strct.entries.iter().any(|entry| match &entry.expr {
            EntryExpr::MapEntry(entry) => {
                expression_violates_cel_policy(&entry.key)
                    || expression_violates_cel_policy(&entry.value)
            }
            EntryExpr::StructField(entry) => expression_violates_cel_policy(&entry.value),
        }),
        Expr::Comprehension(_) => true,
        Expr::Unspecified | Expr::Literal(_) | Expr::Ident(_) => false,
    }
}

#[cfg(feature = "evidence-server-cel")]
fn expression_has_undeclared_references(
    expr: &cel::common::ast::IdedExpr,
    bindings: &CelBindingsConfig,
    claim: &ClaimDefinition,
) -> bool {
    use cel::common::ast::{EntryExpr, Expr};
    if let Some(path) = select_path(expr) {
        return path_is_undeclared(&path, bindings, claim);
    }
    match &expr.expr {
        Expr::Call(call) => {
            call.target
                .as_deref()
                .is_some_and(|target| expression_has_undeclared_references(target, bindings, claim))
                || call
                    .args
                    .iter()
                    .any(|arg| expression_has_undeclared_references(arg, bindings, claim))
        }
        Expr::Select(select) => {
            expression_has_undeclared_references(&select.operand, bindings, claim)
        }
        Expr::List(list) => list
            .elements
            .iter()
            .any(|element| expression_has_undeclared_references(element, bindings, claim)),
        Expr::Map(map) => map.entries.iter().any(|entry| match &entry.expr {
            EntryExpr::MapEntry(entry) => {
                expression_has_undeclared_references(&entry.key, bindings, claim)
                    || expression_has_undeclared_references(&entry.value, bindings, claim)
            }
            EntryExpr::StructField(entry) => {
                expression_has_undeclared_references(&entry.value, bindings, claim)
            }
        }),
        Expr::Struct(strct) => strct.entries.iter().any(|entry| match &entry.expr {
            EntryExpr::MapEntry(entry) => {
                expression_has_undeclared_references(&entry.key, bindings, claim)
                    || expression_has_undeclared_references(&entry.value, bindings, claim)
            }
            EntryExpr::StructField(entry) => {
                expression_has_undeclared_references(&entry.value, bindings, claim)
            }
        }),
        Expr::Comprehension(comprehension) => {
            expression_has_undeclared_references(&comprehension.iter_range, bindings, claim)
                || expression_has_undeclared_references(&comprehension.accu_init, bindings, claim)
                || expression_has_undeclared_references(&comprehension.loop_cond, bindings, claim)
                || expression_has_undeclared_references(&comprehension.loop_step, bindings, claim)
                || expression_has_undeclared_references(&comprehension.result, bindings, claim)
        }
        Expr::Ident(ident) => !matches!(
            ident.as_str(),
            "source" | "claims" | "ctx" | "vars" | "meta" | "true" | "false" | "null"
        ),
        Expr::Unspecified | Expr::Literal(_) => false,
    }
}

#[cfg(feature = "evidence-server-cel")]
fn select_path(expr: &cel::common::ast::IdedExpr) -> Option<Vec<String>> {
    use cel::common::ast::Expr;
    match &expr.expr {
        Expr::Ident(ident) => Some(vec![ident.clone()]),
        Expr::Select(select) => {
            let mut path = select_path(&select.operand)?;
            path.push(select.field.clone());
            Some(path)
        }
        _ => None,
    }
}

#[cfg(feature = "evidence-server-cel")]
fn path_is_undeclared(
    path: &[String],
    bindings: &CelBindingsConfig,
    claim: &ClaimDefinition,
) -> bool {
    match path.first().map(String::as_str) {
        Some("source") => source_path_is_undeclared(path, claim),
        Some("claims") => claim_path_is_undeclared(path, bindings),
        Some("ctx") => ctx_path_is_undeclared(path),
        Some("vars") => path
            .get(1)
            .is_some_and(|name| !bindings.vars.contains_key(name)),
        Some("meta") => meta_path_is_undeclared(path, claim),
        Some("true" | "false" | "null") => false,
        Some(_) | None => true,
    }
}

#[cfg(feature = "evidence-server-cel")]
fn source_path_is_undeclared(path: &[String], claim: &ClaimDefinition) -> bool {
    let Some(alias) = path.get(1) else {
        return false;
    };
    let Some(binding) = claim.source_bindings.get(alias) else {
        return true;
    };
    let Some(field) = path.get(2) else {
        return false;
    };
    field != &binding.lookup.field
        && !binding.fields.contains_key(field)
        && !binding
            .fields
            .values()
            .any(|source_field| source_field.field.split('.').next() == Some(field.as_str()))
}

#[cfg(feature = "evidence-server-cel")]
fn claim_path_is_undeclared(path: &[String], bindings: &CelBindingsConfig) -> bool {
    let Some(alias) = path.get(1) else {
        return false;
    };
    if !bindings.claims.contains_key(alias) {
        return true;
    }
    path.get(2).is_some_and(|field| {
        !matches!(
            field.as_str(),
            "value" | "satisfied" | "claim_id" | "version"
        )
    })
}

#[cfg(feature = "evidence-server-cel")]
fn ctx_path_is_undeclared(path: &[String]) -> bool {
    match path.get(1).map(String::as_str) {
        None | Some("purpose") => false,
        Some("subject") => path.get(2).is_some_and(|field| field != "id"),
        Some(_) => true,
    }
}

#[cfg(feature = "evidence-server-cel")]
fn meta_path_is_undeclared(path: &[String], claim: &ClaimDefinition) -> bool {
    match path.get(1).map(String::as_str) {
        None | Some("service_id" | "api_version") => false,
        Some("claim") => path
            .get(2)
            .is_some_and(|field| !matches!(field.as_str(), "id" | "version" | "subject_type")),
        Some("sources") => {
            let Some(alias) = path.get(2) else {
                return false;
            };
            if !claim.source_bindings.contains_key(alias) {
                return true;
            }
            path.get(3)
                .is_some_and(|field| !matches!(field.as_str(), "dataset" | "entity" | "connector"))
        }
        Some(_) => true,
    }
}

#[cfg(feature = "evidence-server-cel")]
fn evaluate_with_cel_mapper(ctx: &CelEvaluationContext<'_>) -> Result<Value, EvidenceError> {
    use cel_mapper_core::{MappingRuntime, RuntimeOptions, StandaloneExpressionInput};
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
    MappingRuntime::new(RuntimeOptions::default())
        .evaluate_cel_expression_with_input(
            ctx.expression,
            StandaloneExpressionInput::new(root_bindings),
        )
        .map_err(|_| EvidenceError::RuleEvaluationFailed)
}

#[cfg(feature = "evidence-server-cel")]
fn cel_meta(evidence: &EvidenceConfig, claim: &ClaimDefinition) -> Value {
    let mut sources = Map::new();
    for (alias, binding) in &claim.source_bindings {
        let connector = match binding.connector {
            evidence_core::config::SourceConnectorKind::RegistryDataApi => "registry_data_api",
            evidence_core::config::SourceConnectorKind::Dci => "dci",
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

fn render_results(results: &[ClaimResultView], format: &str) -> Result<Value, EvidenceError> {
    match format {
        FORMAT_CLAIM_RESULT_JSON => Ok(json!({ "results": results })),
        FORMAT_CCCEV_JSONLD => Ok(render_cccev(results)),
        FORMAT_SD_JWT_VC => Err(EvidenceError::FormatUnsupported),
        _ => Err(EvidenceError::FormatUnsupported),
    }
}

fn render_cccev(results: &[ClaimResultView]) -> Value {
    let evidence = results
        .iter()
        .map(|result| {
            json!({
                "@type": "Evidence",
                "identifier": result.evaluation_id,
                "supportsRequirement": result.claim_id,
                "isConformantTo": result.satisfied,
                "supportsValue": result.value,
                "providedBy": result.provenance.computed_by,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "@context": {
            "cccev": "https://data.europa.eu/m8g/",
            "Evidence": "cccev:Evidence",
            "supportsRequirement": "cccev:supportsRequirement",
            "supportsValue": "cccev:supportsValue"
        },
        "@graph": evidence
    })
}

pub fn credential_profile_for<'a>(
    config: &'a EvidenceConfig,
    evaluation: &evidence_core::StoredEvaluation,
    requested_profile: Option<&'a str>,
) -> Result<(&'a str, &'a CredentialProfileConfig), EvidenceError> {
    if let Some(profile_id) = requested_profile {
        let profile = config
            .credential_profiles
            .get(profile_id)
            .ok_or(EvidenceError::CredentialIssuerNotConfigured)?;
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
