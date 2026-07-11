// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Load all source bindings for a claim. Returns the resolved source map and an
/// optional observation timestamp.
///
/// The observation timestamp is `Some(t)` when at least one binding was served
/// from the memo (i.e., a previous sibling already read the same upstream record
/// in this batch). In that case `t` is the earliest memo entry timestamp, so
/// the caller can propagate it as `iat`. When all bindings were freshly read,
/// returns `None` and the caller falls back to `ctx.now`.
///
/// Implements single-flight: if two concurrent sibling tasks need the same
/// binding key at the same time, one of them fires the upstream request and the
/// other waits for the result via the `Pending` semaphore in the memo slot.
/// Errors are never left in the table; a failed fetch allows the next caller to
/// retry against upstream without poisoning other subjects.
#[allow(clippy::too_many_arguments)]
pub(super) async fn load_sources(
    evidence: Arc<EvidenceConfig>,
    source: Arc<dyn SourceReader>,
    claim: Arc<ClaimDefinition>,
    source_capability: SourceCapability,
    context: EvidenceRequestContext,
    trusted_policy: TrustedPolicyContext,
    purpose: String,
    disclosure: DisclosureProfile,
    format: String,
    binding_concurrency: Arc<Semaphore>,
    fetch_memo: Option<FetchMemo>,
) -> Result<
    (
        BTreeMap<String, Value>,
        Option<OffsetDateTime>,
        BTreeSet<String>,
        Option<MatchingPolicyAudit>,
    ),
    EvidenceError,
> {
    if claim.source_bindings.is_empty() {
        return Ok((BTreeMap::new(), None, BTreeSet::new(), None));
    }
    let trusted_policy = source_scoped_trusted_policy(SourceScopedTrustedPolicyRequest {
        evidence: &evidence,
        claim: &claim,
        source_capability: &source_capability,
        context: &context,
        trusted_policy: &trusted_policy,
        purpose: &purpose,
        disclosure,
        format: &format,
    })?;
    if claim
        .source_bindings
        .values()
        .any(binding_has_source_lookup_inputs)
    {
        return load_sources_with_dependencies(
            evidence,
            source,
            claim,
            source_capability,
            context,
            trusted_policy,
            purpose,
            disclosure,
            format,
            binding_concurrency,
            fetch_memo,
        )
        .await;
    }

    // Bindings within a claim are independent: each owns its own memo key and
    // takes its own `binding_concurrency` permit only when it actually needs
    // to hit upstream. We spawn one task per binding so the upstream waits
    // overlap up to the configured `concurrency.bindings` cap. Memo waiters
    // do not hold a permit, so the cap remains a fan-out bound on outbound
    // calls, not on intra-claim parallelism.
    let mut tasks: JoinSet<(String, BindingFetchResult)> = JoinSet::new();
    for (id, binding) in &claim.source_bindings {
        let id = id.clone();
        let binding = binding.clone();
        let claim_id = claim.id.clone();
        let source = Arc::clone(&source);
        let evidence = Arc::clone(&evidence);
        let source_capability = source_capability.clone();
        let context = context.clone();
        let trusted_policy = trusted_policy.clone();
        let purpose = purpose.clone();
        let binding_concurrency = Arc::clone(&binding_concurrency);
        let fetch_memo = fetch_memo.clone();
        let allowed_disclosures = claim.disclosure.allowed.clone();
        let allowed_formats = claim.formats.clone();
        let claim_value_type = claim.value.value_type.clone();
        let claim_purpose_constraints = claim_purpose_constraints(&evidence, &claim);
        let format = format.clone();
        tasks.spawn(async move {
            let result = load_one_binding(
                &evidence,
                source,
                &source_capability,
                claim_id.as_str(),
                &claim_purpose_constraints,
                &allowed_disclosures,
                &allowed_formats,
                claim_value_type.as_str(),
                &binding,
                &context,
                &trusted_policy,
                &purpose,
                disclosure,
                format.as_str(),
                binding_concurrency,
                fetch_memo.as_ref(),
            )
            .await;
            (id, result)
        });
    }

    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    let mut oldest_memo_ts: Option<OffsetDateTime> = None;
    let mut redaction_fields = BTreeSet::new();
    let mut matching_policy_audit = MatchingPolicyAudit::default();
    while let Some(joined) = tasks.join_next().await {
        let (id, result) = match joined {
            Ok(pair) => pair,
            Err(join_error) if join_error.is_panic() => {
                tracing::error!(
                    target: "registry_notary_server::runtime",
                    error = %join_error,
                    "binding task panicked",
                );
                return Err(EvidenceError::RuleEvaluationFailed);
            }
            Err(_) => return Err(EvidenceError::RuleEvaluationFailed),
        };
        let (value, memo_ts, binding_policy_effect) = result?;
        redaction_fields.extend(binding_policy_effect.redaction_fields);
        if let Some(audit) = binding_policy_effect.audit {
            matching_policy_audit.record(id.clone(), audit);
        }
        if let Some(ts) = memo_ts {
            oldest_memo_ts = Some(match oldest_memo_ts {
                None => ts,
                Some(prev) => prev.min(ts),
            });
        }
        out.insert(id, value);
    }
    Ok((
        out,
        oldest_memo_ts,
        redaction_fields,
        (!matching_policy_audit.is_empty()).then_some(matching_policy_audit),
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn load_sources_with_dependencies(
    evidence: Arc<EvidenceConfig>,
    source: Arc<dyn SourceReader>,
    claim: Arc<ClaimDefinition>,
    source_capability: SourceCapability,
    context: EvidenceRequestContext,
    trusted_policy: TrustedPolicyContext,
    purpose: String,
    disclosure: DisclosureProfile,
    format: String,
    binding_concurrency: Arc<Semaphore>,
    fetch_memo: Option<FetchMemo>,
) -> Result<
    (
        BTreeMap<String, Value>,
        Option<OffsetDateTime>,
        BTreeSet<String>,
        Option<MatchingPolicyAudit>,
    ),
    EvidenceError,
> {
    let mut pending = claim.source_bindings.clone();
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    let mut oldest_memo_ts: Option<OffsetDateTime> = None;
    let mut redaction_fields = BTreeSet::new();
    let mut matching_policy_audit = MatchingPolicyAudit::default();
    let mut dependencies_by_binding = BTreeMap::new();
    for (id, binding) in &claim.source_bindings {
        let dependencies = binding_source_lookup_dependencies(binding, &claim.source_bindings)?;
        dependencies_by_binding.insert(id.clone(), dependencies);
    }
    validate_source_lookup_dependency_graph(&dependencies_by_binding)?;

    while !pending.is_empty() {
        let mut ready_ids = Vec::new();
        for id in pending.keys() {
            let Some(dependencies) = dependencies_by_binding.get(id) else {
                return Err(EvidenceError::InvalidRequest);
            };
            if dependencies
                .iter()
                .all(|source_id| out.contains_key(source_id))
            {
                ready_ids.push(id.clone());
            }
        }
        if ready_ids.is_empty() {
            return Err(EvidenceError::InvalidRequest);
        }

        let mut ready_bindings = Vec::new();
        for id in ready_ids {
            let Some(binding) = pending.get(&id).cloned() else {
                continue;
            };
            let (read_binding, read_context) =
                binding_with_resolved_source_lookup_context(&binding, &context, &out)
                    .map_err(|error| collapse_dependent_lookup_error(&binding, error))?;
            ready_bindings.push((id, binding, read_binding, read_context));
        }

        let mut tasks: JoinSet<(String, BindingFetchResult)> = JoinSet::new();
        for (id, binding, read_binding, read_context) in ready_bindings {
            // Defensive: each `id` is a unique key cloned from `pending` in the
            // materialization phase above with nothing removed in between, so
            // this always succeeds. Guard the invariant rather than silently
            // drop a binding.
            if pending.remove(&id).is_none() {
                return Err(EvidenceError::InvalidRequest);
            }
            let claim_id = claim.id.clone();
            let source = Arc::clone(&source);
            let evidence = Arc::clone(&evidence);
            let source_capability = source_capability.clone();
            let context = context.clone();
            let trusted_policy = trusted_policy.clone();
            let purpose = purpose.clone();
            let binding_concurrency = Arc::clone(&binding_concurrency);
            let fetch_memo = fetch_memo.clone();
            let allowed_disclosures = claim.disclosure.allowed.clone();
            let allowed_formats = claim.formats.clone();
            let claim_value_type = claim.value.value_type.clone();
            let claim_purpose_constraints = claim_purpose_constraints(&evidence, &claim);
            let format = format.clone();
            tasks.spawn(async move {
                let result = load_one_binding_with_read_context(
                    &evidence,
                    source,
                    &source_capability,
                    claim_id.as_str(),
                    &claim_purpose_constraints,
                    &allowed_disclosures,
                    &allowed_formats,
                    claim_value_type.as_str(),
                    &binding,
                    &context,
                    &read_binding,
                    &read_context,
                    &trusted_policy,
                    &purpose,
                    disclosure,
                    format.as_str(),
                    binding_concurrency,
                    fetch_memo.as_ref(),
                )
                .await;
                (id, result)
            });
        }

        while let Some(joined) = tasks.join_next().await {
            let (id, result) = match joined {
                Ok(pair) => pair,
                Err(join_error) if join_error.is_panic() => {
                    tracing::error!(
                        target: "registry_notary_server::runtime",
                        error = %join_error,
                        "binding task panicked",
                    );
                    return Err(EvidenceError::RuleEvaluationFailed);
                }
                Err(_) => return Err(EvidenceError::RuleEvaluationFailed),
            };
            let (value, memo_ts, binding_policy_effect) = result?;
            redaction_fields.extend(binding_policy_effect.redaction_fields);
            if let Some(audit) = binding_policy_effect.audit {
                matching_policy_audit.record(id.clone(), audit);
            }
            if let Some(ts) = memo_ts {
                oldest_memo_ts = Some(match oldest_memo_ts {
                    None => ts,
                    Some(prev) => prev.min(ts),
                });
            }
            out.insert(id, value);
        }
    }

    Ok((
        out,
        oldest_memo_ts,
        redaction_fields,
        (!matching_policy_audit.is_empty()).then_some(matching_policy_audit),
    ))
}

pub(super) fn binding_has_source_lookup_inputs(
    binding: &registry_notary_core::SourceBindingConfig,
) -> bool {
    parse_source_lookup_reference(&binding.lookup.input).is_some()
        || binding
            .query_fields
            .iter()
            .any(|field| parse_source_lookup_reference(&field.input).is_some())
}

pub(super) fn validate_source_lookup_dependency_graph(
    dependencies_by_binding: &BTreeMap<String, BTreeSet<String>>,
) -> Result<(), EvidenceError> {
    if detect_dependency_cycle(dependencies_by_binding).is_some() {
        return Err(EvidenceError::InvalidRequest);
    }
    Ok(())
}

pub(super) fn binding_source_lookup_dependencies(
    binding: &registry_notary_core::SourceBindingConfig,
    all_bindings: &BTreeMap<String, SourceBindingConfig>,
) -> Result<BTreeSet<String>, EvidenceError> {
    let mut dependencies = BTreeSet::new();
    let inputs = std::iter::once(binding.lookup.input.as_str()).chain(
        binding
            .query_fields
            .iter()
            .map(|field| field.input.as_str()),
    );
    for input in inputs {
        let Some(reference) = parse_source_lookup_reference(input) else {
            continue;
        };
        if !all_bindings.contains_key(reference.binding_id) {
            return Err(EvidenceError::InvalidRequest);
        }
        dependencies.insert(reference.binding_id.to_string());
    }
    Ok(dependencies)
}

pub(super) fn binding_with_resolved_source_lookup_context(
    binding: &registry_notary_core::SourceBindingConfig,
    context: &EvidenceRequestContext,
    sources: &BTreeMap<String, Value>,
) -> Result<(SourceBindingConfig, EvidenceRequestContext), EvidenceError> {
    if !binding_has_source_lookup_inputs(binding) {
        return Ok((binding.clone(), context.clone()));
    }

    let mut binding = binding.clone();
    let mut context = context.clone();
    let mut synthetic_index = 0;
    let lookup_input = materialize_source_lookup_input(
        &binding.lookup.input,
        &mut context,
        sources,
        synthetic_index,
    )?;
    if let Some(input) = lookup_input {
        binding.lookup.input = input;
        synthetic_index += 1;
    }
    for query_field in &mut binding.query_fields {
        let query_input = materialize_source_lookup_input(
            &query_field.input,
            &mut context,
            sources,
            synthetic_index,
        )?;
        if let Some(input) = query_input {
            query_field.input = input;
            synthetic_index += 1;
        }
    }
    Ok((binding, context))
}

pub(super) fn materialize_source_lookup_input(
    input: &str,
    context: &mut EvidenceRequestContext,
    sources: &BTreeMap<String, Value>,
    synthetic_index: usize,
) -> Result<Option<String>, EvidenceError> {
    let Some(reference) = parse_source_lookup_reference(input) else {
        return Ok(None);
    };
    let value = scalar_source_lookup_value(sources, reference)?;
    let attribute = format!("{SOURCE_LOOKUP_CONTEXT_ATTRIBUTE_PREFIX}{synthetic_index}");
    context.target.attributes.insert(attribute.clone(), value);
    Ok(Some(format!("target.attributes.{attribute}")))
}

pub(super) fn scalar_source_lookup_value(
    sources: &BTreeMap<String, Value>,
    reference: SourceLookupReference<'_>,
) -> Result<Value, EvidenceError> {
    let source = sources
        .get(reference.binding_id)
        .ok_or(EvidenceError::SourceNotFound)?;
    let row = match source {
        Value::Array(rows) if rows.is_empty() => return Err(EvidenceError::SourceNotFound),
        Value::Array(rows) if rows.len() > 1 => return Err(EvidenceError::SourceAmbiguous),
        Value::Array(rows) => rows.first().ok_or(EvidenceError::SourceNotFound)?,
        row => row,
    };
    let value = get_json_path(row, reference.field_path).ok_or(EvidenceError::SourceNotFound)?;
    match value {
        Value::String(_) | Value::Number(_) | Value::Bool(_) => Ok(value.clone()),
        Value::Null => Err(EvidenceError::SourceNotFound),
        Value::Array(_) | Value::Object(_) => Err(EvidenceError::InvalidRequest),
    }
}

/// Derive the lookup value for a binding from the request context.
pub(super) fn binding_lookup_value_for_context(
    binding: &registry_notary_core::SourceBindingConfig,
    context: &EvidenceRequestContext,
) -> Result<Value, EvidenceError> {
    if binding.lookup.op != "eq" {
        return Err(EvidenceError::InvalidRequest);
    }
    match context.lookup_value(binding.lookup.input.as_str()) {
        Some(value) => Ok(value),
        None => Err(missing_context_error(binding.lookup.input.as_str())),
    }
}

pub(super) fn binding_cache_value_for_context(
    binding: &registry_notary_core::SourceBindingConfig,
    context: &EvidenceRequestContext,
) -> Result<Value, EvidenceError> {
    if binding.query_fields.is_empty() {
        return binding_lookup_value_for_context(binding, context);
    }
    let mut values = Vec::with_capacity(binding.query_fields.len());
    for query_field in &binding.query_fields {
        if query_field.op != "eq" {
            return Err(EvidenceError::InvalidRequest);
        }
        let value = context
            .lookup_value(query_field.input.as_str())
            .ok_or_else(|| missing_context_error(query_field.input.as_str()))?;
        values.push(serde_json::json!({
            "field": query_field.field.clone(),
            "op": query_field.op.clone(),
            "value": value,
        }));
    }
    Ok(Value::Array(values))
}
