// SPDX-License-Identifier: Apache-2.0

use super::*;

// ---------------------------------------------------------------------------
// Per-batch fetch memoization (Stage 2)
// ---------------------------------------------------------------------------

/// One cached upstream result: the raw JSON record and the timestamp at which
/// the upstream call was observed. The timestamp propagates to `iat` so that
/// subjects sharing a memoized read produce credentials with identical iat.
#[derive(Clone)]
pub(super) struct MemoEntry {
    value: Value,
    observed_at: OffsetDateTime,
}

/// A slot in the memoization table.
///
/// `Pending` means one task is already in-flight for this key. The semaphore
/// starts at 0 permits; waiters `acquire` and block until the owner signals.
/// The owner signals by calling `add_permits(usize::MAX / 2)` on completion
/// (whether success or error). After signalling, the owner either upgrades the
/// slot to `Ready` (success) or removes it (error). Waiters then re-check the
/// table under the lock to see which outcome occurred.
///
/// This implements "single-flight": at most one in-flight upstream request per
/// cache key at any point in time, across all concurrent claim tasks within the
/// same `batch_evaluate` call.
pub(super) enum MemoSlot {
    Pending(Arc<tokio::sync::Semaphore>),
    Ready(MemoEntry),
}

/// Memoization state scoped to a single `batch_evaluate` call.
///
/// `slots`: SHA-256 hex of the canonical upstream request to a slot that is
/// either in-flight (`Pending`) or complete (`Ready`). Errors are never left
/// in the table; a transient failure must not poison other subjects.
///
/// `hits` / `misses`: process-cheap counters bumped from the memo coordination
/// paths so tests and operators can observe dedup effectiveness without
/// scraping the `tracing` stream (whose format is not part of the contract).
pub struct MemoState {
    slots: Mutex<HashMap<String, MemoSlot>>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl MemoState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, MemoSlot>> {
        self.slots.lock().expect("fetch_memo mutex is not poisoned")
    }

    fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }
}

impl Default for MemoState {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MemoState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoState")
            .field("hits", &self.hits.load(Ordering::Relaxed))
            .field("misses", &self.misses.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Build the canonical cache key for one (binding, purpose) pair.
///
/// We include every field that determines the upstream wire request:
/// - connection_id (which upstream server)
/// - connector kind (RDA vs DCI)
/// - dataset, entity (RDA path segments / DCI search domain)
/// - lookup_field, lookup_op, lookup_value (the query predicate)
/// - projected_fields_set (sorted; determines which columns the upstream returns)
/// - purpose (sent as a request header; may affect server-side filtering)
/// - minimized source context (requester/relationship fields can affect adapters)
/// - DCI-specific: query_type, registry_type, record_type, field_paths (sorted)
///
/// We serialize to a `serde_json::Value` with sorted keys, then SHA-256 the
/// bytes. This is collision-resistant enough for a single-request lifetime.
pub(super) fn cache_key_for_binding(
    binding: &registry_notary_core::SourceBindingConfig,
    lookup_value: &Value,
    source_context: &EvidenceRequestContext,
    purpose: &str,
) -> String {
    use registry_notary_core::SourceConnectorKind;
    let connector = match binding.connector {
        SourceConnectorKind::RegistryDataApi => "rda",
        SourceConnectorKind::Dci => "dci",
        SourceConnectorKind::SourceAdapterSidecar => "source_adapter_sidecar",
    };
    // Sorted projected fields set (what the upstream is asked to return).
    let mut fields: Vec<String> = binding.fields.values().map(|f| f.field.clone()).collect();
    fields.sort();
    fields.dedup();
    // Include the lookup field itself since it is always projected.
    if !fields.contains(&binding.lookup.field) {
        fields.push(binding.lookup.field.clone());
        fields.sort();
    }

    // For DCI we include the connection-level query shaping fields, because
    // two connections with identical binding fields but different query_type
    // will produce distinct wire requests. These are carried by the connection
    // config, not the binding, so callers that need DCI separation must use
    // different connection IDs.
    //
    // The connection_id itself is already included below and differentiates
    // two connections. Including it is sufficient; we do not need to
    // separately hash the DCI sub-fields because the connection_id is a
    // stable proxy for the full connection config. This is by design: the
    // cache key only needs to cover what varies per-call, and two calls to
    // the same connection with the same binding/lookup/purpose are identical.

    let key_obj = serde_json::json!({
        "connection_id": binding.connection,
        "connector": connector,
        "dataset": binding.dataset,
        "entity": binding.entity,
        "lookup_field": binding.lookup.field,
        "lookup_op": binding.lookup.op,
        "lookup_value": lookup_value,
        "projected_fields": fields,
        "purpose": purpose,
        "source_context": source_context,
    });
    // Serialize with sorted keys (serde_json sorts object keys by default) and
    // hash the bytes.
    let bytes = serde_json::to_vec(&key_obj).unwrap_or_default();
    sha256_hex(&bytes)
}

/// Group bindings across (subject, claim, binding) by their bulk-eligible
/// connection, dispatch one `SourceReader::read_many` per group, and seed
/// the per-batch memo with the resulting values.
///
/// This runs at the start of `batch_evaluate`. Bindings on connections with
/// `bulk_mode = None` are skipped here and handled by the per-target
/// evaluation path as before (the trait default `read_many` is never called
/// for them).
///
/// Errors from `read_many` are NOT inserted into the memo (matching Stage 2
/// error-not-cached semantics). A target whose bulk read failed will fall
/// through to a fresh per-target `read_one` call.
#[allow(clippy::too_many_arguments)]
pub(super) async fn prefetch_bulk_bindings(
    evidence: Arc<EvidenceConfig>,
    source: Arc<dyn SourceReader>,
    source_capability: SourceCapability,
    contexts: &[EvidenceRequestContext],
    requested_claims: &[ClaimRef],
    claim_versions: &ClaimVersionSelections,
    purpose: &str,
    disclosure: DisclosureProfile,
    format: &str,
    trusted_policy: &TrustedPolicyContext,
    fetch_memo: FetchMemo,
) {
    if contexts.is_empty() || requested_claims.is_empty() {
        return;
    }
    // Closure of claims (requested + transitive deps) so we cover bindings
    // that only show up under depends_on edges.
    let levels = match build_claim_levels(&evidence, requested_claims, claim_versions) {
        Ok(levels) => levels,
        Err(_) => return,
    };
    let claim_closure: Vec<String> = levels.into_iter().flatten().collect();

    // Group key: (connection_id, dataset, entity, query_signature, projected_fields_sorted).
    // Two bindings in different claims that share this tuple AND target the
    // same connection produce identical wire requests and may be batched
    // together. The lookup_op and purpose are uniform within a batch.
    type GroupKey = (String, String, String, Vec<(String, String)>, Vec<String>);
    let mut groups: BTreeMap<
        GroupKey,
        Vec<(
            SourceBindingConfig,
            EvidenceRequestContext,
            EvidenceRequestContext,
            String,
        )>,
    > = BTreeMap::new();
    for claim_id in &claim_closure {
        let Ok(claim) = find_claim_for_selection(&evidence, claim_id, claim_versions) else {
            continue;
        };
        for binding in claim.source_bindings.values() {
            let Some(connection_id) = binding.connection.as_deref() else {
                continue;
            };
            let Some(connection_cfg) = evidence.source_connections.get(connection_id) else {
                continue;
            };
            if connection_cfg.bulk_mode == BulkMode::None {
                continue;
            }
            let mut fields: Vec<String> =
                binding.fields.values().map(|f| f.field.clone()).collect();
            if let Some(source_observed_at_field) =
                binding.matching.source_observed_at_field.as_ref()
            {
                fields.push(source_observed_at_field.clone());
            }
            let query_signature: Vec<(String, String)> = if binding.query_fields.is_empty() {
                vec![(binding.lookup.field.clone(), binding.lookup.op.clone())]
            } else {
                binding
                    .query_fields
                    .iter()
                    .map(|field| (field.field.clone(), field.op.clone()))
                    .collect()
            };
            for (field, _) in &query_signature {
                if !fields.iter().any(|projected| projected == field) {
                    fields.push(field.clone());
                }
            }
            fields.sort();
            fields.dedup();
            let group_key: GroupKey = (
                connection_id.to_string(),
                binding.dataset.clone(),
                binding.entity.clone(),
                query_signature,
                fields,
            );
            for context in contexts {
                if source_scoped_trusted_policy(SourceScopedTrustedPolicyRequest {
                    evidence: &evidence,
                    claim,
                    source_capability: &source_capability,
                    context,
                    trusted_policy,
                    purpose,
                    disclosure,
                    format,
                })
                .is_err()
                {
                    continue;
                }
                let policy_effect = match validate_matching_policy(
                    &evidence,
                    &source_capability,
                    &claim_purpose_constraints(&evidence, claim),
                    binding,
                    context,
                    purpose,
                    trusted_policy,
                    &claim.disclosure.allowed,
                    &claim.formats,
                    disclosure,
                    format,
                ) {
                    Ok(effect) => effect,
                    Err(_) => continue,
                };
                if ensure_redaction_disclosure_allowed(
                    &claim.disclosure.allowed,
                    claim.value.value_type.as_str(),
                    disclosure,
                    &policy_effect.redaction_fields,
                )
                .is_err()
                {
                    continue;
                }
                let source_context = minimized_context_for_binding(binding, context);
                // Compute the per-target cache key and ensure the same
                // (binding, target) pair is not enqueued twice (e.g. two
                // claims sharing a binding).
                let lookup_value = match binding_cache_value_for_context(binding, context) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let cache_key =
                    cache_key_for_binding(binding, &lookup_value, &source_context, purpose);
                let bucket = groups.entry(group_key.clone()).or_default();
                if bucket.iter().any(|(_, _, _, k)| k == &cache_key) {
                    continue;
                }
                bucket.push((binding.clone(), source_context, context.clone(), cache_key));
            }
        }
    }
    if groups.is_empty() {
        return;
    }
    // Dispatch each group as one read_many call. Keep results in input order
    // so cache_keys line up. Run groups sequentially to avoid contending on
    // the same connection's outbound semaphore across groups; within a group
    // the connector decides whether to issue one bulk request or fall back
    // to N concurrent read_one calls.
    for (group_key, entries) in groups {
        let pairs: Vec<(SourceBindingConfig, EvidenceRequestContext)> = entries
            .iter()
            .map(|(binding, source_context, _, _)| (binding.clone(), source_context.clone()))
            .collect();
        tracing::info!(
            target: "registry_notary_server::bulk",
            connection_id = %group_key.0,
            dataset = %group_key.1,
            entity = %group_key.2,
            batch_size = pairs.len(),
            "bulk_prefetch_dispatch",
        );
        let results = source
            .read_many_context_with_capability(&source_capability, pairs, purpose)
            .await;
        let observed_at = OffsetDateTime::now_utc();
        for (entry, result) in entries.into_iter().zip(results) {
            let (binding, _, original_context, cache_key) = entry;
            match result {
                Ok(value) => {
                    if validate_required_binding_fields(&binding, &value).is_err() {
                        continue;
                    }
                    let Ok(source_observed_at) = source_observed_at_from_row(&binding, &value)
                    else {
                        continue;
                    };
                    if validate_matching_freshness_policy(
                        &evidence,
                        &binding,
                        &source_capability,
                        &original_context,
                        purpose,
                        trusted_policy,
                        &[],
                        &[],
                        &[],
                        disclosure,
                        format,
                        source_observed_at,
                    )
                    .is_err()
                    {
                        continue;
                    }
                    let observed_at = source_observed_at.unwrap_or(observed_at);
                    let mut guard = fetch_memo.lock();
                    // Insert Ready directly. No Pending phase is needed: the
                    // memo is empty at this point and subject tasks have not
                    // started yet, so there is nothing to coordinate with.
                    guard.insert(cache_key, MemoSlot::Ready(MemoEntry { value, observed_at }));
                }
                Err(_) => {
                    // Errors are not cached. The per-subject task will retry
                    // through its own read_one path on cache miss.
                }
            }
        }
    }
}

/// Default `read_many` implementation: drive `read_one` futures concurrently
/// and collect results in input order.
///
/// We use a manual poll loop instead of `JoinSet` because the trait borrows
/// `&self` (`JoinSet::spawn` would require `'static`). Each `read_one` future
/// already acquires the per-connection outbound semaphore, so the effective
/// outbound fan-out is naturally bounded; we do not add a second cap here.
/// Load a single source binding, consulting and updating the batch memo.
///
/// Returns `(value, Some(observed_at))` when the result came from the memo
/// (so the caller can pin `iat` to the original read time), or
/// `(value, None)` when the value was freshly fetched.
///
/// Single-flight protocol:
/// 1. Lock the memo; check for a `Ready` entry (cache hit) or a `Pending` slot
///    (another task is in-flight for the same key).
/// 2. If neither exists, insert a `Pending` slot and become the owner.
/// 3. Owner fetches upstream (outside the lock), then under the lock upgrades
///    to `Ready` on success or removes the slot on error; in both cases signals
///    the pending semaphore so waiting tasks can proceed.
/// 4. Waiters re-check the table after the semaphore fires; if `Ready` they
///    return the cached value; if the slot was removed they fall through and
///    attempt a fresh fetch themselves.
#[allow(clippy::too_many_arguments)]
pub(super) async fn load_one_binding(
    evidence: &EvidenceConfig,
    source: Arc<dyn SourceReader>,
    source_capability: &SourceCapability,
    claim_id: &str,
    claim_purpose_constraints: &[Vec<String>],
    allowed_disclosures: &[String],
    allowed_formats: &[String],
    claim_value_type: &str,
    binding: &registry_notary_core::SourceBindingConfig,
    context: &EvidenceRequestContext,
    trusted_policy: &TrustedPolicyContext,
    purpose: &str,
    disclosure: DisclosureProfile,
    format: &str,
    binding_concurrency: Arc<Semaphore>,
    fetch_memo: Option<&FetchMemo>,
) -> Result<(Value, Option<OffsetDateTime>, BindingPolicyEffect), EvidenceError> {
    load_one_binding_with_read_context(
        evidence,
        source,
        source_capability,
        claim_id,
        claim_purpose_constraints,
        allowed_disclosures,
        allowed_formats,
        claim_value_type,
        binding,
        context,
        binding,
        context,
        trusted_policy,
        purpose,
        disclosure,
        format,
        binding_concurrency,
        fetch_memo,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn load_one_binding_with_read_context(
    evidence: &EvidenceConfig,
    source: Arc<dyn SourceReader>,
    source_capability: &SourceCapability,
    claim_id: &str,
    claim_purpose_constraints: &[Vec<String>],
    allowed_disclosures: &[String],
    allowed_formats: &[String],
    claim_value_type: &str,
    binding: &registry_notary_core::SourceBindingConfig,
    context: &EvidenceRequestContext,
    read_binding: &registry_notary_core::SourceBindingConfig,
    read_context: &EvidenceRequestContext,
    trusted_policy: &TrustedPolicyContext,
    purpose: &str,
    disclosure: DisclosureProfile,
    format: &str,
    binding_concurrency: Arc<Semaphore>,
    fetch_memo: Option<&FetchMemo>,
) -> Result<(Value, Option<OffsetDateTime>, BindingPolicyEffect), EvidenceError> {
    let binding_policy_effect = match validate_matching_policy(
        evidence,
        source_capability,
        claim_purpose_constraints,
        binding,
        context,
        purpose,
        trusted_policy,
        allowed_disclosures,
        allowed_formats,
        disclosure,
        format,
    ) {
        Ok(effect) => effect,
        Err(error) => return Err(collapse_matching_error(binding, error)),
    };
    ensure_redaction_disclosure_allowed(
        allowed_disclosures,
        claim_value_type,
        disclosure,
        &binding_policy_effect.redaction_fields,
    )?;
    // Compute the lookup value to build the cache key. If this fails (e.g.
    // unsupported lookup op) we skip the memo entirely and fall through to a
    // direct fetch; the connector will surface the same error there.
    let lookup_value_for_key = binding_cache_value_for_context(read_binding, read_context).ok();
    let source_context_for_key = minimized_context_for_binding(read_binding, read_context);

    if let (Some(memo), Some(ref lv)) = (fetch_memo, &lookup_value_for_key) {
        let key = cache_key_for_binding(read_binding, lv, &source_context_for_key, purpose);

        // --- Phase 1: check under lock, decide action (no await while locked) ---
        enum Action {
            Hit(Value, OffsetDateTime),
            Owner(Arc<tokio::sync::Semaphore>), // we inserted Pending; now fetch
            Wait(Arc<tokio::sync::Semaphore>),  // another task is fetching; wait
        }
        let action = {
            let mut guard = memo.lock();
            match guard.get(&key) {
                Some(MemoSlot::Ready(entry)) => Action::Hit(entry.value.clone(), entry.observed_at),
                Some(MemoSlot::Pending(sem)) => Action::Wait(Arc::clone(sem)),
                None => {
                    let sem = Arc::new(tokio::sync::Semaphore::new(0));
                    guard.insert(key.clone(), MemoSlot::Pending(Arc::clone(&sem)));
                    Action::Owner(sem)
                }
            }
            // guard is dropped here, before any await
        };
        match action {
            Action::Hit(value, ts) => {
                validate_matching_freshness_policy(
                    evidence,
                    binding,
                    source_capability,
                    context,
                    purpose,
                    trusted_policy,
                    claim_purpose_constraints,
                    allowed_disclosures,
                    allowed_formats,
                    disclosure,
                    format,
                    Some(ts),
                )
                .map_err(|error| collapse_matching_error(binding, error))?;
                memo.record_hit();
                tracing::info!(
                    target: "registry_notary_server::memo",
                    "memo_hit",
                );
                return Ok((value, Some(ts), binding_policy_effect.clone()));
            }
            Action::Owner(sem) => {
                let result = fetch_and_signal(
                    evidence,
                    source,
                    source_capability,
                    claim_id,
                    read_binding,
                    read_context,
                    trusted_policy,
                    purpose,
                    claim_purpose_constraints,
                    allowed_disclosures,
                    allowed_formats,
                    disclosure,
                    format,
                    binding_concurrency,
                    memo,
                    key,
                    sem,
                )
                .await;
                return result
                    .map(|(value, memo_ts)| (value, memo_ts, binding_policy_effect.clone()))
                    .map_err(|error| collapse_matching_error(binding, error));
            }
            Action::Wait(sem) => {
                // --- Phase 2: wait for the in-flight owner to finish ---
                let _ = sem.acquire().await;
                // Re-check: if the owner succeeded we now see Ready.
                let hit = {
                    let guard = memo.lock();
                    if let Some(MemoSlot::Ready(entry)) = guard.get(&key) {
                        Some((entry.value.clone(), entry.observed_at))
                    } else {
                        None
                    }
                };
                if let Some((value, ts)) = hit {
                    validate_matching_freshness_policy(
                        evidence,
                        binding,
                        source_capability,
                        context,
                        purpose,
                        trusted_policy,
                        claim_purpose_constraints,
                        allowed_disclosures,
                        allowed_formats,
                        disclosure,
                        format,
                        Some(ts),
                    )
                    .map_err(|error| collapse_matching_error(binding, error))?;
                    memo.record_hit();
                    tracing::info!(
                        target: "registry_notary_server::memo",
                        "memo_hit",
                    );
                    return Ok((value, Some(ts), binding_policy_effect.clone()));
                }
                // Owner failed; fall through to an unconditional fresh fetch.
            }
        }
    }

    // No memo (single-subject evaluate) or lookup derivation failed or the
    // previous owner failed: fetch directly without memoizing.
    fetch_binding_direct(
        evidence,
        source,
        source_capability,
        claim_id,
        read_binding,
        read_context,
        trusted_policy,
        purpose,
        claim_purpose_constraints,
        allowed_disclosures,
        allowed_formats,
        disclosure,
        format,
        binding_concurrency,
    )
    .await
    .map(|(value, memo_ts)| (value, memo_ts, binding_policy_effect.clone()))
    .map_err(|error| collapse_matching_error(binding, error))
}

/// Signal-all permit count used when waking memo waiters. Matches tokio's
/// documented cap so a single `add_permits` releases every parked acquirer.
pub(super) const MEMO_SIGNAL_PERMITS: usize = tokio::sync::Semaphore::MAX_PERMITS;

/// Drop guard for the `Pending` memo slot owned by `fetch_and_signal`.
///
/// On drop (return-by-error OR panic during the upstream fetch), removes the
/// Pending slot from the memo and signals all waiters so they wake up and
/// fall through to a fresh fetch instead of blocking forever on `acquire`.
///
/// The Owner's success path calls `disarm()` before installing the `Ready`
/// entry so this guard becomes a no-op for the happy path.
pub(super) struct PendingGuard<'a> {
    memo: Option<&'a FetchMemo>,
    key: String,
    sem: Arc<tokio::sync::Semaphore>,
}

impl<'a> PendingGuard<'a> {
    fn new(memo: &'a FetchMemo, key: String, sem: Arc<tokio::sync::Semaphore>) -> Self {
        Self {
            memo: Some(memo),
            key,
            sem,
        }
    }

    fn disarm(&mut self) {
        self.memo = None;
    }
}

impl<'a> Drop for PendingGuard<'a> {
    fn drop(&mut self) {
        if let Some(memo) = self.memo.take() {
            // Remove only if the slot is still our Pending entry. If the
            // Owner already installed a Ready value before bailing for some
            // other reason, we must not clobber it.
            let mut guard = memo.lock();
            if let Some(MemoSlot::Pending(slot_sem)) = guard.get(&self.key) {
                if Arc::ptr_eq(slot_sem, &self.sem) {
                    guard.remove(&self.key);
                }
            }
            drop(guard);
            self.sem.add_permits(MEMO_SIGNAL_PERMITS);
        }
    }
}

/// Fetch a binding from upstream and, on success, upgrade the Pending slot in
/// the memo to Ready and signal all waiters.
///
/// On error or panic, the `PendingGuard` drop runs: it removes the Pending slot
/// so the next caller can retry, and signals waiters so they are not stuck.
/// Waiters re-check the slot after waking and fall through to a fresh fetch
/// when they find it absent (matching the existing "owner failed" branch in
/// `load_one_binding`).
#[allow(clippy::too_many_arguments)]
pub(super) async fn fetch_and_signal(
    evidence: &EvidenceConfig,
    source: Arc<dyn SourceReader>,
    source_capability: &SourceCapability,
    claim_id: &str,
    binding: &registry_notary_core::SourceBindingConfig,
    context: &EvidenceRequestContext,
    trusted_policy: &TrustedPolicyContext,
    purpose: &str,
    claim_purpose_constraints: &[Vec<String>],
    allowed_disclosures: &[String],
    allowed_formats: &[String],
    disclosure: DisclosureProfile,
    format: &str,
    binding_concurrency: Arc<Semaphore>,
    memo: &FetchMemo,
    key: String,
    pending_sem: Arc<tokio::sync::Semaphore>,
) -> Result<(Value, Option<OffsetDateTime>), EvidenceError> {
    let mut guard = PendingGuard::new(memo, key.clone(), Arc::clone(&pending_sem));

    let (value, source_observed_at) = fetch_binding_direct(
        evidence,
        Arc::clone(&source),
        source_capability,
        claim_id,
        binding,
        context,
        trusted_policy,
        purpose,
        claim_purpose_constraints,
        allowed_disclosures,
        allowed_formats,
        disclosure,
        format,
        binding_concurrency,
    )
    .await?;
    let observed_at = source_observed_at.unwrap_or_else(OffsetDateTime::now_utc);

    // Success path: install the Ready entry and signal waiters explicitly,
    // then disarm the guard so it does not also clear the slot we just wrote.
    {
        let mut memo_guard = memo.lock();
        memo_guard.insert(
            key,
            MemoSlot::Ready(MemoEntry {
                value: value.clone(),
                observed_at,
            }),
        );
    }
    pending_sem.add_permits(MEMO_SIGNAL_PERMITS);
    guard.disarm();
    memo.record_miss();
    tracing::info!(
        target: "registry_notary_server::memo",
        "memo_miss",
    );
    // Return observed_at so the owner's issued_at matches the memo entry's
    // timestamp. Sibling claims that hit the memo will see the same
    // observed_at, giving all claims for this binding an identical iat.
    Ok((value, Some(observed_at)))
}

/// Unconditionally fetch a single binding from upstream (no memo interaction).
/// Returns the authoritative source observation timestamp when the binding
/// declares one.
#[allow(clippy::too_many_arguments)]
pub(super) async fn fetch_binding_direct(
    evidence: &EvidenceConfig,
    source: Arc<dyn SourceReader>,
    source_capability: &SourceCapability,
    claim_id: &str,
    binding: &registry_notary_core::SourceBindingConfig,
    context: &EvidenceRequestContext,
    trusted_policy: &TrustedPolicyContext,
    purpose: &str,
    claim_purpose_constraints: &[Vec<String>],
    allowed_disclosures: &[String],
    allowed_formats: &[String],
    disclosure: DisclosureProfile,
    format: &str,
    binding_concurrency: Arc<Semaphore>,
) -> Result<(Value, Option<OffsetDateTime>), EvidenceError> {
    require_source_read_capability(source_capability, claim_id)?;
    let _permit = match binding_concurrency.acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => return Err(EvidenceError::RuleEvaluationFailed),
    };
    let source_context = minimized_context_for_binding(binding, context);
    let source_observed_at = if binding.matching.max_source_age_seconds.is_some() {
        let source_observed_at = source
            .source_observed_at_for_context_with_capability(
                source_capability,
                claim_id,
                binding,
                &source_context,
                purpose,
            )
            .await?;
        validate_matching_freshness_policy(
            evidence,
            binding,
            source_capability,
            context,
            purpose,
            trusted_policy,
            claim_purpose_constraints,
            allowed_disclosures,
            allowed_formats,
            disclosure,
            format,
            source_observed_at,
        )?;
        source_observed_at
    } else {
        None
    };
    let row = source
        .read_one_for_context_with_capability(
            source_capability,
            claim_id,
            binding,
            &source_context,
            purpose,
        )
        .await?;
    validate_required_binding_fields(binding, &row)?;
    let row_source_observed_at = source_observed_at_from_row(binding, &row)?;
    if binding.matching.source_observed_at_field.is_some() {
        validate_matching_freshness_policy(
            evidence,
            binding,
            source_capability,
            context,
            purpose,
            trusted_policy,
            claim_purpose_constraints,
            allowed_disclosures,
            allowed_formats,
            disclosure,
            format,
            row_source_observed_at,
        )?;
    }
    let source_observed_at = row_source_observed_at.or(source_observed_at);
    Ok((row, source_observed_at))
}
