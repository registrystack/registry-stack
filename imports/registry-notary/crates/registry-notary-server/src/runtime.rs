// SPDX-License-Identifier: Apache-2.0
//! Registry Notary evaluation runtime.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Per-batch fetch memoization (Stage 2)
// ---------------------------------------------------------------------------

/// One cached upstream result: the raw JSON record and the timestamp at which
/// the upstream call was observed. The timestamp propagates to `iat` so that
/// subjects sharing a memoized read produce credentials with identical iat.
#[derive(Clone)]
struct MemoEntry {
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
enum MemoSlot {
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

type FetchMemo = Arc<MemoState>;

/// Result of loading a single source binding: the row value plus, when the
/// value came from the batch memo, the original observation timestamp so the
/// caller can pin `iat` to the upstream read time.
type BindingFetchResult = Result<(Value, Option<OffsetDateTime>), EvidenceError>;

type ClaimVersionSelections = BTreeMap<String, Option<String>>;

pub(crate) fn claim_ids(claims: &[ClaimRef]) -> Vec<String> {
    claims.iter().map(|claim| claim.id.clone()).collect()
}

fn requested_claim_versions(claims: &[ClaimRef]) -> Result<ClaimVersionSelections, EvidenceError> {
    let mut versions = BTreeMap::new();
    for claim in claims {
        if claim.id.trim().is_empty()
            || claim
                .version
                .as_deref()
                .is_some_and(|version| version.trim().is_empty())
        {
            return Err(EvidenceError::InvalidRequest);
        }
        match versions.get(&claim.id) {
            Some(existing) => {
                if existing != &claim.version {
                    return Err(EvidenceError::InvalidRequest);
                }
            }
            None => {
                versions.insert(claim.id.clone(), claim.version.clone());
            }
        }
    }
    Ok(versions)
}

fn find_claim_for_selection<'a>(
    config: &'a EvidenceConfig,
    claim_id: &str,
    versions: &ClaimVersionSelections,
) -> Result<&'a ClaimDefinition, EvidenceError> {
    match versions.get(claim_id).and_then(Option::as_deref) {
        Some(version) => find_claim_version(config, claim_id, version),
        None => find_claim(config, claim_id),
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
/// - DCI-specific: query_type, registry_type, record_type, field_paths (sorted)
///
/// We serialize to a `serde_json::Value` with sorted keys, then SHA-256 the
/// bytes. This is collision-resistant enough for a single-request lifetime.
fn cache_key_for_binding(
    binding: &registry_notary_core::SourceBindingConfig,
    lookup_value: &Value,
    purpose: &str,
) -> String {
    use registry_notary_core::SourceConnectorKind;
    let connector = match binding.connector {
        SourceConnectorKind::RegistryDataApi => "rda",
        SourceConnectorKind::Dci => "dci",
        SourceConnectorKind::OpenFnSidecar => "openfn_sidecar",
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
    });
    // Serialize with sorted keys (serde_json sorts object keys by default) and
    // hash the bytes.
    let bytes = serde_json::to_vec(&key_obj).unwrap_or_default();
    sha256_hex(&bytes)
}

#[cfg(feature = "registry-notary-cel")]
use crosswalk_core::{
    ErrorSeverity, MappingRuntime, RuntimeOptions, SecurityLimits, StandaloneExpressionInput,
};
use registry_notary_core::{
    missing_context_error, AccessMode, BatchClaimResultView, BatchEvaluateRequest,
    BatchEvaluateResponse, BatchItemError, BatchItemResponse, BatchItemStatus, BatchStatus,
    BatchSummary, BoundedClaimId, BoundedCorrelationId, BulkMode, CelBindingsConfig,
    ClaimDefinition, ClaimProvenance, ClaimRef, ClaimResultView, CredentialProfileConfig,
    DisclosureDowngrade, DisclosureProfile, EvaluateRequest, EvidenceConfig, EvidenceEntity,
    EvidenceEntityRef, EvidenceError, EvidenceFormat, EvidencePrincipal, EvidenceRequestContext,
    MatchingMetadata, RegistryNotaryCelConfig, RenderRequest, RuleConfig, SelfAttestationConfig,
    SelfAttestationDenialCode, SourceBindingConfig, SourceCapability,
    StoredSelfAttestationMetadata, SubjectRequest, TargetRefView, FORMAT_CCCEV_JSONLD,
    FORMAT_CLAIM_RESULT_JSON, FORMAT_SD_JWT_VC, SD_JWT_VC_HOLDER_BINDING_METHOD,
    SD_JWT_VC_ISSUER_KEY_TYPE, SD_JWT_VC_JWT_TYP, SD_JWT_VC_SIGNING_ALG,
};
use registry_platform_audit::AuditKeyHasher;
#[cfg(feature = "registry-notary-cel")]
use serde_json::Map;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use ulid::Ulid;

#[cfg(feature = "registry-notary-cel")]
use crate::cel_worker::{cel_expression_uses_regex, CelWorker, CelWorkerError};
use crate::self_attestation_rate_limit::SelfAttestationRateLimitKeys;

#[cfg(feature = "registry-notary-cel")]
const MAX_CEL_CLAIM_BINDINGS: usize = 64;
#[cfg(feature = "registry-notary-cel")]
const MAX_CEL_VAR_BINDINGS: usize = 64;

pub trait SourceReader: Send + Sync {
    fn has_readiness_check(&self) -> bool {
        false
    }

    fn check_ready<'a>(&'a self) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move { true })
    }

    fn observed_sidecar_config_hashes<'a>(
        &'a self,
        _evidence: &'a EvidenceConfig,
        _claim_ids: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Vec<String>> + Send + 'a>> {
        Box::pin(async move { Vec::new() })
    }

    fn map_target<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        context: &'a EvidenceRequestContext,
    ) -> Pin<Box<dyn Future<Output = Result<SubjectRequest, EvidenceError>> + Send + 'a>> {
        Box::pin(async move {
            context
                .target_subject()
                .ok_or(EvidenceError::TargetAttributesInsufficient)
        })
    }

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

    fn read_one_for_context<'a>(
        &'a self,
        binding: &'a SourceBindingConfig,
        context: &'a EvidenceRequestContext,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async move {
            let subject = self.map_target(binding, context).await?;
            let mapped_subject = self.map_subject(binding, &subject).await?;
            self.read_one(binding, &mapped_subject, purpose).await
        })
    }

    fn read_one_with_capability<'a>(
        &'a self,
        capability: &'a SourceCapability,
        claim_id: &'a str,
        binding: &'a SourceBindingConfig,
        subject: &'a SubjectRequest,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async move {
            require_source_read_capability(capability, claim_id)?;
            self.read_one(binding, subject, purpose).await
        })
    }

    fn read_one_for_context_with_capability<'a>(
        &'a self,
        capability: &'a SourceCapability,
        claim_id: &'a str,
        binding: &'a SourceBindingConfig,
        context: &'a EvidenceRequestContext,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async move {
            require_source_read_capability(capability, claim_id)?;
            self.read_one_for_context(binding, context, purpose).await
        })
    }

    /// Read N bindings as a single batch.
    ///
    /// The default implementation runs `read_one` concurrently with a bounded
    /// `JoinSet`, preserving the input order. Implementations may override
    /// this to take advantage of bulk-capable upstreams (e.g. RDA `in:`
    /// filter, DCI batched search).
    ///
    /// Results are returned in the same order as the input bindings. A
    /// per-subject failure is surfaced as `Err(EvidenceError)` for that
    /// position only; sibling subjects in the same batch are not affected.
    #[allow(clippy::type_complexity)]
    fn read_many<'a>(
        &'a self,
        bindings: Vec<(SourceBindingConfig, SubjectRequest)>,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<Result<Value, EvidenceError>>> + Send + 'a>> {
        Box::pin(default_read_many(self, bindings, purpose))
    }

    #[allow(clippy::type_complexity)]
    fn read_many_context<'a>(
        &'a self,
        bindings: Vec<(SourceBindingConfig, EvidenceRequestContext)>,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<Result<Value, EvidenceError>>> + Send + 'a>> {
        Box::pin(default_read_many_context(self, bindings, purpose))
    }

    #[allow(clippy::type_complexity)]
    fn read_many_with_capability<'a>(
        &'a self,
        capability: &'a SourceCapability,
        bindings: Vec<(SourceBindingConfig, SubjectRequest)>,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<Result<Value, EvidenceError>>> + Send + 'a>> {
        Box::pin(async move {
            if let Err(err) = require_machine_source_capability(capability) {
                let error_code = match err {
                    EvidenceError::SelfAttestationDenied { reason } => reason,
                    _ => SelfAttestationDenialCode::OperationDenied,
                };
                return bindings
                    .into_iter()
                    .map(|_| Err(EvidenceError::SelfAttestationDenied { reason: error_code }))
                    .collect();
            }
            self.read_many(bindings, purpose).await
        })
    }

    #[allow(clippy::type_complexity)]
    fn read_many_context_with_capability<'a>(
        &'a self,
        capability: &'a SourceCapability,
        bindings: Vec<(SourceBindingConfig, EvidenceRequestContext)>,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<Result<Value, EvidenceError>>> + Send + 'a>> {
        Box::pin(async move {
            if let Err(err) = require_machine_source_capability(capability) {
                let error_code = match err {
                    EvidenceError::SelfAttestationDenied { reason } => reason,
                    _ => SelfAttestationDenialCode::OperationDenied,
                };
                return bindings
                    .into_iter()
                    .map(|_| Err(EvidenceError::SelfAttestationDenied { reason: error_code }))
                    .collect();
            }
            self.read_many_context(bindings, purpose).await
        })
    }

    fn required_scopes(
        &self,
        evidence: &EvidenceConfig,
        claim_id: &str,
    ) -> Result<Vec<String>, EvidenceError>;

    fn required_scopes_for_claim(
        &self,
        evidence: &EvidenceConfig,
        claim: &ClaimDefinition,
    ) -> Result<Vec<String>, EvidenceError> {
        self.required_scopes(evidence, &claim.id)
    }
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
async fn prefetch_bulk_bindings(
    evidence: Arc<EvidenceConfig>,
    source: Arc<dyn SourceReader>,
    source_capability: SourceCapability,
    contexts: &[EvidenceRequestContext],
    requested_claims: &[ClaimRef],
    claim_versions: &ClaimVersionSelections,
    purpose: &str,
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
    let mut groups: BTreeMap<GroupKey, Vec<(SourceBindingConfig, EvidenceRequestContext, String)>> =
        BTreeMap::new();
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
                if validate_matching_policy(binding, context, purpose).is_err() {
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
                let cache_key = cache_key_for_binding(binding, &lookup_value, purpose);
                let bucket = groups.entry(group_key.clone()).or_default();
                if bucket.iter().any(|(_, _, k)| k == &cache_key) {
                    continue;
                }
                bucket.push((binding.clone(), source_context, cache_key));
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
            .map(|(b, s, _)| (b.clone(), s.clone()))
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
            let (binding, _, cache_key) = entry;
            match result {
                Ok(value) => {
                    if validate_required_binding_fields(&binding, &value).is_err() {
                        continue;
                    }
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
async fn default_read_many<'a, R: SourceReader + ?Sized>(
    reader: &'a R,
    bindings: Vec<(SourceBindingConfig, SubjectRequest)>,
    purpose: &'a str,
) -> Vec<Result<Value, EvidenceError>> {
    use std::task::{Context, Poll};

    if bindings.is_empty() {
        return Vec::new();
    }

    // Each `read_one` future borrows from a `(binding, subject)` entry in
    // `owned`, so the futures cannot outlive `owned`. We allocate the
    // futures with a local (shorter-than-'a) lifetime and rely on
    // higher-rank reborrowing through `reader.read_one(...)`.
    let owned: Vec<(SourceBindingConfig, SubjectRequest)> = bindings;
    let len = owned.len();
    // Local lifetime trick: `slice` is &'b owned with 'b shorter than 'a.
    let slice: &[(SourceBindingConfig, SubjectRequest)] = owned.as_slice();
    #[allow(clippy::type_complexity)]
    let mut futures: Vec<
        Option<Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + '_>>>,
    > = Vec::with_capacity(len);
    for (binding, subject) in slice.iter() {
        futures.push(Some(reader.read_one(binding, subject, purpose)));
    }
    let mut results: Vec<Option<Result<Value, EvidenceError>>> = (0..len).map(|_| None).collect();

    std::future::poll_fn(|cx: &mut Context<'_>| {
        let mut all_done = true;
        for (idx, slot) in futures.iter_mut().enumerate() {
            if let Some(fut) = slot.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(value) => {
                        results[idx] = Some(value);
                        *slot = None;
                    }
                    Poll::Pending => {
                        all_done = false;
                    }
                }
            }
        }
        if all_done {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    // Drop futures before `owned` to satisfy borrow-checker drop order.
    drop(futures);
    drop(owned);
    results
        .into_iter()
        .map(|slot| slot.expect("every slot populated when poll_fn returns Ready"))
        .collect()
}

/// Default context-aware `read_many` implementation: drive
/// `read_one_for_context` futures concurrently and collect results in input
/// order. This mirrors `default_read_many` without converting the canonical
/// request context back to the old subject-only shape.
async fn default_read_many_context<'a, R: SourceReader + ?Sized>(
    reader: &'a R,
    bindings: Vec<(SourceBindingConfig, EvidenceRequestContext)>,
    purpose: &'a str,
) -> Vec<Result<Value, EvidenceError>> {
    use std::task::{Context, Poll};

    if bindings.is_empty() {
        return Vec::new();
    }

    let owned: Vec<(SourceBindingConfig, EvidenceRequestContext)> = bindings;
    let len = owned.len();
    let slice: &[(SourceBindingConfig, EvidenceRequestContext)] = owned.as_slice();
    #[allow(clippy::type_complexity)]
    let mut futures: Vec<
        Option<Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + '_>>>,
    > = Vec::with_capacity(len);
    for (binding, context) in slice.iter() {
        futures.push(Some(reader.read_one_for_context(binding, context, purpose)));
    }
    let mut results: Vec<Option<Result<Value, EvidenceError>>> = (0..len).map(|_| None).collect();

    std::future::poll_fn(|cx: &mut Context<'_>| {
        let mut all_done = true;
        for (idx, slot) in futures.iter_mut().enumerate() {
            if let Some(fut) = slot.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(value) => {
                        results[idx] = Some(value);
                        *slot = None;
                    }
                    Poll::Pending => {
                        all_done = false;
                    }
                }
            }
        }
        if all_done {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    drop(futures);
    drop(owned);
    results
        .into_iter()
        .map(|slot| slot.expect("every slot populated when poll_fn returns Ready"))
        .collect()
}

#[derive(Debug, Clone)]
struct ClaimResultInternal {
    evaluation_id: String,
    claim_id: String,
    claim_version: String,
    subject_type: String,
    target: EvidenceEntity,
    requester: Option<EvidenceEntity>,
    matching: Option<MatchingMetadata>,
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

#[derive(Debug, Default)]
pub struct EvidenceStore {
    evaluations: Mutex<HashMap<String, registry_notary_core::StoredEvaluation>>,
    idempotency: Mutex<HashMap<String, IdempotencyRecord>>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BatchEvaluateOptions<'a> {
    pub header_purpose: Option<&'a str>,
    pub idempotency_key: Option<&'a str>,
    /// Test-only observer: when set, the runtime uses this `MemoState` as the
    /// per-batch memo instead of constructing its own, letting tests read
    /// `hits()` / `misses()` after the call returns. Production callers leave
    /// this `None`.
    pub memo_observer: Option<&'a Arc<MemoState>>,
}

struct ClaimEvaluationContext {
    evidence: Arc<EvidenceConfig>,
    source: Arc<dyn SourceReader>,
    source_capability: SourceCapability,
    context: EvidenceRequestContext,
    purpose: String,
    correlation_id: Option<BoundedCorrelationId>,
    evaluation_id: String,
    now: OffsetDateTime,
    // Per-request cap on parallel source bindings. Acquired only inside
    // `load_sources`, never at the claim level: sibling claims fan out
    // without permits (pure CPU), and only the actual upstream-bound
    // bindings consume permits. Acquiring at both levels with one shared
    // semaphore would deadlock when `bindings <= concurrent claims`.
    binding_concurrency: Arc<Semaphore>,
    // Per-batch memoization table. Present only during `batch_evaluate`;
    // `None` for single-subject `evaluate` calls where there are no sibling
    // subjects to share results with.
    fetch_memo: Option<FetchMemo>,
    claim_versions: ClaimVersionSelections,
    #[cfg(feature = "registry-notary-cel")]
    cel_worker: Option<Arc<CelWorker>>,
    #[cfg(feature = "registry-notary-cel")]
    cel_config: Arc<RegistryNotaryCelConfig>,
}

#[cfg_attr(not(feature = "registry-notary-cel"), allow(dead_code))]
struct CelEvaluationContext<'a> {
    evidence: &'a EvidenceConfig,
    claim: &'a ClaimDefinition,
    expression: &'a str,
    bindings: &'a CelBindingsConfig,
    claims: &'a BTreeMap<String, ClaimResultInternal>,
    sources: &'a BTreeMap<String, Value>,
    subject: &'a SubjectRequest,
    purpose: &'a str,
    #[cfg(feature = "registry-notary-cel")]
    worker: Option<&'a CelWorker>,
    #[cfg(feature = "registry-notary-cel")]
    config: &'a RegistryNotaryCelConfig,
}

impl EvidenceStore {
    pub fn insert(&self, evaluation: registry_notary_core::StoredEvaluation) {
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

    pub fn get(&self, evaluation_id: &str) -> Option<registry_notary_core::StoredEvaluation> {
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
}

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
        json!({
            "formats": [FORMAT_SD_JWT_VC],
            "sd_jwt_vc": {
                "media_type": FORMAT_SD_JWT_VC,
                "jwt_typ": SD_JWT_VC_JWT_TYP,
                "signing_algs": [SD_JWT_VC_SIGNING_ALG],
                "issuer_key_types": [SD_JWT_VC_ISSUER_KEY_TYPE],
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
        let request_hash = hash_json(&request)?;
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
                purpose.clone(),
                evaluation_id.clone(),
                now,
                request.claims.clone(),
                claim_versions.clone(),
                binding_concurrency,
                source_capability,
                None, // single-subject evaluate: no cross-subject memo needed
                correlation_id,
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
        let claim_versions = requested_claim_versions(&request.claims)?;
        let request_claim_ids = claim_ids(&request.claims);
        let source_capability = source_capability_for_principal(
            &self.self_attestation_rate_keys,
            principal,
            &request_claim_ids,
        )?;
        let max_subjects = max_batch_subjects(&evidence, &request.claims, &claim_versions)?;
        if request.items.len() > max_subjects {
            return Err(EvidenceError::BatchTooLarge);
        }
        let request_hash = hash_json(&request)?;
        let scoped_key = options.idempotency_key.map(|key| {
            format!(
                "{}:/v1/batch-evaluations:{}",
                principal.principal_id,
                sha256_hex(key.as_bytes())
            )
        });
        if let Some(key) = scoped_key.as_deref() {
            if let Some(response) = store.idempotent_batch(key, &request_hash)? {
                return Ok(response);
            }
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
        // Per-batch memoization table shared across all concurrent subject
        // tasks. Scoped to this `batch_evaluate` call; dropped when the call
        // returns, so no state leaks between batches. Tests can pre-create the
        // table via `options.memo_observer` to read counters after the call.
        let fetch_memo: FetchMemo = options
            .memo_observer
            .map(Arc::clone)
            .unwrap_or_else(|| Arc::new(MemoState::new()));
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
            let memo_for_task = Arc::clone(&fetch_memo);
            let source_capability = source_capability.clone();
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
                purpose_override.to_string(),
                evaluation_id.clone(),
                now,
                request.claims.clone(),
                claim_versions.clone(),
                binding_concurrency,
                source_capability,
                Some(fetch_memo),
                None,
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
        purpose: String,
        evaluation_id: String,
        now: OffsetDateTime,
        requested: Vec<ClaimRef>,
        claim_versions: ClaimVersionSelections,
        binding_concurrency: Arc<Semaphore>,
        source_capability: SourceCapability,
        fetch_memo: Option<FetchMemo>,
        correlation_id: Option<BoundedCorrelationId>,
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
                    source_capability: source_capability.clone(),
                    context: context.clone(),
                    purpose: purpose.clone(),
                    correlation_id: correlation_id.clone(),
                    evaluation_id: evaluation_id.clone(),
                    now,
                    binding_concurrency: Arc::clone(&binding_concurrency),
                    fetch_memo: fetch_memo.as_ref().map(Arc::clone),
                    claim_versions: claim_versions.clone(),
                    #[cfg(feature = "registry-notary-cel")]
                    cel_worker: self.cel_worker.as_ref().map(Arc::clone),
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
                        crate::standalone::with_request_correlation_id(correlation_id, evaluation)
                            .await
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

fn stored_evaluation_client_id(
    principal: &EvidencePrincipal,
    self_attestation: Option<&StoredSelfAttestationMetadata>,
) -> String {
    self_attestation
        .map(|metadata| metadata.principal_hash.as_str().to_string())
        .unwrap_or_else(|| principal.principal_id.clone())
}

async fn evaluate_claim_task(
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
    let (sources, observed_at) = load_sources(
        Arc::clone(&ctx.source),
        Arc::clone(&claim_arc(&claim)),
        ctx.source_capability.clone(),
        ctx.context.clone(),
        ctx.purpose.clone(),
        Arc::clone(&ctx.binding_concurrency),
        ctx.fetch_memo.clone(),
    )
    .await?;
    // When a memoized entry was used, `observed_at` carries the timestamp of
    // the original upstream read. Use that as `iat` so sibling subjects that
    // share a read produce credentials with identical issued_at values.
    let issued_at = observed_at.unwrap_or(ctx.now);
    let value = match &claim.rule {
        RuleConfig::Extract { source, field } => {
            let record = sources
                .get(source)
                .ok_or(EvidenceError::SourceUnavailable)?;
            crate::standalone::get_json_path(record, field)
                .cloned()
                .ok_or(EvidenceError::SourceNotFound)?
        }
        RuleConfig::Exists { source } => Value::Bool(sources.contains_key(source)),
        RuleConfig::Cel {
            expression,
            bindings,
        } => {
            let snapshot = prior.lock().expect("prior mutex is not poisoned").clone();
            let target_subject = ctx
                .context
                .target_subject()
                .ok_or(EvidenceError::TargetAttributesInsufficient)?;
            let value = evaluate_cel_expression(&CelEvaluationContext {
                evidence: &ctx.evidence,
                claim: &claim,
                expression,
                bindings,
                claims: &snapshot,
                sources: &sources,
                subject: &target_subject,
                purpose: ctx.purpose.as_str(),
                #[cfg(feature = "registry-notary-cel")]
                worker: ctx.cel_worker.as_deref(),
                #[cfg(feature = "registry-notary-cel")]
                config: &ctx.cel_config,
            })
            .await?;
            validate_claim_value_type(&value, &claim.value.value_type)?;
            value
        }
        RuleConfig::Plugin { .. } => return Err(EvidenceError::OperationUnsupported),
    };
    // The source_count for this claim is the number of direct sources it
    // read, plus the accumulated source_count from any dependency claims
    // that were evaluated to satisfy depends_on. This ensures predicate
    // and CEL claims that have no source_bindings of their own still
    // report the registry reads performed by their dependencies.
    let dep_source_count: usize = {
        let snapshot = prior.lock().expect("prior mutex is not poisoned");
        claim
            .depends_on
            .iter()
            .filter_map(|dep_id| snapshot.get(dep_id))
            .map(|dep| dep.provenance.source_count)
            .sum()
    };
    Ok(ClaimResultInternal {
        evaluation_id: ctx.evaluation_id.clone(),
        claim_id: claim.id.clone(),
        claim_version: claim.version.clone(),
        subject_type: claim.subject_type.clone(),
        target: ctx.context.target.clone(),
        requester: ctx.context.requester.clone(),
        matching: claim_matching_metadata(&claim),
        value,
        issued_at,
        expires_at: None,
        provenance: ClaimProvenance {
            source_count: sources.len() + dep_source_count,
            source_versions: BTreeMap::new(),
            computed_by: ctx.evidence.service_id.clone(),
        },
    })
}

fn claim_arc(claim: &ClaimDefinition) -> Arc<ClaimDefinition> {
    Arc::new(claim.clone())
}

/// Topological levels of the DAG closure over `requested`. Each level is the
/// set of claims whose dependencies all appear in earlier levels. Claims at
/// the same level are independent and safe to evaluate concurrently.
///
/// Cycle and unknown-dep validation already happened at config load; we still
/// guard with bounded iterations so a malformed config cannot infinite-loop.
fn build_claim_levels(
    evidence: &EvidenceConfig,
    requested: &[ClaimRef],
    claim_versions: &ClaimVersionSelections,
) -> Result<Vec<Vec<String>>, EvidenceError> {
    // Closure: starting from `requested`, accumulate every transitive dep.
    let mut closure: BTreeSet<String> = BTreeSet::new();
    let mut frontier: Vec<String> = claim_ids(requested);
    while let Some(claim_id) = frontier.pop() {
        if !closure.insert(claim_id.clone()) {
            continue;
        }
        let claim = find_claim_for_selection(evidence, &claim_id, claim_versions)?;
        for dep in &claim.depends_on {
            if !closure.contains(dep) {
                frontier.push(dep.clone());
            }
        }
    }
    // Kahn-style level construction: a claim is ready when all its deps are
    // already in earlier levels.
    let mut placed: BTreeSet<String> = BTreeSet::new();
    let mut levels: Vec<Vec<String>> = Vec::new();
    let total = closure.len();
    while placed.len() < total {
        let mut next_level: Vec<String> = Vec::new();
        for claim_id in &closure {
            if placed.contains(claim_id) {
                continue;
            }
            let claim = find_claim_for_selection(evidence, claim_id, claim_versions)?;
            if claim.depends_on.iter().all(|dep| placed.contains(dep)) {
                next_level.push(claim_id.clone());
            }
        }
        if next_level.is_empty() {
            // Should never happen: cycle detection runs at config load.
            return Err(EvidenceError::RuleEvaluationFailed);
        }
        for claim_id in &next_level {
            placed.insert(claim_id.clone());
        }
        levels.push(next_level);
    }
    Ok(levels)
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

pub fn find_claim_version<'a>(
    config: &'a EvidenceConfig,
    claim_id: &str,
    version: &str,
) -> Result<&'a ClaimDefinition, EvidenceError> {
    let mut has_claim_id = false;
    for claim in &config.claims {
        if claim.id == claim_id {
            has_claim_id = true;
            if claim.version == version {
                return Ok(claim);
            }
        }
    }
    if has_claim_id {
        Err(EvidenceError::ClaimVersionNotFound)
    } else {
        Err(EvidenceError::ClaimNotFound)
    }
}

fn principal_can_see_claim<R: SourceReader + ?Sized>(
    evidence: &EvidenceConfig,
    source: &R,
    principal: &EvidencePrincipal,
    claim: &ClaimDefinition,
) -> bool {
    source
        .required_scopes_for_claim(evidence, claim)
        .is_ok_and(|scopes| scopes.iter().all(|scope| principal.has_scope(scope)))
}

fn require_claim_access<R: SourceReader + ?Sized>(
    evidence: &EvidenceConfig,
    source: &R,
    principal: &EvidencePrincipal,
    claim: &ClaimDefinition,
) -> Result<(), EvidenceError> {
    if principal.is_self_attestation() {
        return Ok(());
    }
    for scope in source.required_scopes_for_claim(evidence, claim)? {
        if !principal.has_scope(&scope) {
            return Err(EvidenceError::ScopeDenied { required: scope });
        }
    }
    Ok(())
}

fn source_capability_for_principal(
    self_attestation_rate_keys: &SelfAttestationRateLimitKeys,
    principal: &EvidencePrincipal,
    requested_claims: &[String],
) -> Result<SourceCapability, EvidenceError> {
    match principal.access_mode() {
        AccessMode::MachineClient => Ok(SourceCapability::Machine {
            scopes: principal.scopes.iter().cloned().collect(),
        }),
        AccessMode::SelfAttestation => {
            if requested_claims.len() != 1 {
                return Err(EvidenceError::SelfAttestationDenied {
                    reason: SelfAttestationDenialCode::ClaimDenied,
                });
            }
            let claim_id = BoundedClaimId::new(requested_claims[0].clone())
                .map_err(|_| EvidenceError::InvalidRequest)?;
            let claims =
                principal
                    .verified_claims
                    .as_ref()
                    .ok_or(EvidenceError::SelfAttestationDenied {
                        reason: SelfAttestationDenialCode::SubjectClaimMissing,
                    })?;
            let subject_binding_value = claims.subject_binding_value.as_ref().ok_or(
                EvidenceError::SelfAttestationDenied {
                    reason: SelfAttestationDenialCode::SubjectClaimMissing,
                },
            )?;
            let subject_binding_hash = self_attestation_rate_keys
                .subject_binding(subject_binding_value.as_str())
                .map_err(|error| error.evidence_error())?;
            Ok(SourceCapability::SelfAttestation {
                claim_id,
                subject_binding_hash,
            })
        }
        AccessMode::Unknown => Err(EvidenceError::SelfAttestationInvalidToken),
    }
}

fn ensure_source_capability_matches_principal(
    principal: &EvidencePrincipal,
    capability: &SourceCapability,
) -> Result<(), EvidenceError> {
    match (principal.access_mode(), capability.access_mode()) {
        (AccessMode::MachineClient, AccessMode::MachineClient)
        | (AccessMode::SelfAttestation, AccessMode::SelfAttestation) => Ok(()),
        (AccessMode::SelfAttestation, AccessMode::MachineClient) => {
            Err(EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::OperationDenied,
            })
        }
        _ => Err(EvidenceError::SelfAttestationInvalidToken),
    }
}

fn require_source_read_capability(
    capability: &SourceCapability,
    claim_id: &str,
) -> Result<(), EvidenceError> {
    match capability {
        SourceCapability::Machine { .. } => Ok(()),
        SourceCapability::SelfAttestation {
            claim_id: allowed, ..
        } if allowed.as_str() == claim_id => Ok(()),
        SourceCapability::SelfAttestation { .. } => Err(EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::ClaimDenied,
        }),
    }
}

fn require_machine_source_capability(capability: &SourceCapability) -> Result<(), EvidenceError> {
    match capability {
        SourceCapability::Machine { .. } => Ok(()),
        SourceCapability::SelfAttestation { .. } => Err(EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::OperationDenied,
        }),
    }
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
    let mut summary = json!({
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
    });
    if let Some(cccev) = &claim.cccev {
        if let Some(evidence_type) = &cccev.evidence_type {
            summary["evidence_type"] = json!(evidence_type);
        }
        if let Some(evidence_type_iri) = &cccev.evidence_type_iri {
            summary["evidence_type_iri"] = json!(evidence_type_iri);
        }
    }
    summary
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

fn resolve_batch_default_purpose(
    header: Option<&str>,
    body: Option<&str>,
) -> Result<Option<String>, EvidenceError> {
    match (header, body) {
        (Some(header), Some(body)) if header != body => Err(EvidenceError::InvalidRequest),
        (Some(header), _) if !header.trim().is_empty() => Ok(Some(header.to_string())),
        (_, Some(body)) if !body.trim().is_empty() => Ok(Some(body.to_string())),
        (Some(_), _) | (_, Some(_)) => Err(EvidenceError::InvalidRequest),
        _ => Ok(None),
    }
}

fn resolve_batch_subject_purposes(
    subjects: &[registry_notary_core::BatchEvaluateItemRequest],
    batch_default: Option<&str>,
) -> Result<Vec<String>, EvidenceError> {
    subjects
        .iter()
        .map(|subject| match subject.purpose.as_deref() {
            Some(purpose)
                if batch_default.is_some_and(|batch_default| batch_default != purpose) =>
            {
                Err(EvidenceError::InvalidRequest)
            }
            Some(purpose) if !purpose.trim().is_empty() => Ok(purpose.to_string()),
            Some(_) => Err(EvidenceError::InvalidRequest),
            None => batch_default
                .map(str::to_string)
                .ok_or(EvidenceError::PurposeRequired),
        })
        .collect()
}

fn validate_batch_inputs_and_collect_purposes<'a>(
    subjects: &'a [registry_notary_core::BatchEvaluateItemRequest],
    subject_purposes: &'a [String],
) -> Result<BTreeSet<&'a str>, EvidenceError> {
    let mut unique_purposes = BTreeSet::new();
    for (item, purpose) in subjects.iter().zip(subject_purposes) {
        if !item.target.has_matching_input() {
            return Err(EvidenceError::TargetAttributesInsufficient);
        }
        unique_purposes.insert(purpose.as_str());
    }
    Ok(unique_purposes)
}

fn require_purpose_allowed(
    config: &EvidenceConfig,
    claims: &[ClaimRef],
    claim_versions: &ClaimVersionSelections,
    purpose: &str,
) -> Result<(), EvidenceError> {
    if !config.allowed_purposes.is_empty()
        && !config
            .allowed_purposes
            .iter()
            .any(|allowed| allowed == purpose)
    {
        return Err(EvidenceError::PurposeNotAllowed);
    }
    for claim_ref in claims {
        let claim = find_claim_for_selection(config, claim_ref, claim_versions)?;
        if claim
            .purpose
            .as_deref()
            .is_some_and(|allowed| allowed != purpose)
        {
            return Err(EvidenceError::PurposeNotAllowed);
        }
    }
    Ok(())
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
    claims: &[ClaimRef],
    claim_versions: &ClaimVersionSelections,
    requested: &Option<String>,
) -> Result<DisclosureProfile, EvidenceError> {
    let raw = requested
        .as_deref()
        .or_else(|| {
            claims
                .first()
                .and_then(|claim| find_claim_for_selection(config, claim, claim_versions).ok())
                .map(|claim| claim.disclosure.default.as_str())
        })
        .unwrap_or("redacted");
    DisclosureProfile::parse(raw).ok_or(EvidenceError::InvalidRequest)
}

fn max_batch_subjects(
    config: &EvidenceConfig,
    claims: &[ClaimRef],
    claim_versions: &ClaimVersionSelections,
) -> Result<usize, EvidenceError> {
    let mut max = config.inline_batch_limit;
    for claim_id in claims {
        let claim = find_claim_for_selection(config, claim_id, claim_versions)?;
        if !claim.operations.batch_evaluate.enabled {
            return Err(EvidenceError::OperationUnsupported);
        }
        max = max.min(claim.operations.batch_evaluate.max_subjects);
    }
    Ok(max)
}

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
async fn load_sources(
    source: Arc<dyn SourceReader>,
    claim: Arc<ClaimDefinition>,
    source_capability: SourceCapability,
    context: EvidenceRequestContext,
    purpose: String,
    binding_concurrency: Arc<Semaphore>,
    fetch_memo: Option<FetchMemo>,
) -> Result<(BTreeMap<String, Value>, Option<OffsetDateTime>), EvidenceError> {
    if claim.source_bindings.is_empty() {
        return Ok((BTreeMap::new(), None));
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
        let source_capability = source_capability.clone();
        let context = context.clone();
        let purpose = purpose.clone();
        let binding_concurrency = Arc::clone(&binding_concurrency);
        let fetch_memo = fetch_memo.clone();
        tasks.spawn(async move {
            let result = load_one_binding(
                source,
                &source_capability,
                claim_id.as_str(),
                &binding,
                &context,
                &purpose,
                binding_concurrency,
                fetch_memo.as_ref(),
            )
            .await;
            (id, result)
        });
    }

    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    let mut oldest_memo_ts: Option<OffsetDateTime> = None;
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
        let (value, memo_ts) = result?;
        if let Some(ts) = memo_ts {
            oldest_memo_ts = Some(match oldest_memo_ts {
                None => ts,
                Some(prev) => prev.min(ts),
            });
        }
        out.insert(id, value);
    }
    Ok((out, oldest_memo_ts))
}

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
async fn load_one_binding(
    source: Arc<dyn SourceReader>,
    source_capability: &SourceCapability,
    claim_id: &str,
    binding: &registry_notary_core::SourceBindingConfig,
    context: &EvidenceRequestContext,
    purpose: &str,
    binding_concurrency: Arc<Semaphore>,
    fetch_memo: Option<&FetchMemo>,
) -> Result<(Value, Option<OffsetDateTime>), EvidenceError> {
    if let Err(error) = validate_matching_policy(binding, context, purpose) {
        return Err(collapse_matching_error(binding, error));
    }
    // Compute the lookup value to build the cache key. If this fails (e.g.
    // unsupported lookup op) we skip the memo entirely and fall through to a
    // direct fetch; the connector will surface the same error there.
    let lookup_value_for_key = binding_cache_value_for_context(binding, context).ok();

    if let (Some(memo), Some(ref lv)) = (fetch_memo, &lookup_value_for_key) {
        let key = cache_key_for_binding(binding, lv, purpose);

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
                memo.record_hit();
                tracing::info!(
                    target: "registry_notary_server::memo",
                    "memo_hit",
                );
                return Ok((value, Some(ts)));
            }
            Action::Owner(sem) => {
                let result = fetch_and_signal(
                    source,
                    source_capability,
                    claim_id,
                    binding,
                    context,
                    purpose,
                    binding_concurrency,
                    memo,
                    key,
                    sem,
                )
                .await;
                return result.map_err(|error| collapse_matching_error(binding, error));
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
                    memo.record_hit();
                    tracing::info!(
                        target: "registry_notary_server::memo",
                        "memo_hit",
                    );
                    return Ok((value, Some(ts)));
                }
                // Owner failed; fall through to an unconditional fresh fetch.
            }
        }
    }

    // No memo (single-subject evaluate) or lookup derivation failed or the
    // previous owner failed: fetch directly without memoizing.
    fetch_binding_direct(
        source,
        source_capability,
        claim_id,
        binding,
        context,
        purpose,
        binding_concurrency,
    )
    .await
    .map_err(|error| collapse_matching_error(binding, error))
}

/// Signal-all permit count used when waking memo waiters. Matches tokio's
/// documented cap so a single `add_permits` releases every parked acquirer.
const MEMO_SIGNAL_PERMITS: usize = tokio::sync::Semaphore::MAX_PERMITS;

/// Drop guard for the `Pending` memo slot owned by `fetch_and_signal`.
///
/// On drop (return-by-error OR panic during the upstream fetch), removes the
/// Pending slot from the memo and signals all waiters so they wake up and
/// fall through to a fresh fetch instead of blocking forever on `acquire`.
///
/// The Owner's success path calls `disarm()` before installing the `Ready`
/// entry so this guard becomes a no-op for the happy path.
struct PendingGuard<'a> {
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
async fn fetch_and_signal(
    source: Arc<dyn SourceReader>,
    source_capability: &SourceCapability,
    claim_id: &str,
    binding: &registry_notary_core::SourceBindingConfig,
    context: &EvidenceRequestContext,
    purpose: &str,
    binding_concurrency: Arc<Semaphore>,
    memo: &FetchMemo,
    key: String,
    pending_sem: Arc<tokio::sync::Semaphore>,
) -> Result<(Value, Option<OffsetDateTime>), EvidenceError> {
    let mut guard = PendingGuard::new(memo, key.clone(), Arc::clone(&pending_sem));

    let (value, _fresh_ts) = fetch_binding_direct(
        Arc::clone(&source),
        source_capability,
        claim_id,
        binding,
        context,
        purpose,
        binding_concurrency,
    )
    .await?;
    let observed_at = OffsetDateTime::now_utc();

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
/// Returns `(value, None)` since the observation time is managed by the caller.
async fn fetch_binding_direct(
    source: Arc<dyn SourceReader>,
    source_capability: &SourceCapability,
    claim_id: &str,
    binding: &registry_notary_core::SourceBindingConfig,
    context: &EvidenceRequestContext,
    purpose: &str,
    binding_concurrency: Arc<Semaphore>,
) -> Result<(Value, Option<OffsetDateTime>), EvidenceError> {
    require_source_read_capability(source_capability, claim_id)?;
    let _permit = match binding_concurrency.acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => return Err(EvidenceError::RuleEvaluationFailed),
    };
    let source_context = minimized_context_for_binding(binding, context);
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
    Ok((row, None))
}

fn validate_required_binding_fields(
    binding: &registry_notary_core::SourceBindingConfig,
    row: &Value,
) -> Result<(), EvidenceError> {
    for field in binding.fields.values().filter(|field| field.required) {
        match crate::standalone::get_json_path(row, &field.field) {
            Some(value) if !value.is_null() => {}
            _ => return Err(EvidenceError::SourceNotFound),
        }
    }
    Ok(())
}

/// Derive the lookup value for a binding from the request context.
fn binding_lookup_value_for_context(
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

fn binding_cache_value_for_context(
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

fn validate_matching_policy(
    binding: &registry_notary_core::SourceBindingConfig,
    context: &EvidenceRequestContext,
    purpose: &str,
) -> Result<(), EvidenceError> {
    let matching = &binding.matching;
    if context.on_behalf_of.is_some()
        || context.target.profile.is_some()
        || context
            .requester
            .as_ref()
            .is_some_and(|requester| requester.profile.is_some())
    {
        return Err(EvidenceError::ProfileUnsupported);
    }
    if !matching.allowed_purposes.is_empty()
        && !matching
            .allowed_purposes
            .iter()
            .any(|allowed| allowed == purpose)
    {
        return Err(EvidenceError::PurposeNotAllowed);
    }
    if let Some(target_type) = matching.target_type.as_deref() {
        if context.target.entity_type != target_type {
            return Err(EvidenceError::TargetMatchingPolicyRejected);
        }
    }
    if let Some(requester_type) = matching.requester_type.as_deref() {
        if context
            .requester
            .as_ref()
            .map(|requester| requester.entity_type.as_str())
            != Some(requester_type)
        {
            return Err(EvidenceError::RequesterMatchingPolicyRejected);
        }
    }
    if matching.require_requester_reauthentication {
        return Err(EvidenceError::RequesterReauthenticationRequired);
    }
    if !matching.allowed_relationships.is_empty() {
        let relationship_type = context
            .relationship
            .as_ref()
            .map(|relationship| relationship.relationship_type.as_str());
        if relationship_type.is_none() {
            return Err(EvidenceError::RelationshipNotEstablished);
        }
        if relationship_type.is_none_or(|relationship_type| {
            !matching
                .allowed_relationships
                .iter()
                .any(|allowed| allowed == relationship_type)
        }) {
            return Err(EvidenceError::RelationshipPolicyRejected);
        }
    }
    if !matching.sufficient_target_inputs.is_empty()
        && !matching.sufficient_target_inputs.iter().any(|group| {
            group
                .iter()
                .all(|path| context.lookup_value(path.as_str()).is_some())
        })
    {
        let missing = matching
            .sufficient_target_inputs
            .iter()
            .flat_map(|group| group.iter())
            .find(|path| context.lookup_value(path.as_str()).is_none())
            .map(String::as_str)
            .unwrap_or("target.attributes");
        return Err(missing_context_error(missing));
    }
    if !matching.allowed_target_inputs.is_empty() {
        for path in present_entity_paths("target", &context.target) {
            if !path_allowed(path.as_str(), &matching.allowed_target_inputs) {
                return Err(EvidenceError::TargetMatchingPolicyRejected);
            }
        }
    }
    if !matching.allowed_requester_inputs.is_empty() {
        if let Some(requester) = &context.requester {
            for path in present_entity_paths("requester", requester) {
                if !path_allowed(path.as_str(), &matching.allowed_requester_inputs) {
                    return Err(EvidenceError::RequesterMatchingPolicyRejected);
                }
            }
        }
    }
    Ok(())
}

fn minimized_context_for_binding(
    binding: &registry_notary_core::SourceBindingConfig,
    context: &EvidenceRequestContext,
) -> EvidenceRequestContext {
    let mut paths = BTreeSet::new();
    paths.insert(binding.lookup.input.clone());
    for query_field in &binding.query_fields {
        paths.insert(query_field.input.clone());
    }
    for group in &binding.matching.sufficient_target_inputs {
        for path in group {
            paths.insert(path.clone());
        }
    }
    for path in present_entity_paths("target", &context.target) {
        if binding.matching.allowed_target_inputs.is_empty()
            || path_allowed(path.as_str(), &binding.matching.allowed_target_inputs)
        {
            paths.insert(path);
        }
    }
    if let Some(requester) = &context.requester {
        for path in present_entity_paths("requester", requester) {
            if binding.matching.allowed_requester_inputs.is_empty()
                || path_allowed(path.as_str(), &binding.matching.allowed_requester_inputs)
            {
                paths.insert(path);
            }
        }
    }
    if paths.is_empty()
        && binding.matching.allowed_target_inputs.is_empty()
        && binding.matching.allowed_requester_inputs.is_empty()
        && binding.matching.sufficient_target_inputs.is_empty()
    {
        return context.clone();
    }

    EvidenceRequestContext {
        requester: context
            .requester
            .as_ref()
            .and_then(|requester| minimized_entity("requester", requester, &paths)),
        target: minimized_entity("target", &context.target, &paths)
            .unwrap_or_else(|| EvidenceEntity::new(context.target.entity_type.clone())),
        relationship: context.relationship.as_ref().map(|relationship| {
            let mut minimized = registry_notary_core::EvidenceRelationship {
                relationship_type: relationship.relationship_type.clone(),
                attributes: BTreeMap::new(),
            };
            for path in &paths {
                if let Some(key) = path.strip_prefix("relationship.attributes.") {
                    if let Some(value) = relationship.attributes.get(key) {
                        minimized.attributes.insert(key.to_string(), value.clone());
                    }
                }
            }
            minimized
        }),
        on_behalf_of: None,
    }
}

fn minimized_entity(
    prefix: &str,
    entity: &EvidenceEntity,
    paths: &BTreeSet<String>,
) -> Option<EvidenceEntity> {
    let mut minimized = EvidenceEntity::new(entity.entity_type.clone());
    let id_path = format!("{prefix}.id");
    if paths.contains(&id_path) {
        minimized.id = entity.id.clone();
    }
    for identifier in &entity.identifiers {
        let path = format!("{prefix}.identifiers.{}", identifier.scheme);
        if paths.contains(&path) {
            minimized.identifiers.push(identifier.clone());
        }
    }
    let attribute_prefix = format!("{prefix}.attributes.");
    for path in paths {
        if let Some(key) = path.strip_prefix(attribute_prefix.as_str()) {
            if key == "*" {
                minimized.attributes.extend(entity.attributes.clone());
            } else if let Some(value) = entity.attributes.get(key) {
                minimized.attributes.insert(key.to_string(), value.clone());
            }
        }
    }
    if minimized.id.is_none() && minimized.identifiers.is_empty() && minimized.attributes.is_empty()
    {
        None
    } else {
        Some(minimized)
    }
}

fn collapse_matching_error(
    binding: &registry_notary_core::SourceBindingConfig,
    error: EvidenceError,
) -> EvidenceError {
    if !binding.matching.collapse_matching_errors {
        return error;
    }
    match error {
        matching_error @ (EvidenceError::SourceNotFound
        | EvidenceError::SourceAmbiguous
        | EvidenceError::TargetIdentifierMissing
        | EvidenceError::TargetAttributesInsufficient
        | EvidenceError::TargetMatchingPolicyRejected
        | EvidenceError::TargetNotInValidState
        | EvidenceError::TargetMatchLowConfidence
        | EvidenceError::RequesterNotFound
        | EvidenceError::RequesterMatchAmbiguous
        | EvidenceError::RequesterIdentifierMissing
        | EvidenceError::RequesterAttributesInsufficient
        | EvidenceError::RequesterMatchingPolicyRejected
        | EvidenceError::RequesterReauthenticationRequired
        | EvidenceError::RelationshipNotEstablished
        | EvidenceError::RelationshipMatchAmbiguous
        | EvidenceError::RelationshipAttributesInsufficient
        | EvidenceError::RelationshipPolicyRejected) => {
            EvidenceError::MatchingEvidenceNotAvailable {
                audit_code: matching_error.audit_code(),
            }
        }
        other => other,
    }
}

fn present_entity_paths(prefix: &str, entity: &EvidenceEntity) -> Vec<String> {
    let mut paths = Vec::new();
    if entity.id.is_some() {
        paths.push(format!("{prefix}.id"));
    }
    for identifier in &entity.identifiers {
        paths.push(format!("{prefix}.identifiers.{}", identifier.scheme));
    }
    for key in entity.attributes.keys() {
        paths.push(format!("{prefix}.attributes.{key}"));
    }
    paths
}

fn path_allowed(path: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|candidate| {
        candidate == path
            || candidate.strip_suffix(".*").is_some_and(|prefix| {
                path.strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('.'))
            })
    })
}

fn claim_matching_metadata(claim: &ClaimDefinition) -> Option<MatchingMetadata> {
    claim.source_bindings.values().find_map(|binding| {
        let matching = &binding.matching;
        let policy_id = matching.policy_id.as_ref()?;
        Some(MatchingMetadata {
            policy_id: policy_id.clone(),
            method: matching
                .method
                .clone()
                .unwrap_or_else(|| "configured_lookup".to_string()),
            confidence: matching
                .confidence
                .clone()
                .unwrap_or_else(|| "high".to_string()),
            score: None,
        })
    })
}

async fn evaluate_cel_expression(ctx: &CelEvaluationContext<'_>) -> Result<Value, EvidenceError> {
    #[cfg(feature = "registry-notary-cel")]
    let config = ctx.config;
    #[cfg(not(feature = "registry-notary-cel"))]
    let config = &RegistryNotaryCelConfig::default();
    validate_cel_policy(ctx.expression, ctx.bindings, ctx.claim, config)?;
    #[cfg(feature = "registry-notary-cel")]
    {
        evaluate_with_cel(ctx).await
    }
    #[cfg(not(feature = "registry-notary-cel"))]
    {
        let _ = ctx;
        Err(EvidenceError::OperationUnsupported)
    }
}

#[cfg(feature = "registry-notary-cel")]
pub(crate) fn validate_cel_claims_for_startup(
    evidence: &EvidenceConfig,
    config: &RegistryNotaryCelConfig,
) -> Result<(), EvidenceError> {
    let mut runtime = MappingRuntime::new(RuntimeOptions::default());
    runtime.limits = cel_security_limits(config);
    for claim in &evidence.claims {
        let RuleConfig::Cel {
            expression,
            bindings,
        } = &claim.rule
        else {
            continue;
        };
        validate_cel_policy(expression, bindings, claim, config)?;
        validate_cel_expression_roots(expression)?;
        if !config.allow_regex && cel_expression_uses_regex(expression) {
            return Err(EvidenceError::InvalidRequest);
        }
        let input = StandaloneExpressionInput::new(
            cel_preflight_root_bindings(evidence, claim, bindings)
                .into_iter()
                .collect(),
        );
        let preview = runtime.preview_cel_expression_with_input(expression, input);
        if preview
            .issues
            .iter()
            .any(|issue| issue.severity == ErrorSeverity::Error)
        {
            return Err(EvidenceError::InvalidRequest);
        }
        if let Some(value) = preview.value.as_ref() {
            validate_claim_value_type(value, &claim.value.value_type)?;
        }
    }
    Ok(())
}

fn validate_cel_policy(
    expression: &str,
    bindings: &CelBindingsConfig,
    claim: &ClaimDefinition,
    _config: &RegistryNotaryCelConfig,
) -> Result<(), EvidenceError> {
    if expression.trim().is_empty() {
        return Err(EvidenceError::InvalidRequest);
    }
    #[cfg(feature = "registry-notary-cel")]
    {
        cel_security_limits(_config)
            .check_expr(expression)
            .map_err(|_| EvidenceError::InvalidRequest)?;
        if bindings.claims.len() > MAX_CEL_CLAIM_BINDINGS
            || bindings.vars.len() > MAX_CEL_VAR_BINDINGS
        {
            return Err(EvidenceError::InvalidRequest);
        }
        for (alias, binding) in &bindings.claims {
            if !is_cel_identifier(alias) || !claim.depends_on.contains(&binding.claim) {
                return Err(EvidenceError::InvalidRequest);
            }
        }
        for alias in bindings.vars.keys() {
            if !is_cel_identifier(alias) {
                return Err(EvidenceError::InvalidRequest);
            }
        }
    }
    #[cfg(not(feature = "registry-notary-cel"))]
    {
        let _ = (expression, bindings, claim);
    }
    Ok(())
}

fn validate_claim_value_type(value: &Value, value_type: &str) -> Result<(), EvidenceError> {
    let valid = match value_type.trim() {
        "" | "unknown" => true,
        "boolean" | "bool" => value.is_boolean(),
        "number" | "float" | "double" => value.is_number(),
        "integer" | "int" => value.as_i64().is_some() || value.as_u64().is_some(),
        "string" | "date" | "datetime" | "date-time" | "uri" => value.is_string(),
        "array" | "list" => value.is_array(),
        "object" => value.is_object(),
        "null" => value.is_null(),
        _ => return Err(EvidenceError::InvalidRequest),
    };
    if valid {
        Ok(())
    } else {
        Err(EvidenceError::RuleEvaluationFailed)
    }
}

#[cfg(feature = "registry-notary-cel")]
async fn evaluate_with_cel(ctx: &CelEvaluationContext<'_>) -> Result<Value, EvidenceError> {
    let root_bindings = cel_root_bindings(ctx)?;
    let value = if let Some(worker) = ctx.worker {
        worker
            .evaluate(
                ctx.expression,
                Value::Object(root_bindings.into_iter().collect()),
            )
            .await
            .map_err(cel_worker_error)?
    } else {
        #[cfg(test)]
        {
            evaluate_cel_in_process_for_unit_tests(ctx.expression, root_bindings)?
        }
        #[cfg(not(test))]
        {
            return Err(EvidenceError::OperationUnsupported);
        }
    };
    validate_cel_result_limits(&value, ctx.config)?;
    Ok(value)
}

#[cfg(feature = "registry-notary-cel")]
#[cfg(test)]
fn evaluate_cel_in_process_for_unit_tests(
    expression: &str,
    root_bindings: BTreeMap<String, Value>,
) -> Result<Value, EvidenceError> {
    MappingRuntime::new(RuntimeOptions::default())
        .evaluate_cel_expression_with_input(
            expression,
            StandaloneExpressionInput::new(root_bindings.into_iter().collect()),
        )
        .map_err(|error| match error {
            crosswalk_core::StandaloneEvalError::Compile(_)
            | crosswalk_core::StandaloneEvalError::InvalidBindingName { .. } => {
                EvidenceError::InvalidRequest
            }
            crosswalk_core::StandaloneEvalError::Evaluate { .. } => {
                EvidenceError::RuleEvaluationFailed
            }
        })
}

#[cfg(feature = "registry-notary-cel")]
fn cel_preflight_root_bindings(
    evidence: &EvidenceConfig,
    claim: &ClaimDefinition,
    bindings: &CelBindingsConfig,
) -> BTreeMap<String, Value> {
    let mut sources = Map::new();
    for (alias, binding) in &claim.source_bindings {
        let mut source = Map::new();
        for (field_alias, field) in &binding.fields {
            source.insert(
                field_alias.clone(),
                cel_dummy_value_for_type(field.field_type.as_deref().unwrap_or("string")),
            );
        }
        sources.insert(alias.clone(), Value::Object(source));
    }

    let mut claims = Map::new();
    for (alias, binding) in &bindings.claims {
        let value_type = evidence
            .claims
            .iter()
            .find(|candidate| candidate.id == binding.claim)
            .map(|candidate| candidate.value.value_type.as_str())
            .unwrap_or("boolean");
        let value = cel_dummy_value_for_type(value_type);
        claims.insert(
            alias.clone(),
            json!({
                "value": value,
                "satisfied": value.as_bool().unwrap_or(true),
                "claim_id": binding.claim,
                "version": "preflight",
            }),
        );
    }

    BTreeMap::from([
        ("source".to_string(), Value::Object(sources)),
        ("claims".to_string(), Value::Object(claims)),
        (
            "ctx".to_string(),
            json!({
                "purpose": "preflight",
                "subject": { "id": "preflight-subject" },
            }),
        ),
        (
            "vars".to_string(),
            Value::Object(bindings.vars.clone().into_iter().collect()),
        ),
        ("meta".to_string(), cel_meta(evidence, claim)),
    ])
}

#[cfg(feature = "registry-notary-cel")]
fn cel_dummy_value_for_type(value_type: &str) -> Value {
    match value_type {
        "boolean" | "bool" => Value::Bool(true),
        "number" | "float" | "double" => json!(1.0),
        "integer" | "int" => json!(1),
        "date" => json!("2000-01-01"),
        "datetime" | "date-time" => json!("2000-01-01T00:00:00Z"),
        "array" | "list" => json!([]),
        "object" => json!({}),
        "null" => Value::Null,
        _ => json!("preflight"),
    }
}

#[cfg(feature = "registry-notary-cel")]
fn validate_cel_expression_roots(expression: &str) -> Result<(), EvidenceError> {
    for root in cel_root_references(expression) {
        if !matches!(
            root.as_str(),
            "source" | "claims" | "ctx" | "vars" | "meta" | "date" | "person"
        ) {
            return Err(EvidenceError::InvalidRequest);
        }
    }
    Ok(())
}

#[cfg(feature = "registry-notary-cel")]
fn cel_root_references(expression: &str) -> BTreeSet<String> {
    let bytes = expression.as_bytes();
    let mut roots = BTreeSet::new();
    let mut index = 0;
    let mut quote: Option<u8> = None;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(active_quote) = quote {
            if byte == b'\\' {
                index = index.saturating_add(2);
                continue;
            }
            if byte == active_quote {
                quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`') {
            quote = Some(byte);
            index += 1;
            continue;
        }
        if !is_cel_identifier_start_byte(byte) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && is_cel_identifier_continue_byte(bytes[index]) {
            index += 1;
        }
        let mut lookahead = index;
        while lookahead < bytes.len() && bytes[lookahead].is_ascii_whitespace() {
            lookahead += 1;
        }
        let previous = start
            .checked_sub(1)
            .and_then(|previous| bytes.get(previous))
            .copied();
        let is_member = previous == Some(b'.');
        let is_root = matches!(bytes.get(lookahead), Some(b'.' | b'[')) && !is_member;
        if is_root {
            roots.insert(expression[start..index].to_string());
        }
    }
    roots
}

#[cfg(feature = "registry-notary-cel")]
fn is_cel_identifier_start_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

#[cfg(feature = "registry-notary-cel")]
fn is_cel_identifier_continue_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

#[cfg(feature = "registry-notary-cel")]
fn cel_root_bindings(
    ctx: &CelEvaluationContext<'_>,
) -> Result<BTreeMap<String, Value>, EvidenceError> {
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
    validate_cel_binding_limits(
        &Value::Object(root_bindings.clone().into_iter().collect()),
        ctx.config,
    )?;
    Ok(root_bindings)
}

#[cfg(feature = "registry-notary-cel")]
fn cel_worker_error(error: CelWorkerError) -> EvidenceError {
    match error {
        CelWorkerError::Compile | CelWorkerError::Protocol => EvidenceError::InvalidRequest,
        CelWorkerError::Evaluate | CelWorkerError::Harness(_) => {
            EvidenceError::RuleEvaluationFailed
        }
    }
}

#[cfg(feature = "registry-notary-cel")]
fn validate_cel_binding_limits(
    value: &Value,
    config: &RegistryNotaryCelConfig,
) -> Result<(), EvidenceError> {
    if serialized_json_len(value)? > config.max_binding_json_bytes {
        return Err(EvidenceError::RuleEvaluationFailed);
    }
    let mut stack = vec![(value, 0_usize)];
    while let Some((value, depth)) = stack.pop() {
        if depth > config.max_object_depth {
            return Err(EvidenceError::RuleEvaluationFailed);
        }
        match value {
            Value::String(value) if value.len() > config.max_string_bytes => {
                return Err(EvidenceError::RuleEvaluationFailed);
            }
            Value::Array(values) => {
                if values.len() > config.max_list_items {
                    return Err(EvidenceError::RuleEvaluationFailed);
                }
                for value in values {
                    stack.push((value, depth + 1));
                }
            }
            Value::Object(values) => {
                if values.len() > config.max_object_keys {
                    return Err(EvidenceError::RuleEvaluationFailed);
                }
                for value in values.values() {
                    stack.push((value, depth + 1));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(feature = "registry-notary-cel")]
fn validate_cel_result_limits(
    value: &Value,
    config: &RegistryNotaryCelConfig,
) -> Result<(), EvidenceError> {
    validate_cel_binding_limits(value, config)?;
    if serialized_json_len(value)? > config.max_result_json_bytes {
        return Err(EvidenceError::RuleEvaluationFailed);
    }
    Ok(())
}

#[cfg(feature = "registry-notary-cel")]
fn serialized_json_len(value: &Value) -> Result<usize, EvidenceError> {
    struct CountingWriter {
        count: usize,
    }

    impl std::io::Write for CountingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.count = self
                .count
                .checked_add(buf.len())
                .ok_or_else(|| std::io::Error::other("serialized JSON length overflow"))?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut writer = CountingWriter { count: 0 };
    serde_json::to_writer(&mut writer, value).map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    Ok(writer.count)
}

#[cfg(feature = "registry-notary-cel")]
fn cel_security_limits(config: &RegistryNotaryCelConfig) -> SecurityLimits {
    SecurityLimits {
        max_expression_bytes: config.max_expression_bytes,
        max_output_json_bytes: config.max_result_json_bytes,
        max_list_len: config.max_list_items,
        max_string_bytes: config.max_string_bytes,
        ..SecurityLimits::default()
    }
}

#[cfg(feature = "registry-notary-cel")]
fn is_cel_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

#[cfg(feature = "registry-notary-cel")]
fn cel_meta(evidence: &EvidenceConfig, claim: &ClaimDefinition) -> Value {
    let mut sources = Map::new();
    for (alias, binding) in &claim.source_bindings {
        let connector = match binding.connector {
            registry_notary_core::config::SourceConnectorKind::RegistryDataApi => {
                "registry_data_api"
            }
            registry_notary_core::config::SourceConnectorKind::Dci => "dci",
            registry_notary_core::config::SourceConnectorKind::OpenFnSidecar => "openfn_sidecar",
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
    self_attestation_rate_keys: &SelfAttestationRateLimitKeys,
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
        requester_ref: result
            .requester
            .as_ref()
            .map(|requester| entity_ref_view(self_attestation_rate_keys, "requester", requester))
            .transpose()?,
        target_ref: target_ref_view(self_attestation_rate_keys, &result.target)?,
        matching: result.matching.clone(),
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
        "urn:registry-notary:evidence-render:{}:{}",
        result.evaluation_id, result.claim_id
    );
    let value_id = format!("{evidence_id}#value");
    let period_id = format!("{evidence_id}#validity");

    // Look up the requirement IRI from the claim's oots config when present.
    // Fall back to a urn: reference so the output is always valid JSON-LD.
    let requirement_iri = config
        .claims
        .iter()
        .find(|claim| claim.id == result.claim_id && claim.version == result.claim_version)
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
    evaluation: &registry_notary_core::StoredEvaluation,
    requested_profile: Option<&'a str>,
) -> Result<(&'a str, &'a CredentialProfileConfig), EvidenceError> {
    let claim_refs = evaluation.selected_claim_refs();
    let claim_versions = requested_claim_versions(&claim_refs)?;
    if let Some(profile_id) = requested_profile {
        let profile = config
            .credential_profiles
            .get(profile_id)
            .ok_or(EvidenceError::CredentialIssuerNotConfigured)?;
        // The caller-supplied profile must also be on the allow-list of at
        // least one claim in the evaluation. Without this check a client
        // could mint a credential against a profile the claim never opted
        // in to, bypassing per-claim policy.
        let allowed = claim_refs
            .iter()
            .filter_map(|claim_ref| {
                find_claim_for_selection(config, claim_ref, &claim_versions).ok()
            })
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
    for claim_ref in &claim_refs {
        let claim = find_claim_for_selection(config, claim_ref, &claim_versions)?;
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

fn target_ref_view(
    self_attestation_rate_keys: &SelfAttestationRateLimitKeys,
    target: &EvidenceEntity,
) -> Result<TargetRefView, EvidenceError> {
    let entity_ref = entity_ref_view(self_attestation_rate_keys, "target", target)?;
    Ok(TargetRefView {
        entity_type: entity_ref.entity_type,
        handle: entity_ref.handle,
        identifier_schemes: entity_ref.identifier_schemes,
        profile: entity_ref.profile,
    })
}

fn entity_ref_view(
    self_attestation_rate_keys: &SelfAttestationRateLimitKeys,
    role: &str,
    entity: &EvidenceEntity,
) -> Result<EvidenceEntityRef, EvidenceError> {
    let stable_input = serde_json::json!({
        "role": role,
        "type": entity.entity_type,
        "id": entity.id,
        "identifiers": entity.identifiers,
        "attributes": entity.attributes,
    })
    .to_string();
    let hash = self_attestation_rate_keys
        .subject_ref(role, &stable_input)
        .map_err(|error| error.evidence_error())?;
    let mut identifier_schemes: Vec<String> = entity
        .identifiers
        .iter()
        .map(|identifier| identifier.scheme.clone())
        .collect();
    identifier_schemes.sort();
    identifier_schemes.dedup();
    Ok(EvidenceEntityRef {
        entity_type: entity.entity_type.clone(),
        handle: format!("rnref:v1:{}", hash.as_str()),
        identifier_schemes,
        profile: None,
    })
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
        title: crate::api::evidence_title(error).to_string(),
        retryable: matches!(error, EvidenceError::SourceUnavailable),
        audit_code: Some(error.audit_code().to_string()),
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
    crate::api::hex_encode(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_notary_core::Hashed;

    #[derive(Debug, Default)]
    struct CountingSource {
        read_count: AtomicU64,
        purposes: Mutex<Vec<String>>,
    }

    impl SourceReader for CountingSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                self.read_count.fetch_add(1, Ordering::SeqCst);
                self.purposes
                    .lock()
                    .expect("purposes mutex is not poisoned")
                    .push(purpose.to_string());
                Ok(json!({
                    "id": subject.id.clone(),
                    "value": true,
                }))
            })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            _claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(Vec::new())
        }
    }

    #[derive(Debug, Default)]
    struct VersionScopedSource {
        read_count: AtomicU64,
    }

    impl SourceReader for VersionScopedSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                self.read_count.fetch_add(1, Ordering::SeqCst);
                Ok(json!({
                    "id": subject.id.clone(),
                    "value": true,
                }))
            })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(vec![format!("{claim_id}:1.0")])
        }

        fn required_scopes_for_claim(
            &self,
            _evidence: &EvidenceConfig,
            claim: &ClaimDefinition,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(vec![format!("{}:{}", claim.id, claim.version)])
        }
    }

    #[derive(Debug, Default)]
    struct BulkInvalidThenDirectSource {
        bulk_count: AtomicU64,
        direct_count: AtomicU64,
    }

    impl SourceReader for BulkInvalidThenDirectSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                self.direct_count.fetch_add(1, Ordering::SeqCst);
                Ok(json!({
                    "id": subject.id.clone(),
                    "value": true,
                }))
            })
        }

        fn read_one_for_context<'a>(
            &'a self,
            binding: &'a SourceBindingConfig,
            context: &'a EvidenceRequestContext,
            purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                let subject = context
                    .target_subject()
                    .ok_or(EvidenceError::TargetAttributesInsufficient)?;
                self.read_one(binding, &subject, purpose).await
            })
        }

        fn read_many_context<'a>(
            &'a self,
            bindings: Vec<(SourceBindingConfig, EvidenceRequestContext)>,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Vec<Result<Value, EvidenceError>>> + Send + 'a>> {
            Box::pin(async move {
                self.bulk_count.fetch_add(1, Ordering::SeqCst);
                bindings
                    .into_iter()
                    .map(|(_, context)| {
                        let id = context
                            .target_subject()
                            .map(|subject| subject.id)
                            .unwrap_or_default();
                        Ok(json!({ "id": id }))
                    })
                    .collect()
            })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            _claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(Vec::new())
        }
    }

    fn test_source_binding() -> SourceBindingConfig {
        SourceBindingConfig {
            connector: registry_notary_core::SourceConnectorKind::RegistryDataApi,
            connection: None,
            required_scope: None,
            dataset: "people".to_string(),
            entity: "person".to_string(),
            lookup: registry_notary_core::SourceLookupConfig {
                input: "target.id".to_string(),
                field: "id".to_string(),
                op: "eq".to_string(),
                cardinality: "one".to_string(),
            },
            query_fields: Vec::new(),
            fields: BTreeMap::from([(
                "value".to_string(),
                registry_notary_core::SourceFieldConfig {
                    field: "value".to_string(),
                    field_type: Some("boolean".to_string()),
                    unit: None,
                    required: true,
                    semantic_term: None,
                },
            )]),
            matching: registry_notary_core::SourceMatchingConfig::default(),
        }
    }

    fn test_claim(id: &str, depends_on: Vec<&str>, has_source: bool) -> ClaimDefinition {
        let source_bindings = if has_source {
            BTreeMap::from([("src".to_string(), test_source_binding())])
        } else {
            BTreeMap::new()
        };
        ClaimDefinition {
            id: id.to_string(),
            title: id.to_string(),
            version: "1.0".to_string(),
            subject_type: "person".to_string(),
            value: registry_notary_core::ClaimValueConfig {
                value_type: "boolean".to_string(),
                unit: None,
            },
            inputs: Vec::new(),
            depends_on: depends_on.into_iter().map(str::to_string).collect(),
            purpose: None,
            source_bindings,
            rule: if has_source {
                RuleConfig::Extract {
                    source: "src".to_string(),
                    field: "value".to_string(),
                }
            } else {
                RuleConfig::Exists {
                    source: "src".to_string(),
                }
            },
            operations: registry_notary_core::ClaimOperationsConfig::default(),
            disclosure: registry_notary_core::DisclosureConfig {
                default: "value".to_string(),
                allowed: vec!["value".to_string(), "redacted".to_string()],
                downgrade: "redacted".to_string(),
            },
            formats: vec![FORMAT_CLAIM_RESULT_JSON.to_string()],
            credential_profiles: Vec::new(),
            cccev: None,
            oots: None,
        }
    }

    fn test_evidence(claims: Vec<ClaimDefinition>) -> Arc<EvidenceConfig> {
        Arc::new(EvidenceConfig {
            enabled: true,
            service_id: "runtime.test".to_string(),
            claims,
            ..EvidenceConfig::default()
        })
    }

    fn bulk_source_connection() -> registry_notary_core::SourceConnectionConfig {
        registry_notary_core::SourceConnectionConfig {
            base_url: "https://source.test".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: String::new(),
            source_auth: None,
            expected_sidecar: None,
            dci: registry_notary_core::DciSourceConnectionConfig::default(),
            max_in_flight: 1,
            retry_on_5xx: false,
            bulk_mode: BulkMode::OpenFnSidecarBatch,
            bulk_mode_lookup_unique: true,
            bulk_timeout_max_ms: 1_000,
        }
    }

    fn test_request(claim: &str) -> EvaluateRequest {
        EvaluateRequest {
            requester: None,
            target: Some(registry_notary_core::EvidenceEntity::from_subject_request(
                "Person",
                SubjectRequest {
                    id: "person-1".to_string(),
                    id_type: None,
                },
            )),
            relationship: None,
            on_behalf_of: None,
            claims: vec![ClaimRef::from(claim)],
            disclosure: Some("value".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("test".to_string()),
        }
    }

    fn machine_principal() -> EvidencePrincipal {
        EvidencePrincipal {
            principal_id: "machine".to_string(),
            scopes: Vec::new(),
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
        }
    }

    fn self_attestation_principal() -> EvidencePrincipal {
        EvidencePrincipal {
            principal_id: "citizen".to_string(),
            scopes: vec!["self_attestation".to_string()],
            access_mode: AccessMode::SelfAttestation,
            verified_claims: None,
        }
    }

    fn self_attestation_capability(claim_id: &str) -> SourceCapability {
        SourceCapability::SelfAttestation {
            claim_id: BoundedClaimId::new(claim_id).expect("claim id is bounded"),
            subject_binding_hash: Hashed::from_hash("sha256:test"),
        }
    }

    #[test]
    fn claim_summary_advertises_cccev_evidence_type_metadata() {
        let mut claim = test_claim("civil-child-status", Vec::new(), false);
        claim.cccev = Some(registry_notary_core::CccevConfig {
            requirement_type: Some("InformationRequirement".to_string()),
            evidence_type: Some("civil_child_status_evidence".to_string()),
            evidence_type_iri: Some(
                "https://demo.example.gov/evidence-types/civil-child-status".to_string(),
            ),
        });

        let summary = claim_summary(&claim);

        assert_eq!(summary["evidence_type"], "civil_child_status_evidence");
        assert_eq!(
            summary["evidence_type_iri"],
            "https://demo.example.gov/evidence-types/civil-child-status"
        );
        assert_eq!(
            summary["cccev"]["evidence_type_iri"],
            "https://demo.example.gov/evidence-types/civil-child-status"
        );
    }

    #[test]
    fn self_attestation_source_capability_uses_keyed_subject_binding_hash() {
        const ENV: &str = "TEST_RUNTIME_AUDIT_HASH_SECRET";
        std::env::set_var(ENV, "0123456789abcdef0123456789abcdef");
        let keys = SelfAttestationRateLimitKeys::new(
            AuditKeyHasher::from_env(ENV).expect("test audit hasher loads"),
        );
        let mut principal = self_attestation_principal();
        principal.verified_claims = Some(
            serde_json::from_value(json!({
                "issuer": "https://id.example.gov",
                "audiences": ["registry-notary"],
                "subject_binding_claim": "national_id",
                "subject_binding_value": "12345678901"
            }))
            .expect("verified claims parse"),
        );

        let capability =
            source_capability_for_principal(&keys, &principal, &["selected".to_string()])
                .expect("source capability builds");
        let SourceCapability::SelfAttestation {
            subject_binding_hash,
            ..
        } = capability
        else {
            panic!("expected self-attestation capability");
        };

        assert!(subject_binding_hash.as_str().starts_with("hmac-sha256:"));
        assert!(!subject_binding_hash.as_str().contains("12345678901"));
    }

    #[test]
    fn service_document_advertises_api_key_and_bearer_auth() {
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "evidence.test".to_string(),
            ..EvidenceConfig::default()
        };

        let document = RegistryNotaryRuntime::service_document(&evidence);

        assert_eq!(document["auth"]["methods"], json!(["api_key", "bearer"]));
        assert_eq!(document["auth"]["api_key"]["header"], json!("X-Api-Key"));
        assert_eq!(document["auth"]["bearer"]["header"], json!("Authorization"));
        assert_eq!(document["auth"]["bearer"]["scheme"], json!("bearer"));
        assert_eq!(
            document["auth"]["bearer"]["format"],
            json!("Bearer <token>")
        );
        assert_eq!(document["auth"]["audience"], json!("evidence.test"));
    }

    #[test]
    fn service_document_advertises_sd_jwt_vc_conformance_capabilities() {
        let mut credential_profiles = BTreeMap::new();
        credential_profiles.insert(
            "profile-a".to_string(),
            CredentialProfileConfig {
                format: FORMAT_SD_JWT_VC.to_string(),
                issuer: "did:web:issuer.test".to_string(),
                signing_key: "issuer-key".to_string(),
                vct: "https://issuer.test/credentials/profile-a".to_string(),
                validity_seconds: 600,
                holder_binding: registry_notary_core::HolderBindingConfig {
                    mode: "did".to_string(),
                    proof_of_possession: Some("required".to_string()),
                    allowed_did_methods: vec![SD_JWT_VC_HOLDER_BINDING_METHOD.to_string()],
                },
                allowed_claims: vec!["claim-a".to_string()],
                disclosure: registry_notary_core::CredentialDisclosureConfig {
                    allowed: vec!["predicate".to_string()],
                },
            },
        );
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "evidence.test".to_string(),
            credential_profiles,
            ..EvidenceConfig::default()
        };

        let document = RegistryNotaryRuntime::service_document(&evidence);
        let capabilities = &document["credential_capabilities"]["sd_jwt_vc"];

        assert_eq!(capabilities["media_type"], json!(FORMAT_SD_JWT_VC));
        assert_eq!(capabilities["jwt_typ"], json!(SD_JWT_VC_JWT_TYP));
        assert_eq!(capabilities["signing_algs"], json!([SD_JWT_VC_SIGNING_ALG]));
        assert_eq!(
            capabilities["issuer_key_types"],
            json!([SD_JWT_VC_ISSUER_KEY_TYPE])
        );
        assert_eq!(
            capabilities["holder_binding_methods"],
            json!([SD_JWT_VC_HOLDER_BINDING_METHOD])
        );
        assert_eq!(capabilities["status_methods"], json!([]));
        assert_eq!(capabilities["openid4vci"]["support"], "not_full_issuer");
        assert_eq!(capabilities["credential_profiles"][0]["id"], "profile-a");
        assert_eq!(
            capabilities["credential_profiles"][0]["format"],
            FORMAT_SD_JWT_VC
        );
        assert_eq!(
            document["credential_capabilities"]["unsupported_features"],
            json!([
                "application/vc+sd-jwt",
                "json_ld_vc_issuance",
                "data_integrity_proofs",
                "credential_status",
                "mso_mdoc",
                "openid4vci_full_issuer"
            ])
        );
    }

    #[test]
    fn service_document_preserves_output_when_self_attestation_disabled() {
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "evidence.test".to_string(),
            ..EvidenceConfig::default()
        };

        assert_eq!(
            RegistryNotaryRuntime::service_document_with_self_attestation(
                &evidence,
                &SelfAttestationConfig::default(),
                false,
            ),
            RegistryNotaryRuntime::service_document(&evidence),
        );
    }

    #[test]
    fn service_document_redacts_self_attestation_details_when_not_authorized() {
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "evidence.test".to_string(),
            ..EvidenceConfig::default()
        };
        let self_attestation: SelfAttestationConfig = serde_json::from_value(json!({
            "enabled": true,
            "subject_binding": {
                "token_claim": "https://id.example.gov/claims/national_id",
                "request_field": "SubjectId",
                "id_type": "national_id",
                "normalize": "exact"
            },
            "token_policy": {
                "max_auth_age_seconds": 900,
                "max_access_token_lifetime_seconds": 900,
                "max_evaluation_age_seconds": 600,
                "max_credential_validity_seconds": 300,
                "max_clock_leeway_seconds": 60
            },
            "allowed_operations": {
                "evaluate": true,
                "render": true,
                "issue_credential": false,
                "batch_evaluate": false
            },
            "allowed_claims": ["person-is-alive"],
            "allowed_formats": [FORMAT_CLAIM_RESULT_JSON],
            "allowed_disclosures": ["predicate"],
            "required_scopes": ["self_attestation"],
            "credential_profiles": ["civil_status_sd_jwt"],
            "rate_limits": {
                "mode": "in_process",
                "invalid_token_per_client_address_per_minute": 20,
                "per_principal_per_minute": 10,
                "subject_mismatch_per_principal_per_hour": 5,
                "per_holder_per_hour": 10,
                "credential_issuance_per_principal_per_hour": 5
            }
        }))
        .expect("self-attestation config parses");

        let document = RegistryNotaryRuntime::service_document_with_self_attestation(
            &evidence,
            &self_attestation,
            false,
        );

        assert_eq!(document["self_attestation"]["enabled"], json!(true));
        assert!(document["self_attestation"]["subject_id_type"].is_null());
        assert!(document["self_attestation"]["token_claim_name"].is_null());
        assert!(document["self_attestation"]["allowed_claim_ids"].is_null());
        assert!(document["self_attestation"]["credential_profile_ids"].is_null());
    }

    #[test]
    fn service_document_advertises_enabled_self_attestation_capabilities() {
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "evidence.test".to_string(),
            ..EvidenceConfig::default()
        };
        let self_attestation: SelfAttestationConfig = serde_json::from_value(json!({
            "enabled": true,
            "subject_binding": {
                "token_claim": "https://id.example.gov/claims/national_id",
                "request_field": "SubjectId",
                "id_type": "national_id",
                "normalize": "exact"
            },
            "token_policy": {
                "max_auth_age_seconds": 900,
                "max_access_token_lifetime_seconds": 900,
                "max_evaluation_age_seconds": 600,
                "max_credential_validity_seconds": 300,
                "max_clock_leeway_seconds": 60
            },
            "allowed_operations": {
                "evaluate": true,
                "render": true,
                "issue_credential": false,
                "batch_evaluate": false
            },
            "allowed_claims": ["person-is-alive"],
            "allowed_formats": [FORMAT_CLAIM_RESULT_JSON],
            "allowed_disclosures": ["predicate"],
            "required_scopes": ["self_attestation"],
            "credential_profiles": ["civil_status_sd_jwt"],
            "rate_limits": {
                "mode": "in_process",
                "invalid_token_per_client_address_per_minute": 20,
                "per_principal_per_minute": 10,
                "subject_mismatch_per_principal_per_hour": 5,
                "per_holder_per_hour": 10,
                "credential_issuance_per_principal_per_hour": 5
            }
        }))
        .expect("self-attestation config parses");

        let document = RegistryNotaryRuntime::service_document_with_self_attestation(
            &evidence,
            &self_attestation,
            true,
        );

        assert_eq!(document["self_attestation"]["enabled"], json!(true));
        assert_eq!(
            document["self_attestation"]["allowed_operations"],
            json!({
                "evaluate": true,
                "render": true,
                "issue_credential": false,
                "batch_evaluate": false
            })
        );
        assert_eq!(
            document["self_attestation"]["allowed_claim_ids"],
            json!(["person-is-alive"])
        );
        assert_eq!(
            document["self_attestation"]["allowed_formats"],
            json!([FORMAT_CLAIM_RESULT_JSON])
        );
        assert_eq!(
            document["self_attestation"]["allowed_disclosures"],
            json!(["predicate"])
        );
        assert_eq!(
            document["self_attestation"]["credential_profile_ids"],
            json!(["civil_status_sd_jwt"])
        );
        assert_eq!(
            document["self_attestation"]["subject_id_type"],
            json!("national_id")
        );
        assert_eq!(
            document["self_attestation"]["token_claim_name"],
            json!("https://id.example.gov/claims/national_id")
        );
        assert_eq!(
            document["self_attestation"]["required_scopes"],
            json!(["self_attestation"])
        );
        assert_eq!(
            document["self_attestation"]["scope_policy"],
            json!("required")
        );
        assert_eq!(
            document["self_attestation"]["max_evaluation_age_seconds"],
            json!(600)
        );
        assert_eq!(
            document["self_attestation"]["max_credential_validity_seconds"],
            json!(300)
        );
        assert_eq!(
            document["self_attestation"]["rate_limit_mode"],
            json!("in_process")
        );
        assert!(document["self_attestation"]["rate_limits"].is_null());
        assert!(document["self_attestation"]["allowed_wallet_origins"].is_null());
        assert!(document["self_attestation"]["citizen_clients"].is_null());
        assert!(document["self_attestation"]["token_policy"].is_null());
    }

    #[tokio::test]
    async fn evaluate_target_ref_serializes_as_opaque_handle() {
        let source = Arc::new(CountingSource::default());
        let evidence = test_evidence(vec![test_claim("selected", Vec::new(), true)]);
        let store = EvidenceStore::default();
        let mut request = test_request("selected");
        request.target = Some(registry_notary_core::EvidenceEntity::with_identifier(
            "Person",
            "national_id",
            "person-1",
        ));

        let results = RegistryNotaryRuntime::new()
            .evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                None,
            )
            .await
            .expect("evaluate succeeds");
        let target_ref =
            serde_json::to_value(&results[0].target_ref).expect("target_ref serializes");

        assert!(target_ref["handle"].as_str().is_some());
        assert!(target_ref["handle"]
            .as_str()
            .unwrap()
            .starts_with("rnref:v1:"));
        assert!(target_ref.get("id_type").is_none());
        assert!(!target_ref.to_string().contains("person-1"));
    }

    #[tokio::test]
    async fn batch_item_target_ref_serializes_as_opaque_handle() {
        let source = Arc::new(CountingSource::default());
        let mut claim = test_claim("selected", Vec::new(), true);
        claim.operations.batch_evaluate.enabled = true;
        claim.operations.batch_evaluate.max_subjects = 1;
        let mut evidence_config = (*test_evidence(vec![claim])).clone();
        evidence_config.inline_batch_limit = 1;
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let request = BatchEvaluateRequest {
            items: vec![registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-1".to_string(),
                    id_type: Some("national_id".to_string()),
                    purpose: None,
                },
            )],
            claims: vec![ClaimRef::from("selected")],
            disclosure: Some("value".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("test".to_string()),
        };

        let response = RegistryNotaryRuntime::new()
            .batch_evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                BatchEvaluateOptions::default(),
            )
            .await
            .expect("batch evaluate succeeds");
        let target_ref =
            serde_json::to_value(&response.items[0].target_ref).expect("target_ref serializes");

        assert!(target_ref["handle"].as_str().is_some());
        assert!(target_ref["handle"]
            .as_str()
            .unwrap()
            .starts_with("rnref:v1:"));
        assert!(target_ref.get("id_type").is_none());
        assert!(!target_ref.to_string().contains("person-1"));
    }

    #[tokio::test]
    async fn bulk_prefetch_does_not_cache_rows_missing_required_fields() {
        let source = Arc::new(BulkInvalidThenDirectSource::default());
        let mut claim = test_claim("selected", Vec::new(), true);
        claim.operations.batch_evaluate.enabled = true;
        claim.operations.batch_evaluate.max_subjects = 1;
        claim
            .source_bindings
            .get_mut("src")
            .expect("test claim has source binding")
            .connection = Some("bulk-source".to_string());
        let mut evidence_config = (*test_evidence(vec![claim])).clone();
        evidence_config.inline_batch_limit = 1;
        evidence_config.source_connections =
            BTreeMap::from([("bulk-source".to_string(), bulk_source_connection())]);
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let memo = Arc::new(MemoState::new());
        let request = BatchEvaluateRequest {
            items: vec![registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-1".to_string(),
                    id_type: None,
                    purpose: None,
                },
            )],
            claims: vec![ClaimRef::from("selected")],
            disclosure: Some("value".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("test".to_string()),
        };

        let response = RegistryNotaryRuntime::new()
            .batch_evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                BatchEvaluateOptions {
                    memo_observer: Some(&memo),
                    ..BatchEvaluateOptions::default()
                },
            )
            .await
            .expect("batch evaluate succeeds after direct retry");

        assert_eq!(response.summary.succeeded, 1);
        assert_eq!(response.summary.failed, 0);
        assert!(matches!(
            response.items[0].status,
            BatchItemStatus::Succeeded
        ));
        assert_eq!(response.items[0].claim_results[0].value, Some(json!(true)));
        assert_eq!(source.bulk_count.load(Ordering::SeqCst), 1);
        assert_eq!(source.direct_count.load(Ordering::SeqCst), 1);
        assert_eq!(memo.hits(), 0);
        assert_eq!(memo.misses(), 1);
    }

    #[tokio::test]
    async fn evaluate_uses_requested_claim_version() {
        let source = Arc::new(CountingSource::default());
        let older_claim = test_claim("selected", Vec::new(), false);
        let mut newer_claim = test_claim("selected", Vec::new(), true);
        newer_claim.version = "2.0".to_string();
        let evidence = test_evidence(vec![older_claim, newer_claim]);
        let store = EvidenceStore::default();
        let mut request = test_request("selected");
        request.claims = vec![ClaimRef::with_version("selected", "2.0")];

        let results = RegistryNotaryRuntime::new()
            .evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                None,
            )
            .await
            .expect("versioned evaluate succeeds");

        assert_eq!(results[0].claim_version, "2.0");
        assert_eq!(results[0].value, Some(json!(true)));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn evaluate_authorizes_required_scope_from_requested_claim_version() {
        let source = Arc::new(VersionScopedSource::default());
        let older_claim = test_claim("selected", Vec::new(), true);
        let mut newer_claim = test_claim("selected", Vec::new(), true);
        newer_claim.version = "2.0".to_string();
        let evidence = test_evidence(vec![older_claim, newer_claim]);
        let store = EvidenceStore::default();
        let mut request = test_request("selected");
        request.claims = vec![ClaimRef::with_version("selected", "2.0")];
        let principal = EvidencePrincipal {
            principal_id: "machine".to_string(),
            scopes: vec!["selected:1.0".to_string()],
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
        };

        let err = RegistryNotaryRuntime::new()
            .evaluate(
                Arc::clone(&evidence),
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &principal,
                request.clone(),
                None,
            )
            .await
            .expect_err("version 1 scope must not authorize version 2");

        assert!(matches!(
            err,
            EvidenceError::ScopeDenied { required } if required == "selected:2.0"
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);

        let principal = EvidencePrincipal {
            scopes: vec!["selected:2.0".to_string()],
            ..principal
        };
        let results = RegistryNotaryRuntime::new()
            .evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &principal,
                request,
                None,
            )
            .await
            .expect("version 2 scope authorizes version 2");

        assert_eq!(results[0].claim_version, "2.0");
        assert_eq!(source.read_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn render_cccev_uses_result_claim_version_for_requirement() {
        let mut older_claim = test_claim("selected", Vec::new(), true);
        older_claim.oots = Some(registry_notary_core::OotsConfig {
            enabled: true,
            requirement: Some("https://requirements.example/v1".to_string()),
            ..registry_notary_core::OotsConfig::default()
        });
        let mut newer_claim = test_claim("selected", Vec::new(), true);
        newer_claim.version = "2.0".to_string();
        newer_claim.oots = Some(registry_notary_core::OotsConfig {
            enabled: true,
            requirement: Some("https://requirements.example/v2".to_string()),
            ..registry_notary_core::OotsConfig::default()
        });
        let evidence = test_evidence(vec![older_claim, newer_claim]);
        let result = ClaimResultView {
            evaluation_id: "evaluation".to_string(),
            claim_id: "selected".to_string(),
            claim_version: "2.0".to_string(),
            subject_type: "person".to_string(),
            requester_ref: None,
            target_ref: TargetRefView {
                entity_type: "Person".to_string(),
                handle: "rnref:v1:target".to_string(),
                identifier_schemes: Vec::new(),
                profile: None,
            },
            matching: None,
            value: Some(json!(true)),
            satisfied: Some(true),
            disclosure: "value".to_string(),
            format: FORMAT_CCCEV_JSONLD.to_string(),
            issued_at: "2026-06-08T00:00:00Z".to_string(),
            expires_at: None,
            provenance: ClaimProvenance {
                source_count: 0,
                source_versions: BTreeMap::new(),
                computed_by: "runtime.test".to_string(),
            },
        };

        let rendered =
            render_results(&evidence, &[result], FORMAT_CCCEV_JSONLD).expect("CCCEV renders");

        assert_eq!(
            rendered["@graph"][0]["cccev:supportsRequirement"]["@id"],
            json!("https://requirements.example/v2")
        );
    }

    #[tokio::test]
    async fn evaluate_rejects_missing_claim_version() {
        let source = Arc::new(CountingSource::default());
        let evidence = test_evidence(vec![test_claim("selected", Vec::new(), true)]);
        let store = EvidenceStore::default();
        let mut request = test_request("selected");
        request.claims = vec![ClaimRef::with_version("selected", "2.0")];

        let err = RegistryNotaryRuntime::new()
            .evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                None,
            )
            .await
            .expect_err("unknown version is rejected");

        assert!(matches!(err, EvidenceError::ClaimVersionNotFound));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn requested_claim_versions_accepts_duplicate_same_version() {
        let versions = requested_claim_versions(&[
            ClaimRef::with_version("selected", "2.0"),
            ClaimRef::with_version("selected", "2.0"),
        ])
        .expect("duplicate matching version is accepted");

        assert_eq!(
            versions.get("selected").and_then(Option::as_deref),
            Some("2.0")
        );
    }

    #[test]
    fn requested_claim_versions_rejects_duplicate_conflicting_version() {
        let err = requested_claim_versions(&[
            ClaimRef::with_version("selected", "1.0"),
            ClaimRef::with_version("selected", "2.0"),
        ])
        .expect_err("conflicting versions are rejected");

        assert!(matches!(err, EvidenceError::InvalidRequest));
    }

    #[test]
    fn batch_input_validation_deduplicates_purposes() {
        let subjects = vec![
            registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-1".to_string(),
                    id_type: None,
                    purpose: None,
                },
            ),
            registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-2".to_string(),
                    id_type: None,
                    purpose: None,
                },
            ),
            registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-3".to_string(),
                    id_type: None,
                    purpose: None,
                },
            ),
        ];
        let purposes = vec![
            "benefits".to_string(),
            "benefits".to_string(),
            "appeals".to_string(),
        ];

        let unique = validate_batch_inputs_and_collect_purposes(&subjects, &purposes)
            .expect("batch inputs are valid");

        assert_eq!(unique, BTreeSet::from(["appeals", "benefits"]));
    }

    #[tokio::test]
    async fn batch_subject_purpose_conflict_rejects_batch_default() {
        let source = Arc::new(CountingSource::default());
        let mut claim = test_claim("selected", Vec::new(), true);
        claim.operations.batch_evaluate.enabled = true;
        claim.operations.batch_evaluate.max_subjects = 2;
        let mut evidence_config = (*test_evidence(vec![claim])).clone();
        evidence_config.inline_batch_limit = 2;
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let request = BatchEvaluateRequest {
            items: vec![
                registry_notary_core::BatchEvaluateItemRequest::from(
                    registry_notary_core::BatchSubjectRequest {
                        id: "person-1".to_string(),
                        id_type: None,
                        purpose: Some("program-a".to_string()),
                    },
                ),
                registry_notary_core::BatchEvaluateItemRequest::from(
                    registry_notary_core::BatchSubjectRequest {
                        id: "person-2".to_string(),
                        id_type: None,
                        purpose: None,
                    },
                ),
            ],
            claims: vec![ClaimRef::from("selected")],
            disclosure: Some("value".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("program-b".to_string()),
        };

        let error = RegistryNotaryRuntime::new()
            .batch_evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                BatchEvaluateOptions::default(),
            )
            .await
            .expect_err("batch item purpose must not conflict with batch default");

        assert_eq!(error.code(), "request.invalid");
        assert!(source
            .purposes
            .lock()
            .expect("purposes mutex is not poisoned")
            .is_empty());
    }

    #[tokio::test]
    async fn self_attestation_capability_rejects_dependency_source_read_before_connector() {
        let source = Arc::new(CountingSource::default());
        let evidence = test_evidence(vec![
            test_claim("selected", vec!["dependency"], false),
            test_claim("dependency", Vec::new(), true),
        ]);
        let store = EvidenceStore::default();

        let err = RegistryNotaryRuntime::new()
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &self_attestation_principal(),
                self_attestation_capability("selected"),
                test_request("selected"),
                None,
                None,
                None,
            )
            .await
            .expect_err("dependency source read is not selected claim");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::ClaimDenied
            }
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn self_attestation_capability_rejects_arbitrary_requested_claim() {
        let source = Arc::new(CountingSource::default());
        let evidence = test_evidence(vec![
            test_claim("selected", Vec::new(), false),
            test_claim("other", Vec::new(), false),
        ]);
        let store = EvidenceStore::default();

        let err = RegistryNotaryRuntime::new()
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &self_attestation_principal(),
                self_attestation_capability("selected"),
                test_request("other"),
                None,
                None,
                None,
            )
            .await
            .expect_err("self-attestation cannot switch claims after guard selection");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::ClaimDenied
            }
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn machine_capability_preserves_dependency_source_read() {
        let source = Arc::new(CountingSource::default());
        let evidence = test_evidence(vec![
            test_claim("selected", vec!["dependency"], false),
            test_claim("dependency", Vec::new(), true),
        ]);
        let store = EvidenceStore::default();

        let results = RegistryNotaryRuntime::new()
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                SourceCapability::Machine {
                    scopes: BTreeSet::new(),
                },
                test_request("selected"),
                None,
                None,
                None,
            )
            .await
            .expect("machine source reads keep existing behavior");

        assert_eq!(results.len(), 1);
        assert_eq!(source.read_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn self_attestation_batch_is_denied_before_source_reads() {
        let source = Arc::new(CountingSource::default());
        let evidence = test_evidence(vec![test_claim("selected", Vec::new(), true)]);
        let store = EvidenceStore::default();
        let request = BatchEvaluateRequest {
            items: vec![registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-1".to_string(),
                    id_type: None,
                    purpose: None,
                },
            )],
            claims: vec![ClaimRef::from("selected")],
            disclosure: Some("value".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("test".to_string()),
        };

        let err = RegistryNotaryRuntime::new()
            .batch_evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &self_attestation_principal(),
                request,
                BatchEvaluateOptions::default(),
            )
            .await
            .expect_err("self-attestation batch is not supported");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::BatchDenied
            }
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "registry-notary-cel")]
    #[test]
    fn cel_binding_limits_reject_large_strings_and_lists() {
        let config = RegistryNotaryCelConfig {
            max_string_bytes: 4,
            max_list_items: 2,
            ..RegistryNotaryCelConfig::default()
        };

        assert!(validate_cel_binding_limits(&json!({ "value": "abcd" }), &config).is_ok());
        assert!(matches!(
            validate_cel_binding_limits(&json!({ "value": "abcde" }), &config),
            Err(EvidenceError::RuleEvaluationFailed)
        ));
        assert!(matches!(
            validate_cel_binding_limits(&json!({ "items": [1, 2, 3] }), &config),
            Err(EvidenceError::RuleEvaluationFailed)
        ));
    }

    #[cfg(feature = "registry-notary-cel")]
    #[test]
    fn cel_policy_validation_rejects_invalid_alias_and_unlisted_dependency() {
        let claim = test_claim("cel-claim", vec!["dependency"], false);
        let invalid_alias = CelBindingsConfig {
            claims: BTreeMap::from([(
                "not-valid-alias".to_string(),
                registry_notary_core::ClaimBindingConfig {
                    claim: "dependency".to_string(),
                    binding_type: None,
                },
            )]),
            vars: BTreeMap::new(),
        };
        assert!(matches!(
            validate_cel_policy(
                "true",
                &invalid_alias,
                &claim,
                &RegistryNotaryCelConfig::default()
            ),
            Err(EvidenceError::InvalidRequest)
        ));

        let unlisted_dependency = CelBindingsConfig {
            claims: BTreeMap::from([(
                "dep".to_string(),
                registry_notary_core::ClaimBindingConfig {
                    claim: "other".to_string(),
                    binding_type: None,
                },
            )]),
            vars: BTreeMap::new(),
        };
        assert!(matches!(
            validate_cel_policy(
                "true",
                &unlisted_dependency,
                &claim,
                &RegistryNotaryCelConfig::default()
            ),
            Err(EvidenceError::InvalidRequest)
        ));
    }

    #[cfg(feature = "registry-notary-cel")]
    #[test]
    fn cel_startup_validation_accepts_date_source_field_dummy_values() {
        let mut source_binding = test_source_binding();
        source_binding.fields.insert(
            "birth_date".to_string(),
            registry_notary_core::SourceFieldConfig {
                field: "birth_date".to_string(),
                field_type: Some("date".to_string()),
                unit: None,
                required: true,
                semantic_term: None,
            },
        );

        let mut claim = test_claim("age-band", Vec::new(), false);
        claim.value.value_type = "string".to_string();
        claim.source_bindings = BTreeMap::from([("civil".to_string(), source_binding)]);
        claim.rule = RuleConfig::Cel {
            expression: "source.civil.birth_date == vars.as_of_date ? 'same' : 'different'"
                .to_string(),
            bindings: CelBindingsConfig {
                claims: BTreeMap::new(),
                vars: BTreeMap::from([("as_of_date".to_string(), json!("2000-01-01"))]),
            },
        };
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "runtime.test".to_string(),
            claims: vec![claim],
            ..EvidenceConfig::default()
        };

        validate_cel_claims_for_startup(&evidence, &RegistryNotaryCelConfig::default())
            .expect("date-typed CEL bindings should preflight with valid dummy dates");
    }

    #[cfg(feature = "registry-notary-cel")]
    #[test]
    fn cel_startup_validation_accepts_numeric_source_field_aliases() {
        let mut source_binding = test_source_binding();
        source_binding.fields.insert(
            "farm_area".to_string(),
            registry_notary_core::SourceFieldConfig {
                field: "farm_area".to_string(),
                field_type: Some("float".to_string()),
                unit: None,
                required: true,
                semantic_term: None,
            },
        );
        source_binding.fields.insert(
            "risk_score".to_string(),
            registry_notary_core::SourceFieldConfig {
                field: "risk_score".to_string(),
                field_type: Some("double".to_string()),
                unit: None,
                required: true,
                semantic_term: None,
            },
        );

        let mut claim = test_claim("small-farm-low-risk", Vec::new(), false);
        claim.source_bindings = BTreeMap::from([("farm".to_string(), source_binding)]);
        claim.rule = RuleConfig::Cel {
            expression: "source.farm.farm_area < 4.0 && source.farm.risk_score <= 1.0".to_string(),
            bindings: CelBindingsConfig {
                claims: BTreeMap::new(),
                vars: BTreeMap::new(),
            },
        };
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "runtime.test".to_string(),
            claims: vec![claim],
            ..EvidenceConfig::default()
        };

        validate_cel_claims_for_startup(&evidence, &RegistryNotaryCelConfig::default())
            .expect("numeric CEL source field aliases should preflight as numbers");
    }

    #[cfg(feature = "registry-notary-cel")]
    #[test]
    fn cel_startup_validation_rejects_unknown_roots_and_regex_usage() {
        assert!(validate_cel_expression_roots(
            "source.farmer.total_farmed_area < 4 && claims.prior.satisfied"
        )
        .is_ok());
        assert!(matches!(
            validate_cel_expression_roots("credential.level == 'gold'"),
            Err(EvidenceError::InvalidRequest)
        ));
        assert!(cel_expression_uses_regex(
            "source.person.name.matches('^A')"
        ));
        assert!(cel_expression_uses_regex(
            "text.regex_replace(source.person.name, '^A', 'B')"
        ));
        assert!(cel_expression_uses_regex(
            "text . regex_replace(source.person.name, '^A', 'B')"
        ));
        assert!(cel_expression_uses_regex(
            "text. regex_extract(source.person.name, '^(.+)$', 1)"
        ));
        assert!(cel_expression_uses_regex(
            "text_regex_extract(source.person.name, '^(.+)$', 1)"
        ));
        assert!(cel_expression_uses_regex(
            "validate.matches(source.person.name, '^A', 'bad')"
        ));
        assert!(!cel_expression_uses_regex(
            "'text.regex_replace(source.person.name, pattern)'"
        ));
    }

    #[test]
    fn claim_value_type_validation_matches_declared_json_shape() {
        assert!(validate_claim_value_type(&json!(true), "boolean").is_ok());
        assert!(validate_claim_value_type(&json!(1.5), "number").is_ok());
        assert!(validate_claim_value_type(&json!(1), "integer").is_ok());
        assert!(validate_claim_value_type(&json!("value"), "string").is_ok());
        assert!(validate_claim_value_type(&json!("2026-06-03"), "date").is_ok());
        assert!(validate_claim_value_type(&json!([1]), "array").is_ok());
        assert!(validate_claim_value_type(&json!({ "k": "v" }), "object").is_ok());
        assert!(validate_claim_value_type(&Value::Null, "null").is_ok());
        assert!(validate_claim_value_type(&json!("value"), "").is_ok());

        assert!(matches!(
            validate_claim_value_type(&json!("value"), "boolean"),
            Err(EvidenceError::RuleEvaluationFailed)
        ));
        assert!(matches!(
            validate_claim_value_type(&json!(1.5), "integer"),
            Err(EvidenceError::RuleEvaluationFailed)
        ));
        assert!(matches!(
            validate_claim_value_type(&json!(true), "unsupported"),
            Err(EvidenceError::InvalidRequest)
        ));
    }

    #[cfg(feature = "registry-notary-cel")]
    #[test]
    fn cel_binding_limits_reject_deep_json_without_recursive_walk() {
        let config = RegistryNotaryCelConfig::default();
        let mut value = json!(true);
        for _ in 0..=config.max_object_depth {
            value = json!({ "nested": value });
        }

        assert!(matches!(
            validate_cel_binding_limits(&value, &config),
            Err(EvidenceError::RuleEvaluationFailed)
        ));
    }

    #[cfg(feature = "registry-notary-cel")]
    #[test]
    fn cel_result_limits_reject_oversized_serialized_output() {
        let config = RegistryNotaryCelConfig {
            max_result_json_bytes: 4,
            ..RegistryNotaryCelConfig::default()
        };

        assert!(matches!(
            validate_cel_result_limits(&json!("12345"), &config),
            Err(EvidenceError::RuleEvaluationFailed)
        ));
    }

    #[cfg(feature = "registry-notary-cel")]
    #[test]
    fn cel_result_limits_reject_deep_worker_output_without_recursive_walk() {
        let config = RegistryNotaryCelConfig::default();
        let mut value = json!(true);
        for _ in 0..=config.max_object_depth {
            value = json!({ "nested": value });
        }

        assert!(matches!(
            validate_cel_result_limits(&value, &config),
            Err(EvidenceError::RuleEvaluationFailed)
        ));
    }

    #[test]
    fn credential_profile_for_rejects_profile_not_listed_in_claim() {
        // A caller-supplied credential_profile must be in the requested claim's
        // own credential_profiles allow-list. Otherwise a client could mint a
        // credential against a profile the claim never opted in to.
        let evidence: EvidenceConfig = serde_norway::from_str(
            r#"
enabled: true
service_id: test.notary
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
signing_keys:
  issuer-key:
    provider: local_jwk_env
    private_jwk_env: ISSUER_KEY
    alg: EdDSA
    kid: did:web:issuer.example#key-1
    status: active
  issuer-key-b:
    provider: local_jwk_env
    private_jwk_env: ISSUER_KEY_B
    alg: EdDSA
    kid: did:web:issuer.example#key-2
    status: active
credential_profiles:
  profile_a:
    format: application/dc+sd-jwt
    issuer: https://issuer.example
    signing_key: issuer-key
    vct: https://vct.example/a
    allowed_claims:
      - claim-a
  profile_b:
    format: application/dc+sd-jwt
    issuer: https://issuer.example
    signing_key: issuer-key-b
    vct: https://vct.example/b
    allowed_claims:
      - claim-a
"#,
        )
        .expect("evidence config is valid YAML");

        let evaluation = registry_notary_core::StoredEvaluation {
            client_id: "client".to_string(),
            purpose: "test".to_string(),
            claim_ids: vec!["claim-a".to_string()],
            claim_refs: Vec::new(),
            disclosure: "redacted".to_string(),
            format: FORMAT_SD_JWT_VC.to_string(),
            results: Vec::new(),
            created_at: "1970-01-01T00:00:00Z".to_string(),
            expires_at: "1970-01-01T00:00:00Z".to_string(),
            request_hash: "h".to_string(),
            self_attestation: None,
        };

        let err = credential_profile_for(&evidence, &evaluation, Some("profile_b"))
            .expect_err("profile_b is not listed on claim-a");
        assert!(matches!(err, EvidenceError::CredentialIssuerNotConfigured));

        let (profile_id, _) = credential_profile_for(&evidence, &evaluation, Some("profile_a"))
            .expect("profile_a is listed on claim-a");
        assert_eq!(profile_id, "profile_a");
    }

    #[test]
    fn credential_profile_for_uses_stored_claim_version() {
        let mut older_claim = test_claim("claim-a", Vec::new(), true);
        older_claim.credential_profiles = vec!["profile_a".to_string()];
        let mut newer_claim = test_claim("claim-a", Vec::new(), true);
        newer_claim.version = "2.0".to_string();
        newer_claim.credential_profiles = vec!["profile_b".to_string()];
        let mut evidence = (*test_evidence(vec![older_claim, newer_claim])).clone();
        evidence.credential_profiles = serde_norway::from_str(
            r#"
profile_a:
  format: application/dc+sd-jwt
  issuer: https://issuer.example
  signing_key: issuer-key
  vct: https://vct.example/a
  allowed_claims: [claim-a]
profile_b:
  format: application/dc+sd-jwt
  issuer: https://issuer.example
  signing_key: issuer-key
  vct: https://vct.example/b
  allowed_claims: [claim-a]
"#,
        )
        .expect("credential profiles parse");
        let evaluation = registry_notary_core::StoredEvaluation {
            client_id: "client".to_string(),
            purpose: "test".to_string(),
            claim_ids: vec!["claim-a".to_string()],
            claim_refs: vec![ClaimRef::with_version("claim-a", "2.0")],
            disclosure: "redacted".to_string(),
            format: FORMAT_SD_JWT_VC.to_string(),
            results: Vec::new(),
            created_at: "1970-01-01T00:00:00Z".to_string(),
            expires_at: "1970-01-01T00:00:00Z".to_string(),
            request_hash: "h".to_string(),
            self_attestation: None,
        };

        let err = credential_profile_for(&evidence, &evaluation, Some("profile_a"))
            .expect_err("profile_a is not listed on claim-a version 2.0");
        assert!(matches!(err, EvidenceError::CredentialIssuerNotConfigured));

        let (profile_id, _) = credential_profile_for(&evidence, &evaluation, Some("profile_b"))
            .expect("profile_b is listed on claim-a version 2.0");
        assert_eq!(profile_id, "profile_b");
        let (profile_id, _) =
            credential_profile_for(&evidence, &evaluation, None).expect("default profile resolves");
        assert_eq!(profile_id, "profile_b");
    }
}
