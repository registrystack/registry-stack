// SPDX-License-Identifier: Apache-2.0
//! Registry Witness evaluation runtime.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(feature = "registry-witness-cel")]
use std::time::Duration;

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
    binding: &registry_witness_core::SourceBindingConfig,
    lookup_value: &Value,
    purpose: &str,
) -> String {
    use registry_witness_core::SourceConnectorKind;
    let connector = match binding.connector {
        SourceConnectorKind::RegistryDataApi => "rda",
        SourceConnectorKind::Dci => "dci",
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

#[cfg(feature = "registry-witness-cel")]
use cel_mapper_core::{
    MappingRuntime, RuntimeOptions, SecurityLimits, StandaloneEvalError, StandaloneExpressionInput,
};
use registry_witness_core::{
    AccessMode, BatchClaimResultView, BatchEvaluateRequest, BatchEvaluateResponse, BatchItemError,
    BatchItemResponse, BatchItemStatus, BatchStatus, BatchSummary, BoundedClaimId,
    BoundedCorrelationId, BulkMode, CelBindingsConfig, ClaimDefinition, ClaimProvenance,
    ClaimResultView, CredentialProfileConfig, DisclosureDowngrade, DisclosureProfile,
    EvaluateRequest, EvidenceConfig, EvidenceError, EvidenceFormat, EvidencePrincipal, Hashed,
    RenderRequest, RuleConfig, SelfAttestationConfig, SelfAttestationDenialCode,
    SourceBindingConfig, SourceCapability, StoredSelfAttestationMetadata, SubjectBinding,
    SubjectRequest, FORMAT_CCCEV_JSONLD, FORMAT_CLAIM_RESULT_JSON, FORMAT_SD_JWT_VC,
    SD_JWT_VC_HOLDER_BINDING_METHOD, SD_JWT_VC_ISSUER_KEY_TYPE, SD_JWT_VC_JWT_TYP,
    SD_JWT_VC_SIGNING_ALG,
};
#[cfg(feature = "registry-witness-cel")]
use serde_json::Map;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
#[cfg(feature = "registry-witness-cel")]
use tokio::time::timeout;
use ulid::Ulid;

#[cfg(feature = "registry-witness-cel")]
const CEL_EVALUATION_TIMEOUT: Duration = Duration::from_millis(500);

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

    fn required_scopes(
        &self,
        evidence: &EvidenceConfig,
        claim_id: &str,
    ) -> Result<Vec<String>, EvidenceError>;
}

/// Group bindings across (subject, claim, binding) by their bulk-eligible
/// connection, dispatch one `SourceReader::read_many` per group, and seed
/// the per-batch memo with the resulting values.
///
/// This runs at the start of `batch_evaluate`. Bindings on connections with
/// `bulk_mode = None` are skipped here and handled by the per-subject
/// evaluation path as before (the trait default `read_many` is never called
/// for them).
///
/// Errors from `read_many` are NOT inserted into the memo (matching Stage 2
/// error-not-cached semantics). A subject whose bulk read failed will fall
/// through to a fresh per-subject `read_one` call.
async fn prefetch_bulk_bindings(
    evidence: Arc<EvidenceConfig>,
    source: Arc<dyn SourceReader>,
    source_capability: SourceCapability,
    subjects: &[SubjectRequest],
    requested_claims: &[String],
    purpose: &str,
    fetch_memo: FetchMemo,
) {
    if subjects.is_empty() || requested_claims.is_empty() {
        return;
    }
    // Closure of claims (requested + transitive deps) so we cover bindings
    // that only show up under depends_on edges.
    let levels = match build_claim_levels(&evidence, requested_claims) {
        Ok(levels) => levels,
        Err(_) => return,
    };
    let claim_closure: Vec<String> = levels.into_iter().flatten().collect();

    // Group key: (connection_id, dataset, entity, lookup_field, projected_fields_sorted).
    // Two bindings in different claims that share this tuple AND target the
    // same connection produce identical wire requests and may be batched
    // together. The lookup_op and purpose are uniform within a batch.
    type GroupKey = (String, String, String, String, Vec<String>);
    let mut groups: BTreeMap<GroupKey, Vec<(SourceBindingConfig, SubjectRequest, String)>> =
        BTreeMap::new();
    for claim_id in &claim_closure {
        let Ok(claim) = find_claim(&evidence, claim_id) else {
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
            if !fields.iter().any(|f| f == &binding.lookup.field) {
                fields.push(binding.lookup.field.clone());
            }
            fields.sort();
            fields.dedup();
            let group_key: GroupKey = (
                connection_id.to_string(),
                binding.dataset.clone(),
                binding.entity.clone(),
                binding.lookup.field.clone(),
                fields,
            );
            for subject in subjects {
                // Compute the per-subject cache key and ensure the same
                // (binding, subject) pair is not enqueued twice (e.g. two
                // claims sharing a binding).
                let lookup_value = match binding_lookup_value(binding, subject) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let cache_key = cache_key_for_binding(binding, &lookup_value, purpose);
                let bucket = groups.entry(group_key.clone()).or_default();
                if bucket.iter().any(|(_, _, k)| k == &cache_key) {
                    continue;
                }
                bucket.push((binding.clone(), subject.clone(), cache_key));
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
        let pairs: Vec<(SourceBindingConfig, SubjectRequest)> = entries
            .iter()
            .map(|(b, s, _)| (b.clone(), s.clone()))
            .collect();
        tracing::info!(
            target: "registry_witness_server::bulk",
            connection_id = %group_key.0,
            dataset = %group_key.1,
            entity = %group_key.2,
            batch_size = pairs.len(),
            "bulk_prefetch_dispatch",
        );
        let results = source
            .read_many_with_capability(&source_capability, pairs, purpose)
            .await;
        let observed_at = OffsetDateTime::now_utc();
        for (entry, result) in entries.into_iter().zip(results) {
            let (_, _, cache_key) = entry;
            match result {
                Ok(value) => {
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

#[derive(Debug, Clone)]
struct Oid4vciNonceRecord {
    expires_at: OffsetDateTime,
}

const MAX_OID4VCI_NONCES: usize = 4096;

#[derive(Debug, Default)]
pub struct EvidenceStore {
    evaluations: Mutex<HashMap<String, registry_witness_core::StoredEvaluation>>,
    idempotency: Mutex<HashMap<String, IdempotencyRecord>>,
    holder_proofs: Mutex<HashMap<String, HolderProofRecord>>,
    oid4vci_nonces: Mutex<HashMap<String, Oid4vciNonceRecord>>,
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
    subject: SubjectRequest,
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

    pub fn insert_oid4vci_nonce(
        &self,
        key: String,
        expires_at: OffsetDateTime,
    ) -> Result<(), EvidenceError> {
        let now = OffsetDateTime::now_utc();
        let mut records = self
            .oid4vci_nonces
            .lock()
            .expect("evidence oid4vci nonce mutex is not poisoned");
        records.retain(|_, record| record.expires_at > now);
        if records.len() >= MAX_OID4VCI_NONCES && !records.contains_key(&key) {
            return Err(EvidenceError::SelfAttestationRateLimited);
        }
        records.insert(key, Oid4vciNonceRecord { expires_at });
        Ok(())
    }

    pub fn consume_oid4vci_nonce(&self, key: &str) -> Result<(), EvidenceError> {
        let now = OffsetDateTime::now_utc();
        let mut records = self
            .oid4vci_nonces
            .lock()
            .expect("evidence oid4vci nonce mutex is not poisoned");
        records.retain(|_, record| record.expires_at > now);
        let Some(record) = records.remove(key) else {
            return Err(EvidenceError::HolderProofRequired);
        };
        if record.expires_at <= now {
            return Err(EvidenceError::HolderProofRequired);
        }
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
        let source_capability = source_capability_for_principal(principal, &request.claims)?;
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
        for claim_id in &request.claims {
            require_source_read_capability(&source_capability, claim_id)?;
        }
        for claim_id in &request.claims {
            require_claim_access(&evidence, source.as_ref(), principal, claim_id)?;
        }
        let purpose = resolve_purpose(header_purpose, request.purpose.as_deref())?;
        let format = request
            .format
            .clone()
            .unwrap_or_else(|| FORMAT_CLAIM_RESULT_JSON.to_string());
        for claim_id in &request.claims {
            require_claim_format(&evidence, claim_id, &format)?;
        }
        let disclosure = requested_disclosure(&evidence, &request.claims, &request.disclosure)?;
        let request_hash = hash_json(&request)?;
        let evaluation_id = Ulid::new().to_string();
        let now = OffsetDateTime::now_utc();
        let binding_concurrency = Arc::new(Semaphore::new(evidence.concurrency.bindings));
        let internal = self
            .evaluate_claims_dag(
                Arc::clone(&evidence),
                Arc::clone(&source),
                request.subject.clone(),
                purpose.clone(),
                evaluation_id.clone(),
                now,
                request.claims.clone(),
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
                let claim = find_claim(&evidence, claim_id)?;
                let result = internal
                    .get(claim_id)
                    .ok_or(EvidenceError::RuleEvaluationFailed)?;
                view_claim(result, claim, disclosure, &format)
            })
            .collect::<Result<Vec<_>, EvidenceError>>()?;
        let expires_at = self_attestation
            .as_ref()
            .and_then(|metadata| metadata.evaluation_expires_at.as_deref())
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            .unwrap_or(now + time::Duration::minutes(15));
        let client_id = stored_evaluation_client_id(principal, self_attestation.as_ref());
        store.insert(registry_witness_core::StoredEvaluation {
            client_id,
            purpose,
            claim_ids: request.claims,
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
        if request.claims.is_empty() || request.subjects.is_empty() {
            return Err(EvidenceError::InvalidRequest);
        }
        let source_capability = source_capability_for_principal(principal, &request.claims)?;
        let max_subjects = max_batch_subjects(&evidence, &request.claims)?;
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
        let subject_count = request.subjects.len();
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
        // all bindings across all subjects via `SourceReader::read_many` and
        // seed the memo with the results. The per-subject evaluation pipeline
        // then naturally hits the memo and skips its own per-subject upstream
        // call. We do this before the JoinSet so the bulk request runs
        // exactly once per group instead of being raced by N sibling subject
        // tasks.
        prefetch_bulk_bindings(
            Arc::clone(&evidence),
            Arc::clone(&source),
            source_capability.clone(),
            &request.subjects,
            &request.claims,
            purpose.as_str(),
            Arc::clone(&fetch_memo),
        )
        .await;
        let mut join_set: JoinSet<(usize, Result<Vec<ClaimResultView>, EvidenceError>)> =
            JoinSet::new();
        for (input_index, subject) in request.subjects.clone().into_iter().enumerate() {
            let runtime = self.clone();
            let evidence = Arc::clone(&evidence);
            let source = Arc::clone(&source);
            let permit_semaphore = Arc::clone(&subject_concurrency);
            let claims_list = request.claims.clone();
            let disclosure = request.disclosure.clone();
            let format = request.format.clone();
            let purpose_for_task = purpose.clone();
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
                    subject,
                    claims: claims_list,
                    disclosure,
                    format,
                    purpose: Some(purpose_for_task.clone()),
                };
                let principal = EvidencePrincipal {
                    principal_id,
                    scopes: principal_scopes,
                    access_mode: registry_witness_core::AccessMode::MachineClient,
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
                        target: "registry_witness_server::runtime",
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
                        store.insert(registry_witness_core::StoredEvaluation {
                            client_id: principal.principal_id.clone(),
                            purpose: purpose.clone(),
                            claim_ids: request.claims.clone(),
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
                    items[input_index] = Some(BatchItemResponse {
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
                    items[input_index] = Some(BatchItemResponse {
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
        for claim_id in &request.claims {
            require_source_read_capability(&source_capability, claim_id)?;
        }
        for claim_id in &request.claims {
            require_claim_access(&evidence, source.as_ref(), principal, claim_id)?;
        }
        let format = request
            .format
            .clone()
            .unwrap_or_else(|| FORMAT_CLAIM_RESULT_JSON.to_string());
        for claim_id in &request.claims {
            require_claim_format(&evidence, claim_id, &format)?;
        }
        let disclosure = requested_disclosure(&evidence, &request.claims, &request.disclosure)?;
        let evaluation_id = Ulid::new().to_string();
        let now = OffsetDateTime::now_utc();
        let binding_concurrency = Arc::new(Semaphore::new(evidence.concurrency.bindings));
        let internal = self
            .evaluate_claims_dag(
                Arc::clone(&evidence),
                Arc::clone(&source),
                request.subject.clone(),
                purpose_override.to_string(),
                evaluation_id.clone(),
                now,
                request.claims.clone(),
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
                let claim = find_claim(&evidence, claim_id)?;
                let result = internal
                    .get(claim_id)
                    .ok_or(EvidenceError::RuleEvaluationFailed)?;
                view_claim(result, claim, disclosure, &format)
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
        subject: SubjectRequest,
        purpose: String,
        evaluation_id: String,
        now: OffsetDateTime,
        requested: Vec<String>,
        binding_concurrency: Arc<Semaphore>,
        source_capability: SourceCapability,
        fetch_memo: Option<FetchMemo>,
        correlation_id: Option<BoundedCorrelationId>,
    ) -> Result<BTreeMap<String, ClaimResultInternal>, EvidenceError> {
        let levels = build_claim_levels(&evidence, &requested)?;
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
                    subject: subject.clone(),
                    purpose: purpose.clone(),
                    correlation_id: correlation_id.clone(),
                    evaluation_id: evaluation_id.clone(),
                    now,
                    binding_concurrency: Arc::clone(&binding_concurrency),
                    fetch_memo: fetch_memo.as_ref().map(Arc::clone),
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
                            target: "registry_witness_server::runtime",
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
    let claim = find_claim(&ctx.evidence, claim_id)?.clone();
    if !claim.operations.evaluate.enabled {
        return Err(EvidenceError::OperationUnsupported);
    }
    let (sources, observed_at) = load_sources(
        Arc::clone(&ctx.source),
        Arc::clone(&claim_arc(&claim)),
        ctx.source_capability.clone(),
        ctx.subject.clone(),
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
            evaluate_cel_expression(&CelEvaluationContext {
                evidence: &ctx.evidence,
                claim: &claim,
                expression,
                bindings,
                claims: &snapshot,
                sources: &sources,
                subject: &ctx.subject,
                purpose: ctx.purpose.as_str(),
            })
            .await?
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
        subject_ref: evaluation_subject_ref(&ctx.evaluation_id),
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
    requested: &[String],
) -> Result<Vec<Vec<String>>, EvidenceError> {
    // Closure: starting from `requested`, accumulate every transitive dep.
    let mut closure: BTreeSet<String> = BTreeSet::new();
    let mut frontier: Vec<String> = requested.to_vec();
    while let Some(claim_id) = frontier.pop() {
        if !closure.insert(claim_id.clone()) {
            continue;
        }
        let claim = find_claim(evidence, &claim_id)?;
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
            let claim = find_claim(evidence, claim_id)?;
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
    if principal.is_self_attestation() {
        return Ok(());
    }
    for scope in source.required_scopes(evidence, claim_id)? {
        if !principal.has_scope(&scope) {
            return Err(EvidenceError::ScopeDenied { required: scope });
        }
    }
    Ok(())
}

fn source_capability_for_principal(
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
            Ok(SourceCapability::SelfAttestation {
                claim_id,
                subject_binding_hash: Hashed::<SubjectBinding>::from_hash(format!(
                    "sha256:{}",
                    sha256_hex(subject_binding_value.as_str().as_bytes())
                )),
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
    subject: SubjectRequest,
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
        let subject = subject.clone();
        let purpose = purpose.clone();
        let binding_concurrency = Arc::clone(&binding_concurrency);
        let fetch_memo = fetch_memo.clone();
        tasks.spawn(async move {
            let result = load_one_binding(
                source,
                &source_capability,
                claim_id.as_str(),
                &binding,
                &subject,
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
                    target: "registry_witness_server::runtime",
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
    binding: &registry_witness_core::SourceBindingConfig,
    subject: &SubjectRequest,
    purpose: &str,
    binding_concurrency: Arc<Semaphore>,
    fetch_memo: Option<&FetchMemo>,
) -> Result<(Value, Option<OffsetDateTime>), EvidenceError> {
    // Compute the lookup value to build the cache key. If this fails (e.g.
    // unsupported lookup op) we skip the memo entirely and fall through to a
    // direct fetch; the connector will surface the same error there.
    let lookup_value_for_key = binding_lookup_value(binding, subject).ok();

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
                    target: "registry_witness_server::memo",
                    "memo_hit",
                );
                return Ok((value, Some(ts)));
            }
            Action::Owner(sem) => {
                return fetch_and_signal(
                    source,
                    source_capability,
                    claim_id,
                    binding,
                    subject,
                    purpose,
                    binding_concurrency,
                    memo,
                    key,
                    sem,
                )
                .await;
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
                        target: "registry_witness_server::memo",
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
        subject,
        purpose,
        binding_concurrency,
    )
    .await
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
    binding: &registry_witness_core::SourceBindingConfig,
    subject: &SubjectRequest,
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
        subject,
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
        target: "registry_witness_server::memo",
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
    binding: &registry_witness_core::SourceBindingConfig,
    subject: &SubjectRequest,
    purpose: &str,
    binding_concurrency: Arc<Semaphore>,
) -> Result<(Value, Option<OffsetDateTime>), EvidenceError> {
    require_source_read_capability(source_capability, claim_id)?;
    let _permit = match binding_concurrency.acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => return Err(EvidenceError::RuleEvaluationFailed),
    };
    let mapped_subject = source.map_subject(binding, subject).await?;
    let row = source
        .read_one_with_capability(
            source_capability,
            claim_id,
            binding,
            &mapped_subject,
            purpose,
        )
        .await?;
    for field in binding.fields.values().filter(|field| field.required) {
        match crate::standalone::get_json_path(&row, &field.field) {
            Some(value) if !value.is_null() => {}
            _ => return Err(EvidenceError::SourceNotFound),
        }
    }
    Ok((row, None))
}

/// Derive the lookup value for a binding from the subject request.
///
/// This mirrors the derivation in `standalone::lookup_value` but is placed here
/// so `load_sources` can compute cache keys without depending on `standalone`
/// internals. Only the "eq" operator with a subject-scoped input is supported.
fn binding_lookup_value(
    binding: &registry_witness_core::SourceBindingConfig,
    subject: &SubjectRequest,
) -> Result<Value, EvidenceError> {
    if binding.lookup.op != "eq" {
        return Err(EvidenceError::InvalidRequest);
    }
    match binding.lookup.input.as_str() {
        "subject_id" | "subject.id" => Ok(Value::String(subject.id.clone())),
        _ => Err(EvidenceError::InvalidRequest),
    }
}

async fn evaluate_cel_expression(ctx: &CelEvaluationContext<'_>) -> Result<Value, EvidenceError> {
    validate_cel_policy(ctx.expression, ctx.bindings, ctx.claim)?;
    #[cfg(feature = "registry-witness-cel")]
    {
        evaluate_with_cel(ctx).await
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
async fn evaluate_with_cel(ctx: &CelEvaluationContext<'_>) -> Result<Value, EvidenceError> {
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
    let limits = SecurityLimits::default();
    validate_cel_binding_limits(
        &Value::Object(root_bindings.clone().into_iter().collect()),
        &limits,
    )?;
    let expression = ctx.expression.to_string();
    let input = StandaloneExpressionInput::new(root_bindings);
    let handle = tokio::task::spawn_blocking(move || {
        let runtime = MappingRuntime::new(RuntimeOptions::default());
        runtime.evaluate_cel_expression_with_input(&expression, input)
    });
    let result = timeout(CEL_EVALUATION_TIMEOUT, handle)
        .await
        .map_err(|_| EvidenceError::RuleEvaluationFailed)?
        .map_err(|_| EvidenceError::RuleEvaluationFailed)?;
    result.map_err(|error| match error {
        StandaloneEvalError::Compile(_) | StandaloneEvalError::InvalidBindingName { .. } => {
            EvidenceError::InvalidRequest
        }
        StandaloneEvalError::Evaluate { .. } => EvidenceError::RuleEvaluationFailed,
    })
}

#[cfg(feature = "registry-witness-cel")]
fn validate_cel_binding_limits(
    value: &Value,
    limits: &SecurityLimits,
) -> Result<(), EvidenceError> {
    match value {
        Value::String(value) if value.len() > limits.max_string_bytes => {
            Err(EvidenceError::RuleEvaluationFailed)
        }
        Value::Array(values) => {
            if values.len() > limits.max_list_len {
                return Err(EvidenceError::RuleEvaluationFailed);
            }
            for value in values {
                validate_cel_binding_limits(value, limits)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_cel_binding_limits(value, limits)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
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

fn evaluation_subject_ref(evaluation_id: &str) -> String {
    format!("urn:subject:evaluation:{evaluation_id}")
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
        title: crate::api::evidence_title(error).to_string(),
        retryable: matches!(error, EvidenceError::SourceUnavailable),
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

    #[derive(Debug, Default)]
    struct CountingSource {
        read_count: AtomicU64,
    }

    impl SourceReader for CountingSource {
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
            _claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(Vec::new())
        }
    }

    fn test_source_binding() -> SourceBindingConfig {
        SourceBindingConfig {
            connector: registry_witness_core::SourceConnectorKind::RegistryDataApi,
            connection: None,
            required_scope: None,
            dataset: "people".to_string(),
            entity: "person".to_string(),
            lookup: registry_witness_core::SourceLookupConfig {
                input: "subject_id".to_string(),
                field: "id".to_string(),
                op: "eq".to_string(),
                cardinality: "one".to_string(),
            },
            fields: BTreeMap::from([(
                "value".to_string(),
                registry_witness_core::SourceFieldConfig {
                    field: "value".to_string(),
                    field_type: Some("boolean".to_string()),
                    unit: None,
                    required: true,
                    semantic_term: None,
                },
            )]),
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
            value: registry_witness_core::ClaimValueConfig {
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
            operations: registry_witness_core::ClaimOperationsConfig::default(),
            disclosure: registry_witness_core::DisclosureConfig {
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

    fn test_request(claim: &str) -> EvaluateRequest {
        EvaluateRequest {
            subject: SubjectRequest {
                id: "person-1".to_string(),
                id_type: None,
            },
            claims: vec![claim.to_string()],
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
    fn service_document_advertises_sd_jwt_vc_conformance_capabilities() {
        let mut credential_profiles = BTreeMap::new();
        credential_profiles.insert(
            "profile-a".to_string(),
            CredentialProfileConfig {
                format: FORMAT_SD_JWT_VC.to_string(),
                issuer: "did:web:issuer.test".to_string(),
                issuer_key_env: "ISSUER_JWK".to_string(),
                issuer_kid: Some("did:web:issuer.test#key-1".to_string()),
                vct: "https://issuer.test/credentials/profile-a".to_string(),
                validity_seconds: 600,
                holder_binding: registry_witness_core::HolderBindingConfig {
                    mode: "did".to_string(),
                    proof_of_possession: Some("required".to_string()),
                    allowed_did_methods: vec![SD_JWT_VC_HOLDER_BINDING_METHOD.to_string()],
                },
                allowed_claims: vec!["claim-a".to_string()],
                disclosure: registry_witness_core::CredentialDisclosureConfig {
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

        let document = RegistryWitnessRuntime::service_document(&evidence);
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
            RegistryWitnessRuntime::service_document_with_self_attestation(
                &evidence,
                &SelfAttestationConfig::default(),
                false,
            ),
            RegistryWitnessRuntime::service_document(&evidence),
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

        let document = RegistryWitnessRuntime::service_document_with_self_attestation(
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

        let document = RegistryWitnessRuntime::service_document_with_self_attestation(
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

    #[test]
    fn subject_ref_is_evaluation_scoped_not_subject_hash() {
        assert_eq!(
            evaluation_subject_ref("01KSARTEST"),
            "urn:subject:evaluation:01KSARTEST"
        );
    }

    #[tokio::test]
    async fn self_attestation_capability_rejects_dependency_source_read_before_connector() {
        let source = Arc::new(CountingSource::default());
        let evidence = test_evidence(vec![
            test_claim("selected", vec!["dependency"], false),
            test_claim("dependency", Vec::new(), true),
        ]);
        let store = EvidenceStore::default();

        let err = RegistryWitnessRuntime::new()
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

        let err = RegistryWitnessRuntime::new()
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

        let results = RegistryWitnessRuntime::new()
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
            subjects: vec![SubjectRequest {
                id: "person-1".to_string(),
                id_type: None,
            }],
            claims: vec!["selected".to_string()],
            disclosure: Some("value".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("test".to_string()),
        };

        let err = RegistryWitnessRuntime::new()
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

    #[test]
    fn oid4vci_nonce_store_has_memory_cap() {
        let store = EvidenceStore::default();
        let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(60);
        for index in 0..MAX_OID4VCI_NONCES {
            store
                .insert_oid4vci_nonce(format!("nonce-{index}"), expires_at)
                .expect("nonce below cap inserts");
        }

        assert!(matches!(
            store.insert_oid4vci_nonce("nonce-over-cap".to_string(), expires_at),
            Err(EvidenceError::SelfAttestationRateLimited)
        ));
    }

    #[cfg(feature = "registry-witness-cel")]
    #[test]
    fn cel_binding_limits_reject_large_strings_and_lists() {
        let limits = SecurityLimits {
            max_string_bytes: 4,
            max_list_len: 2,
            ..SecurityLimits::default()
        };

        assert!(validate_cel_binding_limits(&json!({ "value": "abcd" }), &limits).is_ok());
        assert!(matches!(
            validate_cel_binding_limits(&json!({ "value": "abcde" }), &limits),
            Err(EvidenceError::RuleEvaluationFailed)
        ));
        assert!(matches!(
            validate_cel_binding_limits(&json!({ "items": [1, 2, 3] }), &limits),
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
    format: application/dc+sd-jwt
    issuer: https://issuer.example
    issuer_key_env: ISSUER_KEY
    vct: https://vct.example/a
    allowed_claims:
      - claim-a
  profile_b:
    format: application/dc+sd-jwt
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
            self_attestation: None,
        };

        let err = credential_profile_for(&evidence, &evaluation, Some("profile_b"))
            .expect_err("profile_b is not listed on claim-a");
        assert!(matches!(err, EvidenceError::CredentialIssuerNotConfigured));

        let (profile_id, _) = credential_profile_for(&evidence, &evaluation, Some("profile_a"))
            .expect("profile_a is listed on claim-a");
        assert_eq!(profile_id, "profile_a");
    }
}
