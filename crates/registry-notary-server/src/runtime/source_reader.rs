// SPDX-License-Identifier: Apache-2.0

use super::*;

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

    /// Minimized public summaries of any source runtimes a claim crosses that
    /// represent an external execution boundary (the source-adapter sidecar). Returned
    /// per claim so each claim's provenance reports only the runtimes it used.
    /// The default is empty; only the standalone reader observes real sidecars.
    fn observed_source_runtimes<'a>(
        &'a self,
        _evidence: &'a EvidenceConfig,
        _claim_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<SourceRuntimeSummary>> + Send + 'a>> {
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

    fn source_observed_at_for_context<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        _context: &'a EvidenceRequestContext,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<OffsetDateTime>, EvidenceError>> + Send + 'a>>
    {
        Box::pin(async move { Ok(None) })
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

    fn source_observed_at_for_context_with_capability<'a>(
        &'a self,
        capability: &'a SourceCapability,
        claim_id: &'a str,
        binding: &'a SourceBindingConfig,
        context: &'a EvidenceRequestContext,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<OffsetDateTime>, EvidenceError>> + Send + 'a>>
    {
        Box::pin(async move {
            require_source_read_capability(capability, claim_id)?;
            self.source_observed_at_for_context(binding, context, purpose)
                .await
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
pub(super) async fn default_read_many<'a, R: SourceReader + ?Sized>(
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
pub(super) async fn default_read_many_context<'a, R: SourceReader + ?Sized>(
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
