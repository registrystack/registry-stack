// SPDX-License-Identifier: Apache-2.0
//! Request-aware source backends for governed consultations.
//!
//! SnapshotExact is deliberately separate from the generic entity-query and
//! connector boundaries. A consultation can capture only an immutable handle
//! that was published through the durable materialization state plane.

mod datafusion;
mod materialization;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use ::datafusion::catalog::TableProvider;
use arc_swap::ArcSwapOption;
use thiserror::Error;
use ulid::Ulid;

use crate::consultation::SnapshotGenerationId;
use crate::source_plan::{CompiledConsultationRegistry, CompiledSourcePlan, SourcePlanKind};

pub(crate) use datafusion::{
    execute_snapshot_exact, SnapshotExactBackendError, SnapshotExactBackendResult,
    SnapshotExactRecord,
};
pub(crate) use materialization::{
    ActiveSnapshotCandidate, SnapshotMaterializationCandidate, SnapshotMaterializationCoordinator,
};

const SLOT_UNAVAILABLE: u8 = 0;
const SLOT_PUBLISHING: u8 = 1;
const SLOT_READY: u8 = 2;

/// Restricted digest of the complete immutable snapshot bytes.
///
/// It is retained only in the state plane and the private published handle.
/// It is never serialized into public consultation provenance.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SnapshotContentDigest([u8; 32]);

impl SnapshotContentDigest {
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for SnapshotContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SnapshotContentDigest(<restricted>)")
    }
}

/// Exact immutable snapshot captured for one consultation.
///
/// The provider is paired with the identity and digest that were atomically
/// made active. Callers cannot replace any member independently.
pub(crate) struct PublishedSnapshotHandle {
    generation: SnapshotGenerationId,
    digest: SnapshotContentDigest,
    published_at_unix_ms: i64,
    source_revision: Option<Box<str>>,
    source_observed_at_unix_ms: Option<i64>,
    provider: Arc<dyn TableProvider>,
}

impl PublishedSnapshotHandle {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        generation: Ulid,
        digest: SnapshotContentDigest,
        published_at_unix_ms: i64,
        source_revision: Option<String>,
        source_observed_at_unix_ms: Option<i64>,
        provider: Arc<dyn TableProvider>,
    ) -> Result<Self, SnapshotRegistryError> {
        let generation = SnapshotGenerationId::try_from(generation.to_string().as_str())
            .map_err(|_| SnapshotRegistryError::InvalidPublication)?;
        if published_at_unix_ms <= 0
            || source_revision
                .as_deref()
                .is_some_and(|revision| revision.is_empty() || revision.len() > 512)
            || source_observed_at_unix_ms.is_some_and(|value| value <= 0)
        {
            return Err(SnapshotRegistryError::InvalidPublication);
        }
        Ok(Self {
            generation,
            digest,
            published_at_unix_ms,
            source_revision: source_revision.map(String::into_boxed_str),
            source_observed_at_unix_ms,
            provider,
        })
    }

    pub(crate) const fn generation(&self) -> SnapshotGenerationId {
        self.generation
    }

    pub(crate) const fn published_at_unix_ms(&self) -> i64 {
        self.published_at_unix_ms
    }

    pub(crate) fn provider(&self) -> Arc<dyn TableProvider> {
        Arc::clone(&self.provider)
    }
}

impl fmt::Debug for PublishedSnapshotHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishedSnapshotHandle")
            .field("generation", &self.generation)
            .field("digest", &self.digest)
            .field("published_at_unix_ms", &self.published_at_unix_ms)
            .field(
                "source_revision",
                &self.source_revision.as_ref().map(|_| "<set>"),
            )
            .field(
                "source_observed_at_unix_ms",
                &self.source_observed_at_unix_ms.map(|_| "<set>"),
            )
            .field("provider", &"<private>")
            .finish()
    }
}

struct SnapshotSlot {
    profile_id: Box<str>,
    profile_version: u64,
    binding_hash: Box<str>,
    state: AtomicU8,
    handle: ArcSwapOption<PublishedSnapshotHandle>,
}

impl SnapshotSlot {
    fn matches_plan(&self, plan: &CompiledSourcePlan) -> bool {
        self.profile_id.as_ref() == plan.profile().id().as_str()
            && self.profile_version == plan.profile().version().get()
            && self.binding_hash.as_ref() == plan.binding_hash()
    }
}

/// Immutable registry of SnapshotExact publication slots.
///
/// V1 requires a one-to-one provider/profile mapping. This keeps publication,
/// freshness, rollback, and readiness authority unambiguous.
pub(crate) struct PublishedSnapshotRegistry {
    by_provider: BTreeMap<Box<str>, Arc<SnapshotSlot>>,
}

impl PublishedSnapshotRegistry {
    pub(crate) fn compile(
        registry: &CompiledConsultationRegistry,
    ) -> Result<Self, SnapshotRegistryError> {
        let mut by_provider = BTreeMap::new();
        for plan in registry
            .plans_for_concrete_activation()
            .filter(|plan| plan.kind() == SourcePlanKind::SnapshotExact)
        {
            let binding = plan
                .snapshot_binding()
                .ok_or(SnapshotRegistryError::InvalidPlan)?;
            let provider: Box<str> = binding.table_provider().into();
            let slot = Arc::new(SnapshotSlot {
                profile_id: plan.profile().id().as_str().into(),
                profile_version: plan.profile().version().get(),
                binding_hash: plan.binding_hash().into(),
                state: AtomicU8::new(SLOT_UNAVAILABLE),
                handle: ArcSwapOption::empty(),
            });
            if by_provider.insert(provider, slot).is_some() {
                return Err(SnapshotRegistryError::DuplicateProvider);
            }
        }
        Ok(Self { by_provider })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.by_provider.is_empty()
    }

    pub(crate) fn begin_publication(
        &self,
        table_provider: &str,
    ) -> Result<SnapshotPublicationGuard, SnapshotRegistryError> {
        let slot = self
            .by_provider
            .get(table_provider)
            .cloned()
            .ok_or(SnapshotRegistryError::UnknownProvider)?;
        let claimed = slot
            .state
            .compare_exchange(
                SLOT_READY,
                SLOT_PUBLISHING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
            || slot
                .state
                .compare_exchange(
                    SLOT_UNAVAILABLE,
                    SLOT_PUBLISHING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok();
        if !claimed {
            return Err(SnapshotRegistryError::PublicationInProgress);
        }
        Ok(SnapshotPublicationGuard {
            slot,
            completed: false,
        })
    }

    pub(crate) fn capture(
        &self,
        plan: &CompiledSourcePlan,
    ) -> Result<Arc<PublishedSnapshotHandle>, SnapshotRegistryError> {
        let binding = plan
            .snapshot_binding()
            .ok_or(SnapshotRegistryError::InvalidPlan)?;
        let slot = self
            .by_provider
            .get(binding.table_provider())
            .ok_or(SnapshotRegistryError::UnknownProvider)?;
        if !slot.matches_plan(plan) || slot.state.load(Ordering::Acquire) != SLOT_READY {
            return Err(SnapshotRegistryError::Unavailable);
        }
        slot.handle
            .load_full()
            .ok_or(SnapshotRegistryError::Unavailable)
    }

    pub(crate) fn is_current(
        &self,
        plan: &CompiledSourcePlan,
        handle: &Arc<PublishedSnapshotHandle>,
    ) -> bool {
        let Some(binding) = plan.snapshot_binding() else {
            return false;
        };
        let Some(slot) = self.by_provider.get(binding.table_provider()) else {
            return false;
        };
        slot.matches_plan(plan)
            && slot.state.load(Ordering::Acquire) == SLOT_READY
            && slot
                .handle
                .load_full()
                .is_some_and(|current| Arc::ptr_eq(&current, handle))
    }

    pub(crate) fn all_ready(&self) -> bool {
        self.by_provider.values().all(|slot| {
            slot.state.load(Ordering::Acquire) == SLOT_READY && slot.handle.load().is_some()
        })
    }
}

impl fmt::Debug for PublishedSnapshotRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishedSnapshotRegistry")
            .field("provider_count", &self.by_provider.len())
            .finish()
    }
}

/// Critical-section guard that leaves the profile unavailable unless the
/// exact durably published handle is installed.
pub(crate) struct SnapshotPublicationGuard {
    slot: Arc<SnapshotSlot>,
    completed: bool,
}

impl SnapshotPublicationGuard {
    pub(crate) fn publish(mut self, handle: PublishedSnapshotHandle) {
        self.slot.handle.store(Some(Arc::new(handle)));
        self.slot.state.store(SLOT_READY, Ordering::Release);
        self.completed = true;
    }
}

impl Drop for SnapshotPublicationGuard {
    fn drop(&mut self) {
        if !self.completed {
            // Once replacement starts, the old handle cannot be used as a
            // stale fallback. A later successful publication is required.
            self.slot.state.store(SLOT_UNAVAILABLE, Ordering::Release);
        }
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum SnapshotRegistryError {
    #[error("snapshot exact plan is invalid")]
    InvalidPlan,
    #[error("snapshot exact provider is duplicated")]
    DuplicateProvider,
    #[error("snapshot exact provider is unknown")]
    UnknownProvider,
    #[error("snapshot exact publication is already in progress")]
    PublicationInProgress,
    #[error("snapshot exact publication is invalid")]
    InvalidPublication,
    #[error("snapshot exact provider is unavailable")]
    Unavailable,
}
